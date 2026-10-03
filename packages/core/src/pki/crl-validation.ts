import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { TimestampError, TimestampErrorCode } from "../types.js";
import { toArrayBuffer, bytesToHex } from "../utils.js";
import { ensureWebCrypto } from "../utils/web-crypto.js";
import {
    createDerDecodeBudget,
    parseCanonicalDERSequenceTree,
    parseCanonicalDERValue,
    requireSchemaRoundTrip,
    type DerDecodeBudget,
} from "./der-utils.js";
import { getCRLDistributionPointMetadata, type DistributionPointMetadata } from "./crl-utils.js";
import {
    hasSplitDirectoryNameWrapper,
    isCanonicalDerOidContent,
    isUndecidableGeneralNameWrapper,
    isWellFormedName,
    oidContentOctets,
} from "./name-grammar.js";
import type { RevocationEvidenceResult, RevocationStatus } from "./validation-types.js";

/**
 * Strict CRL evidence authentication (RFC 5280, T07).
 *
 * This module is deliberately NOT a thin wrapper around
 * `CertificateRevocationList.verify`: auditing pkijs 3.4.1 shows that
 * adapter cannot express this session's policy. It reads only the OUTER
 * signatureAlgorithm (a relabelled outer OID verifies under an algorithm
 * that never executed), checks no inner/outer consistency, no key usage,
 * no freshness window, no distribution scope, no entry-extension
 * criticality, and no schema completeness (retained subtrees re-emit
 * verbatim). Signature verification here reuses only the same public
 * WebCrypto primitive (`verifyWithPublicKey` over the retained `tbsView`
 * bytes); every policy decision below is explicit.
 *
 * Deliberate duplication note: the strict ASN.1 helpers below
 * (bytesEqual, algorithm-parameter comparison, INTEGER-pair grammar,
 * signature framing, RSA/ECDSA OID sets) mirror ocsp-validation.ts on
 * purpose. That module is frozen (T06 complete -- the T07 brief forbids
 * touching it), and a shared strict-helpers module would either require
 * refactoring it or create asymmetric dual sources of truth. The copies
 * are verbatim where the semantics are identical, so a future
 * consolidation is mechanical; the one intentional divergence is
 * documented on checkCrlTbsCompleteness. The Name grammar and OID
 * content checks are the exception: they live in name-grammar.ts,
 * shared with the distribution-point metadata reader (T07 fix round 2),
 * because both CRL-side paths must apply the identical grammar.
 */

// ---------------------------------------------------------------------------
// Bounds. Ordinary CRLs carry tens of entries and a couple of extensions;
// the caps below are generous multiples of that. They bound per-CRL work
// only: T08's OperationBudget will govern aggregate attempts, bytes, and
// deadlines across certificates, and the hook sites are marked there.
// ---------------------------------------------------------------------------

/**
 * Maximum revokedCertificates entries scanned for a serial match.
 * asn1js parses at most 10000 nodes per value (DEFAULT_MAX_NODES), which
 * caps plain CRLs near 3000 entries upstream; this explicit cap sits
 * below that ceiling so the over-limit verdict stays reachable and
 * testable instead of dying in the backend first.
 */
export const MAX_CRL_REVOKED_ENTRIES = 2000;

/** Maximum extensions walked in any single CRL or entry extension list. */
export const MAX_CRL_EXTENSION_SCAN = 64;

/** Maximum GeneralNames walked in one entry certificateIssuer extension. */
export const MAX_CRL_CERT_ISSUER_NAMES = 64;

const OID_CRL_NUMBER = "2.5.29.20";
const OID_DELTA_CRL_INDICATOR = "2.5.29.27";
const OID_ISSUING_DISTRIBUTION_POINT = "2.5.29.28";
const OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
const OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
const OID_KEY_USAGE = "2.5.29.15";
const OID_REASON_CODE = "2.5.29.21";
const OID_HOLD_INSTRUCTION_CODE = "2.5.29.23";
const OID_INVALIDITY_DATE = "2.5.29.24";
const OID_CERTIFICATE_ISSUER = "2.5.29.29";
const OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const OID_RSASSA_PSS = "1.2.840.113549.1.1.10";

/**
 * Shared unknown-status diagnostics for malformed CRL scoping extensions.
 * Each is returned from three nearby sites; the single spelling keeps the
 * pinned wording identical everywhere it surfaces.
 */
const MALFORMED_AKI_MESSAGE =
    "CRL: CRL authority key identifier is malformed; revocation status unknown";
const MALFORMED_IDP_MESSAGE =
    "CRL: CRL issuing distribution point is malformed; revocation status unknown";

/** RSASSA-PKCS1-v1_5 signature OIDs (SHA-1/256/384/512). */
const RSA_PKCS1V15_SIGNATURE_OIDS: ReadonlySet<string> = new Set([
    "1.2.840.113549.1.1.5",
    "1.2.840.113549.1.1.11",
    "1.2.840.113549.1.1.12",
    "1.2.840.113549.1.1.13",
]);

/** ECDSA signature OIDs (SHA-1/256/384/512). */
const ECDSA_SIGNATURE_OIDS: ReadonlySet<string> = new Set([
    "1.2.840.10045.4.1",
    "1.2.840.10045.4.3.2",
    "1.2.840.10045.4.3.3",
    "1.2.840.10045.4.3.4",
]);

/** CRL extensions this profile actually processes. */
const RECOGNIZED_CRL_EXTENSIONS: ReadonlySet<string> = new Set([
    OID_CRL_NUMBER,
    OID_AUTHORITY_KEY_IDENTIFIER,
    OID_ISSUING_DISTRIBUTION_POINT,
]);

/** Revoked-entry extensions this profile actually processes. */
const RECOGNIZED_CRL_ENTRY_EXTENSIONS: ReadonlySet<string> = new Set([
    OID_REASON_CODE,
    OID_CERTIFICATE_ISSUER,
    OID_HOLD_INSTRUCTION_CODE,
    OID_INVALIDITY_DATE,
]);

/**
 * Options for internal CRL evidence authentication. Policy values come
 * from the ValidationSession options; the expected issuer key is the
 * T05-verified issuer, never the CRL's own issuer field alone.
 */
export interface ValidateCRLOptions {
    /** Certificate the revocation status is evaluated for. */
    cert: pkijs.Certificate;
    /** T05-verified issuing certificate of `cert`. */
    issuer: pkijs.Certificate;
    /** Moment the CRL must be fresh at. */
    checkDate: Date;
    /** Accepted clock skew in milliseconds, applied both directions. */
    clockSkewMs: number;
}

function unknownEvidence(diagnostic: string): RevocationEvidenceResult {
    return { status: "unknown", source: "CRL", errors: [diagnostic] };
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
    if (left.length !== right.length) return false;
    for (let index = 0; index < left.length; index++) {
        if (left[index] !== right[index]) return false;
    }
    return true;
}

function invalidArgument(message: string): TimestampError {
    return new TimestampError(TimestampErrorCode.INVALID_ARGUMENT, message);
}

function invalidCrl(message: string): TimestampError {
    return new TimestampError(TimestampErrorCode.INVALID_RESPONSE, message);
}

/**
 * Rejects unsupported critical extensions in one extension list. Callers
 * pass the OIDs this profile actually processes; any other critical
 * extension fails closed (RFC 5280 4.2). An empty extnID rejects before
 * criticality filtering: an OID value with no content octets is
 * malformed (X.690 8.19) even when noncritical. Returns a full unknown
 * diagnostic, or null when the list is acceptable.
 */
function checkNoUnknownCriticalExtensions(
    extensions: pkijs.Extension[],
    recognized: ReadonlySet<string>,
    where: string
): string | null {
    for (const extension of extensions) {
        if (extension.extnID === "") {
            return (
                `CRL: ${where} carries an extension with an empty extension OID; ` +
                `revocation status unknown`
            );
        }
        if (extension.critical && !recognized.has(extension.extnID)) {
            return (
                `CRL: ${where} carries an unsupported critical extension ` +
                `(${extension.extnID}); revocation status unknown`
            );
        }
    }
    return null;
}

/**
 * Exact numeric identity of a serial number: the minimal-DER magnitude
 * bytes, or null when the encoding is not a non-negative minimal
 * INTEGER. The outer CRL preflight already enforces INTEGER minimality
 * for entry serials; the target certificate serial is caller context
 * parsed elsewhere, so both sides are validated here. A bare
 * leading-zero strip would conflate -128 (`80`) with 128 (`00 80`) and
 * match empty integers, and `valueDec` loses precision past 2^53 --
 * neither reaches a revocation decision.
 */
function serialIdentityBytes(serial: asn1js.Integer): Uint8Array | null {
    const bytes = new Uint8Array(serial.valueBlock.valueHexView);
    if (bytes.length === 0) return null;
    const first = bytes[0];
    if (first === undefined) return null;
    if (bytes.length > 1) {
        const second = bytes[1];
        if (second === undefined) return null;
        if (first === 0x00 && (second & 0x80) === 0) return null;
        if (first === 0xff && (second & 0x80) !== 0) return null;
    }
    // CertificateSerialNumber is non-negative (RFC 5280 4.1.2.2);
    // negatives (including the minimal -128) have no valid identity.
    if (first >= 0x80) return null;
    if (bytes.length > 1 && first === 0x00) return bytes.subarray(1);
    return bytes;
}

/**
 * Strict-only TBSCertList completeness. The forced field-by-field
 * re-encoding exposes trailing or duplicated TBS members the schema
 * decoder ignored, while the explicit issuer Name walk covers the
 * retained name subtree that re-encoding re-emits verbatim. Runs before
 * any decoded extension is trusted. Original signature bytes stay
 * authoritative, and structural collection is untouched. Returns a full
 * unknown diagnostic, or null when complete.
 *
 * Intentional divergence from the OCSP twin: pkijs exposes
 * `encodeTBS()` on certificates but marks it protected on
 * CertificateRevocationList, so it is reached through a structural
 * cast (verified present at runtime on pkijs 3.4.1).
 */
function checkCrlTbsCompleteness(crl: pkijs.CertificateRevocationList): string | null {
    let forced: Uint8Array;
    try {
        const withEncodeTbs = crl as unknown as { encodeTBS(): asn1js.Sequence };
        forced = new Uint8Array(withEncodeTbs.encodeTBS().toBER(false));
    } catch {
        return "CRL: TBSCertList is malformed; revocation status unknown";
    }
    if (crl.tbsView.length === 0 || !bytesEqual(new Uint8Array(crl.tbsView), forced)) {
        return (
            "CRL: TBSCertList does not fully conform to the certificate list schema; " +
            "revocation status unknown"
        );
    }
    if (!isWellFormedName(crl.issuer)) {
        return "CRL: CRL issuer name is malformed; revocation status unknown";
    }
    return null;
}

/**
 * True when two AlgorithmIdentifiers carry equivalent parameters: both
 * absent (pkijs leaves absent parameters undefined, and an `Any`
 * placeholder encodes to nothing, so it counts as absent too), or both
 * present with byte-identical DER. Never throws; any failure means
 * unequal.
 */
function algorithmParametersEqual(
    left: pkijs.AlgorithmIdentifier,
    right: pkijs.AlgorithmIdentifier
): boolean {
    const leftParams: unknown = left.algorithmParams;
    const rightParams: unknown = right.algorithmParams;
    if (leftParams === undefined || leftParams instanceof asn1js.Any) {
        return rightParams === undefined || rightParams instanceof asn1js.Any;
    }
    if (rightParams === undefined || rightParams instanceof asn1js.Any) return false;
    if (!(leftParams instanceof asn1js.BaseBlock) || !(rightParams instanceof asn1js.BaseBlock)) {
        return false;
    }
    try {
        return bytesEqual(
            new Uint8Array(leftParams.toBER(false)),
            new Uint8Array(rightParams.toBER(false))
        );
    } catch {
        return false;
    }
}

/**
 * Validates the CRL signature algorithms before the WebCrypto primitive
 * runs. pkijs `CertificateRevocationList.verify()` reads only the OUTER
 * signatureAlgorithm, and its WebCrypto adapter takes the verification
 * family from the issuer key and only the hash from the declared OID --
 * so a relabelled outer OID verifies under an algorithm that never
 * executed. RFC 5280 section 4.1.1.2 requires the inner
 * (TBSCertList.signature) and outer (CertificateList.signatureAlgorithm)
 * identifiers to be the SAME algorithm: the OIDs must match, and the
 * parameters must both be absent or carry byte-identical DER. The agreed
 * OID must then suit the ISSUER key family: RSA keys pair only with
 * RSASSA-PKCS1-v1_5 OIDs (parameters NULL or absent -- real-world CAs
 * encode NULL, pkijs-built CRLs omit), EC keys only with ECDSA OIDs
 * (parameters absent per RFC 5758). RSA-PSS, EdDSA, and unknown OIDs
 * fail closed. Returns a full unknown diagnostic, or null when the pair
 * may be executed.
 */
function checkCrlSignatureAlgorithm(
    crl: pkijs.CertificateRevocationList,
    issuer: pkijs.Certificate
): string | null {
    const inner = crl.signature;
    const outer = crl.signatureAlgorithm;
    if (inner.algorithmId !== outer.algorithmId) {
        return (
            "CRL: CRL carries inconsistent signature algorithms " +
            `(inner ${inner.algorithmId} vs outer ${outer.algorithmId}); ` +
            "revocation status unknown"
        );
    }
    if (!algorithmParametersEqual(inner, outer)) {
        return (
            "CRL: CRL carries inconsistent signature algorithm " +
            `parameters for ${inner.algorithmId}; revocation status unknown`
        );
    }
    const params: unknown = outer.algorithmParams;
    const keyOid = issuer.subjectPublicKeyInfo.algorithm.algorithmId;
    const sigOid = inner.algorithmId;
    if (keyOid === OID_RSA_ENCRYPTION && RSA_PKCS1V15_SIGNATURE_OIDS.has(sigOid)) {
        if (params !== undefined && !(params instanceof asn1js.Null)) {
            return (
                `CRL: CRL signature algorithm ${sigOid} carries unsupported ` +
                "parameters for the issuer RSA key; revocation status unknown"
            );
        }
        return null;
    }
    if (keyOid === OID_EC_PUBLIC_KEY && ECDSA_SIGNATURE_OIDS.has(sigOid)) {
        // RFC 5758 section 3.1: ECDSA signature parameters MUST be absent.
        if (params !== undefined) {
            return (
                `CRL: CRL signature algorithm ${sigOid} carries unexpected ` +
                "parameters for the issuer EC key; revocation status unknown"
            );
        }
        return null;
    }
    if (sigOid === OID_RSASSA_PSS) {
        return (
            "CRL: CRL signature uses RSA-PSS, which the supported profile " +
            "does not implement; revocation status unknown"
        );
    }
    return (
        `CRL: CRL signature algorithm ${sigOid} is not compatible with ` +
        `the issuer key (${keyOid}); revocation status unknown`
    );
}

/**
 * True when canonical DER INTEGER content octets encode a strictly
 * positive value: the first octet must clear the sign bit (the DER
 * preflight this input passed through already rejects empty and
 * non-minimal encodings), and at least one octet must be nonzero.
 */
function isStrictPositiveIntegerContent(content: Uint8Array): boolean {
    const first = content[0];
    if (first === undefined || first >= 0x80) return false;
    for (const octet of content) {
        if (octet !== 0) return true;
    }
    return false;
}

/**
 * Strict grammar for the two INTEGER-pair structures this profile
 * executes: ECDSA-Sig-Value (RFC 3279 2.2.3) and RSAPublicKey (RFC 3279
 * 2.3.1). pkijs decodes only the first object (`fromBER` without an
 * offset check), so both shapes need their own complete-consumption
 * gate: canonical DER framing (definite minimal lengths, primitive
 * minimal INTEGERs), exactly two INTEGER members, and strictly
 * positive values. The ECDSA range check against the curve order stays
 * with WebCrypto (oversized components throw during raw conversion and
 * fail closed there). Returns a full unknown diagnostic, or null when
 * the payload is well-formed.
 */
function checkIntegerPairEncoding(
    payload: Uint8Array,
    what: string,
    budget: DerDecodeBudget
): string | null {
    let tree: asn1js.BaseBlock;
    try {
        tree = parseCanonicalDERSequenceTree(payload, `CRL ${what}`, { budget });
    } catch {
        return `CRL: CRL ${what} is malformed; revocation status unknown`;
    }
    if (!(tree instanceof asn1js.Sequence)) {
        return `CRL: CRL ${what} is malformed; revocation status unknown`;
    }
    const members = tree.valueBlock.value;
    const first = members[0];
    const second = members[1];
    if (
        members.length !== 2 ||
        first === undefined ||
        second === undefined ||
        !(first instanceof asn1js.Integer) ||
        !(second instanceof asn1js.Integer)
    ) {
        return `CRL: CRL ${what} must contain exactly two INTEGERs; revocation status unknown`;
    }
    if (
        !isStrictPositiveIntegerContent(new Uint8Array(first.valueBlock.valueHexView)) ||
        !isStrictPositiveIntegerContent(new Uint8Array(second.valueBlock.valueHexView))
    ) {
        return `CRL: CRL ${what} carries a non-positive INTEGER; revocation status unknown`;
    }
    return null;
}

/**
 * Strict signature BIT STRING framing for the CRL signatureValue. pkijs
 * verifies over `valueHexView`, which excludes the unused-bits octet,
 * and its ECDSA path decodes the first DER object while ignoring
 * trailing bytes -- so a primitive, nonempty, octet-aligned BIT STRING
 * and (for ECDSA OIDs) a canonical two-INTEGER payload with complete
 * consumption are required BEFORE the WebCrypto primitive runs. RSA
 * payloads stay opaque here: they are raw fixed-length bytes, so
 * trailing garbage breaks verification naturally. Returns a full
 * unknown diagnostic, or null when the value may be executed.
 */
function checkSignatureValueEncoding(
    signature: asn1js.BitString,
    signatureAlgorithm: pkijs.AlgorithmIdentifier,
    budget: DerDecodeBudget
): string | null {
    if (signature.idBlock.isConstructed || signature.valueBlock.isConstructed) {
        return "CRL: CRL signature is not a primitive BIT STRING; revocation status unknown";
    }
    if (signature.valueBlock.unusedBits !== 0) {
        return "CRL: CRL signature BIT STRING is not octet-aligned; revocation status unknown";
    }
    if (signature.valueBlock.valueHexView.byteLength === 0) {
        return "CRL: CRL signature is empty; revocation status unknown";
    }
    if (ECDSA_SIGNATURE_OIDS.has(signatureAlgorithm.algorithmId)) {
        return checkIntegerPairEncoding(
            new Uint8Array(signature.valueBlock.valueHexView),
            "ECDSA signature",
            budget
        );
    }
    return null;
}

/**
 * Strict-only encoding of the issuer public key, before it executes in
 * WebCrypto. The issuer is caller-supplied chain material, but its key
 * still executes here -- and the backend tolerates malformed SPKIs
 * (misaligned framing, trailing payload bytes, extra or non-positive
 * INTEGERs, non-NULL RSA parameters all verify today), so the encoding
 * gates fail closed first. The RSA payload gets its own
 * complete-consumption parse (RSAPublicKey, RFC 3279 2.3.1) through
 * the shared budget; RSA parameters must be NULL or absent; EC
 * parameters must be exactly the named-curve OID the import consumes.
 * On-curve EC point validation stays with key import, which enforces
 * it. Mirrors the T06 delegate-key gate (including the `Any` tolerance
 * for absent RSA parameters); the one intentional divergence is the
 * shared budget threading. Returns a full unknown diagnostic, or null
 * when the key may be executed.
 */
function checkIssuerPublicKeyEncoding(
    spki: pkijs.PublicKeyInfo,
    budget: DerDecodeBudget
): string | null {
    const keyOid = spki.algorithm.algorithmId;
    const params: unknown = spki.algorithm.algorithmParams;
    if (keyOid === OID_RSA_ENCRYPTION) {
        if (
            params !== undefined &&
            !(params instanceof asn1js.Any) &&
            !(params instanceof asn1js.Null)
        ) {
            return (
                "CRL: issuer RSA public key carries unsupported parameters; " +
                "revocation status unknown"
            );
        }
    } else if (keyOid === OID_EC_PUBLIC_KEY) {
        if (!(params instanceof asn1js.ObjectIdentifier)) {
            return (
                "CRL: issuer EC public key requires named-curve parameters; " +
                "revocation status unknown"
            );
        }
    } else {
        return (
            `CRL: issuer key algorithm ${keyOid} is not supported; ` + "revocation status unknown"
        );
    }
    const keyBits = spki.subjectPublicKey;
    if (keyBits.idBlock.isConstructed || keyBits.valueBlock.isConstructed) {
        return "CRL: issuer public key is not a primitive BIT STRING; revocation status unknown";
    }
    if (keyBits.valueBlock.unusedBits !== 0) {
        return "CRL: issuer public key BIT STRING is not octet-aligned; revocation status unknown";
    }
    if (keyBits.valueBlock.valueHexView.byteLength === 0) {
        return "CRL: issuer public key is empty; revocation status unknown";
    }
    if (keyOid === OID_RSA_ENCRYPTION) {
        return checkIntegerPairEncoding(
            new Uint8Array(keyBits.valueBlock.valueHexView),
            "issuer RSA public key",
            budget
        );
    }
    return null;
}

/**
 * Verifies the CRL signature over the retained TBS bytes with the
 * issuer public key, using the same public pkijs WebCrypto primitive as
 * Certificate.verify. Strict framing and ECDSA grammar are enforced
 * before the primitive runs. Never throws; any failure (including an
 * unsupported algorithm or a missing engine) means unverified.
 */
async function verifyTbsSignature(
    tbsView: Uint8Array,
    signature: asn1js.BitString,
    publicKeyInfo: pkijs.PublicKeyInfo,
    signatureAlgorithm: pkijs.AlgorithmIdentifier,
    budget: DerDecodeBudget
): Promise<boolean> {
    try {
        if (tbsView.length === 0) return false;
        if (checkSignatureValueEncoding(signature, signatureAlgorithm, budget) !== null) {
            return false;
        }
        const engine = pkijs.getEngine();
        const crypto = engine.crypto;
        if (!crypto) return false;
        const tbs = toArrayBuffer(tbsView);
        return await crypto.verifyWithPublicKey(tbs, signature, publicKeyInfo, signatureAlgorithm);
    } catch {
        return false;
    }
}

/**
 * True when the issuer key usage extension permits cRLSign (bit 6).
 * The BIT STRING payload must be canonical DER with complete
 * consumption (RFC 5280 4.1), primitive, and its padding bits zero.
 * Malformed input forbids: the caller reports the single
 * forbids-CRL-signing diagnostic.
 */
function keyUsagePermitsCrlSign(extension: pkijs.Extension, budget: DerDecodeBudget): boolean {
    try {
        const raw = new Uint8Array(extension.extnValue.valueBlock.valueHexView);
        const parsed = parseCanonicalDERValue(raw, "CRL issuer key usage", { budget });
        if (!(parsed instanceof asn1js.BitString)) {
            return false;
        }
        if (parsed.idBlock.isConstructed || parsed.valueBlock.isConstructed) {
            return false;
        }
        const unusedBits = parsed.valueBlock.unusedBits;
        if (!Number.isInteger(unusedBits) || unusedBits < 0 || unusedBits > 7) {
            return false;
        }
        const bits = new Uint8Array(parsed.valueBlock.valueHexView);
        const first = bits[0];
        const last = bits[bits.length - 1];
        if (first === undefined || last === undefined) return false;
        if (unusedBits > 0 && (last & ((1 << unusedBits) - 1)) !== 0) {
            return false;
        }
        return (first & 0x02) !== 0;
    } catch {
        return false;
    }
}

/**
 * Key bytes of the issuer subject key identifier, or null when the
 * issuer carries no single well-formed SKI. Binding hint only: the CRL
 * signature always decides issuance. Never throws.
 */
function issuerSubjectKeyIdentifier(
    issuer: pkijs.Certificate,
    budget: DerDecodeBudget
): Uint8Array | null {
    try {
        const skis = (issuer.extensions ?? []).filter(
            (extension) => extension.extnID === OID_SUBJECT_KEY_IDENTIFIER
        );
        if (skis.length !== 1) return null;
        const ski = skis[0];
        if (ski === undefined) return null;
        const raw = new Uint8Array(ski.extnValue.valueBlock.valueHexView);
        const parsed = parseCanonicalDERValue(raw, "CRL issuer subject key identifier", {
            budget,
        });
        if (!(parsed instanceof asn1js.OctetString) || parsed.idBlock.isConstructed) {
            return null;
        }
        return new Uint8Array(parsed.valueBlock.valueHexView);
    } catch {
        return null;
    }
}

/**
 * Processes one CRL number extension (RFC 5280 5.2.3): canonical
 * INTEGER with complete consumption, non-negative. The value feeds no
 * verdict (there is no delta merging to order); the gate exists so a
 * critical CRL number is recognized-and-processed rather than skipped.
 * Returns a full unknown diagnostic, or null when acceptable.
 */
function checkCrlNumber(extension: pkijs.Extension, budget: DerDecodeBudget): string | null {
    let parsed: asn1js.BaseBlock;
    try {
        const raw = new Uint8Array(extension.extnValue.valueBlock.valueHexView);
        parsed = parseCanonicalDERValue(raw, "CRL number", { budget });
    } catch {
        return "CRL: CRL number extension is malformed; revocation status unknown";
    }
    if (!(parsed instanceof asn1js.Integer)) {
        return "CRL: CRL number extension is malformed; revocation status unknown";
    }
    const content = new Uint8Array(parsed.valueBlock.valueHexView);
    const first = content[0];
    if (first === undefined || first >= 0x80) {
        return "CRL: CRL number is not a non-negative INTEGER; revocation status unknown";
    }
    return null;
}

/**
 * Raw authority-key-identifier member grammar (T07 fix round 4). pkijs
 * matches only leading SEQUENCE members (a trailer after the last
 * matched member is dropped while the keyIdentifier still binds) and
 * only leading [1] children, so the raw framing gates the decoded AKI
 * before it is trusted. Members are context [0]/[1]/[2], each at most
 * once, in DER order; [0]/[2] are primitives, [1] is a non-empty
 * GeneralNames whose every child proves a complete GeneralName (the
 * fullName profile: undecidable [0]/[3]/[5] wrappers deferred,
 * single-Name directoryNames with strict Name grammar). An empty
 * SEQUENCE stays well-formed (all members OPTIONAL; the key-binding
 * rule below decides it). Returns a full unknown diagnostic, or null
 * when the framing is complete.
 */
function checkAkiFraming(parsed: asn1js.BaseBlock): string | null {
    const malformed = MALFORMED_AKI_MESSAGE;
    if (!(parsed instanceof asn1js.Sequence)) return malformed;
    let seen = -1;
    for (const member of parsed.valueBlock.value) {
        if (member.idBlock.tagClass !== 3) return malformed;
        const tag = member.idBlock.tagNumber;
        if (tag !== 0 && tag !== 1 && tag !== 2) return malformed;
        if (tag <= seen) return malformed;
        seen = tag;
        if (tag === 1) {
            if (!(member instanceof asn1js.Constructed)) return malformed;
            const names = member.valueBlock.value;
            if (names.length === 0 || names.length > MAX_CRL_CERT_ISSUER_NAMES) return malformed;
            for (const child of names) {
                if (child.idBlock.tagClass !== 3) return malformed;
                const choice = child.idBlock.tagNumber;
                if (choice < 0 || choice > 8) return malformed;
                if (isUndecidableGeneralNameWrapper(child)) return malformed;
                if (hasSplitDirectoryNameWrapper(child)) return malformed;
                if (choice === 4 && child instanceof asn1js.Constructed) {
                    // The split check above proved exactly one Name
                    // child; the undefined guard is for the type
                    // checker only.
                    const nameNode = child.valueBlock.value[0];
                    if (nameNode === undefined) return malformed;
                    let name: pkijs.RelativeDistinguishedNames;
                    try {
                        name = new pkijs.RelativeDistinguishedNames({ schema: nameNode });
                    } catch {
                        return malformed;
                    }
                    if (!isWellFormedName(name)) return malformed;
                }
            }
        } else if (!(member instanceof asn1js.Primitive)) {
            return malformed;
        }
    }
    return null;
}

/**
 * Processes one CRL authority key identifier (RFC 5280 5.2.1):
 * canonical parse with complete consumption, raw member framing (see
 * above), then keyIdentifier binding against the issuer SKI when both
 * sides are known. A mismatch fails closed at any criticality (a
 * contradicting AKI is never ignored); otherwise a critical AKI must
 * be fully processable (keyIdentifier present and matching, no
 * unprocessed authorityCertIssuer or authorityCertSerialNumber
 * content), while a non-critical AKI without a bindable key identifier
 * is ignored -- the signature decides. Returns a full unknown
 * diagnostic, or null when acceptable.
 */
function checkCrlAuthorityKeyIdentifier(
    extension: pkijs.Extension,
    issuer: pkijs.Certificate,
    budget: DerDecodeBudget
): string | null {
    let parsed: asn1js.BaseBlock;
    try {
        const raw = new Uint8Array(extension.extnValue.valueBlock.valueHexView);
        parsed = parseCanonicalDERValue(raw, "CRL authority key identifier", { budget });
    } catch {
        return MALFORMED_AKI_MESSAGE;
    }
    const framing = checkAkiFraming(parsed);
    if (framing !== null) return framing;
    let aki: pkijs.AuthorityKeyIdentifier;
    try {
        aki = new pkijs.AuthorityKeyIdentifier({ schema: parsed });
    } catch {
        return MALFORMED_AKI_MESSAGE;
    }
    const keyIdentifier = aki.keyIdentifier;
    if (keyIdentifier === undefined) {
        if (extension.critical) {
            return (
                "CRL: CRL authority key identifier carries no processable key " +
                "identifier; revocation status unknown"
            );
        }
        return null;
    }
    const keyId = new Uint8Array(keyIdentifier.valueBlock.valueHexView);
    const issuerSki = issuerSubjectKeyIdentifier(issuer, budget);
    if (issuerSki !== null && !bytesEqual(keyId, issuerSki)) {
        return (
            "CRL: CRL authority key identifier does not match the issuer; " +
            "revocation status unknown"
        );
    }
    if (extension.critical) {
        if (issuerSki === null) {
            return (
                "CRL: CRL authority key identifier cannot be bound to the issuer; " +
                "revocation status unknown"
            );
        }
        if (aki.authorityCertIssuer !== undefined || aki.authorityCertSerialNumber !== undefined) {
            return (
                "CRL: CRL authority key identifier carries unprocessed critical " +
                "content; revocation status unknown"
            );
        }
    }
    return null;
}

/**
 * Processes one issuing distribution point (RFC 5280 5.2.5) with an
 * explicit grammar walk: the supported profile is full CRLs under
 * direct issuance, so any scope constraint partitions the CRL out of
 * the profile. The first member decides: [1]/[2]/[4]/[5] DEFAULT
 * FALSE booleans must be TRUE when present (an explicitly encoded
 * FALSE violates DER minimal encoding of DEFAULT values); [0]
 * distributionPoint and [3] onlySomeReasons partition by presence
 * alone (their payloads need no grammar: the verdict is unknown
 * either way). Member order and duplicates are verdict-neutral --
 * every present member independently rejects -- so no ordering state
 * is tracked. indirectCRL ([4]) gets its own diagnostic. Returns a
 * full unknown diagnostic, or null when the CRL is full-scope.
 */
function checkIssuingDistributionPoint(
    extension: pkijs.Extension,
    budget: DerDecodeBudget
): string | null {
    let parsed: asn1js.BaseBlock;
    try {
        const raw = new Uint8Array(extension.extnValue.valueBlock.valueHexView);
        parsed = parseCanonicalDERValue(raw, "CRL issuing distribution point", { budget });
    } catch {
        return MALFORMED_IDP_MESSAGE;
    }
    if (!(parsed instanceof asn1js.Sequence)) {
        return MALFORMED_IDP_MESSAGE;
    }
    const malformed = MALFORMED_IDP_MESSAGE;
    for (const member of parsed.valueBlock.value) {
        if (member.idBlock.tagClass !== 3) return malformed;
        const tag = member.idBlock.tagNumber;
        if (tag < 0 || tag > 5) return malformed;
        if (tag === 0 || tag === 3) {
            return (
                "CRL: partitioned CRLs are not supported (issuing distribution point " +
                "constrains the CRL scope); revocation status unknown"
            );
        }
        if (tag === 4) {
            if (!isEncodedTrue(member)) return malformed;
            return (
                "CRL: indirect CRLs are not supported (issuing distribution point " +
                "delegates issuance); revocation status unknown"
            );
        }
        // Tags 1, 2, 5: DEFAULT FALSE booleans, TRUE when present.
        if (!isEncodedTrue(member)) return malformed;
        return (
            "CRL: partitioned CRLs are not supported (issuing distribution point " +
            "constrains the CRL scope); revocation status unknown"
        );
    }
    return null;
}

/**
 * True when a context-tagged member encodes BOOLEAN TRUE: primitive,
 * exactly one content octet, 0xFF. FALSE (0x00) is a non-canonical
 * explicit DEFAULT and any other shape is malformed; both fail closed
 * at the caller.
 */
function isEncodedTrue(member: asn1js.BaseBlock): boolean {
    if (!(member instanceof asn1js.Primitive)) return false;
    const content = new Uint8Array(member.valueBlock.valueHexView);
    return content.length === 1 && content[0] === 0xff;
}

/**
 * Freshness of the CRL against the check date. Returns a full unknown
 * diagnostic, or null when fresh. Boundary comparisons are inclusive:
 * a timestamp exactly at checkDate plus or minus skew still counts as
 * fresh. A missing nextUpdate fails closed: without it the freshness
 * horizon is unbounded, and this interface carries no maximum-age
 * policy (unlike the OCSP validator) by design.
 */
function checkCrlFreshness(
    thisUpdate: Date,
    nextUpdate: Date | undefined,
    checkMs: number,
    skewMs: number
): string | null {
    const thisMs = thisUpdate.getTime();
    if (!Number.isFinite(thisMs)) {
        return "CRL: CRL carries non-finite timestamps; revocation status unknown";
    }
    if (thisMs > checkMs + skewMs) {
        return "CRL: CRL thisUpdate is after the check date; revocation status unknown";
    }
    if (nextUpdate === undefined) {
        return "CRL: CRL carries no nextUpdate; freshness is unbounded; revocation status unknown";
    }
    const nextMs = nextUpdate.getTime();
    if (!Number.isFinite(nextMs)) {
        return "CRL: CRL carries non-finite timestamps; revocation status unknown";
    }
    if (nextMs < thisMs) {
        return "CRL: CRL nextUpdate is before thisUpdate; revocation status unknown";
    }
    if (checkMs - skewMs > nextMs) {
        return "CRL: CRL is stale (nextUpdate has passed); revocation status unknown";
    }
    return null;
}

/**
 * Revocation instant of the serial-matching entry against thisUpdate.
 * Returns a full unknown diagnostic, or null when the revocationDate
 * is a finite date no later than thisUpdate plus skew (inclusive).
 * Non-Date shapes are unknown, mirroring checkRevocationTime.
 *
 * @internal Exported for direct unit tests of unreachable-via-DER
 * shapes; not part of any public entry.
 */
export function checkRevocationDate(
    revocationDate: unknown,
    thisUpdateMs: number,
    skewMs: number
): string | null {
    if (!(revocationDate instanceof Date)) {
        return (
            "CRL: matching revoked entry carries a revocationDate with an " +
            "unsupported shape; revocation status unknown"
        );
    }
    const revMs = revocationDate.getTime();
    if (!Number.isFinite(revMs)) {
        return (
            "CRL: matching revoked entry carries a non-finite revocationDate; " +
            "revocation status unknown"
        );
    }
    if (revMs > thisUpdateMs + skewMs) {
        return "CRL: revocationDate is after thisUpdate; revocation status unknown";
    }
    return null;
}

/**
 * Processes one entry reason code (RFC 5280 5.3.1): canonical
 * ENUMERATED with complete consumption, then the value against the
 * supported enumeration. removeFromCRL (8) may only appear in delta
 * CRLs, so it fails this complete-CRL profile; every other defined
 * reason (0-7, 9, 10) confirms the listing. Value 7 is unused by the
 * RFC but carries no remove semantics, so it confirms like the rest;
 * certificateHold (6) does NOT soften the verdict (hold/release
 * semantics belong to T09b). Negative and undefined values fail
 * closed. The value is read from the raw content octets (a minimal
 * multi-octet ENUMERATED is always out of range), never lossy
 * valueDec. Returns a full unknown diagnostic, or null when acceptable.
 */
function checkEntryReasonCode(
    extension: pkijs.Extension,
    budget: DerDecodeBudget,
    where = "matching revoked entry"
): string | null {
    const malformed = `CRL: ${where} carries a malformed reason code; revocation status unknown`;
    let parsed: asn1js.BaseBlock;
    try {
        const raw = new Uint8Array(extension.extnValue.valueBlock.valueHexView);
        parsed = parseCanonicalDERValue(raw, "CRL entry reason code", { budget });
    } catch {
        return malformed;
    }
    if (!(parsed instanceof asn1js.Enumerated)) {
        return malformed;
    }
    const content = new Uint8Array(parsed.valueBlock.valueHexView);
    if (content.length !== 1) {
        return `CRL: ${where} carries an unsupported reason code; revocation status unknown`;
    }
    const value = content[0];
    if (value === 8) {
        return (
            `CRL: ${where} carries removeFromCRL, which is restricted to ` +
            "delta CRLs; revocation status unknown"
        );
    }
    if (value === undefined || (value > 7 && value !== 9 && value !== 10)) {
        return `CRL: ${where} carries an unsupported reason code; revocation status unknown`;
    }
    return null;
}

/**
 * Processes one entry hold instruction code (RFC 5280 5.3.4): canonical
 * OBJECT IDENTIFIER with complete consumption and canonical OID
 * content. The value feeds no verdict (see checkEntryReasonCode).
 * Returns a full unknown diagnostic, or null when acceptable.
 */
function checkEntryHoldInstruction(
    extension: pkijs.Extension,
    budget: DerDecodeBudget,
    where = "matching revoked entry"
): string | null {
    const malformed = `CRL: ${where} carries a malformed hold instruction; revocation status unknown`;
    let parsed: asn1js.BaseBlock;
    try {
        const raw = new Uint8Array(extension.extnValue.valueBlock.valueHexView);
        parsed = parseCanonicalDERValue(raw, "CRL entry hold instruction", { budget });
    } catch {
        return malformed;
    }
    if (!(parsed instanceof asn1js.ObjectIdentifier)) {
        return malformed;
    }
    const content = oidContentOctets(parsed);
    if (content === null || !isCanonicalDerOidContent(content)) {
        return malformed;
    }
    return null;
}

/**
 * True when GeneralizedTime content octets are the canonical profile
 * form: exactly `YYYYMMDDHHMMSSZ` (RFC 5280 4.1.2.5.2 -- Zulu only,
 * seconds required, no fractional seconds, no differential), with a
 * real proleptic-Gregorian calendar date and DER-midnight hours
 * (00-23; 24:00 and leap seconds are non-canonical here). asn1js
 * parses Feb-30, month 13, and `+0000` offsets into a GeneralizedTime
 * without error (silently normalizing), so the raw octets gate the
 * grammar instead of the parsed Date. Deliberately local (not shared
 * with the T09a UTCTime validity check, which compares TBS re-encoding
 * rather than reading raw content): the one caller feeds no verdict
 * from the value, and historical interpretation stays deferred (T09b).
 */
function isCanonicalGeneralizedTimeContent(content: Uint8Array): boolean {
    if (content.length !== 15 || content[14] !== 0x5a) return false;
    for (let index = 0; index < 14; index++) {
        const octet = content[index];
        if (octet === undefined || octet < 0x30 || octet > 0x39) return false;
    }
    const digits = (at: number, count: number): number => {
        let value = 0;
        for (let index = 0; index < count; index++) {
            value = value * 10 + ((content[at + index] ?? 0) - 0x30);
        }
        return value;
    };
    const month = digits(4, 2);
    const day = digits(6, 2);
    const hour = digits(8, 2);
    const minute = digits(10, 2);
    const second = digits(12, 2);
    if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
    const year = digits(0, 4);
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    let daysInMonth = 31;
    if (month === 2) {
        daysInMonth = leap ? 29 : 28;
    } else if (month === 4 || month === 6 || month === 9 || month === 11) {
        daysInMonth = 30;
    }
    return day >= 1 && day <= daysInMonth;
}

/**
 * Processes one entry invalidity date (RFC 5280 5.3.2): canonical
 * GeneralizedTime with complete consumption plus the UTC-seconds and
 * calendar grammar above. UTCTime is the wrong type for this
 * extension. The value feeds no verdict (see checkEntryReasonCode).
 * Returns a full unknown diagnostic, or null when acceptable.
 */
function checkEntryInvalidityDate(
    extension: pkijs.Extension,
    budget: DerDecodeBudget,
    where = "matching revoked entry"
): string | null {
    const malformed = `CRL: ${where} carries a malformed invalidity date; revocation status unknown`;
    let parsed: asn1js.BaseBlock;
    try {
        const raw = new Uint8Array(extension.extnValue.valueBlock.valueHexView);
        parsed = parseCanonicalDERValue(raw, "CRL entry invalidity date", { budget });
    } catch {
        return malformed;
    }
    if (!(parsed instanceof asn1js.GeneralizedTime)) {
        return malformed;
    }
    if (!isCanonicalGeneralizedTimeContent(new Uint8Array(parsed.valueBlock.valueHexView))) {
        return malformed;
    }
    return null;
}

/**
 * Resolves one entry's certificateIssuer extension (RFC 5280 5.3.3) to
 * its explicit issuer scope: in-scope when the entry carries no such
 * extension (the CRL-issuer default) or when the extension names only
 * the verified issuer subject, unknown otherwise. The COMPLETE
 * GeneralNames payload gates scope: it must be a nonempty bounded
 * SEQUENCE, every name must parse, every name must be a directoryName
 * with a well-formed Name, and every directoryName must equal the
 * verified issuer subject. A same-issuer scope restates the
 * direct-issuance default and is accepted (pinned); any foreign,
 * unbindable, or malformed scope fails the direct-only profile. There
 * is deliberately no skip: per-entry scope resets cannot express RFC
 * 5280 5.3.3 inheritance, where an entry without the extension
 * inherits the PRECEDING entry's issuer -- so the caller walks every
 * entry in order before selection, and any foreign scope fails fast
 * there (equivalent to tracking, since no foreign scope can then
 * propagate to an inheriting entry, with a more precise diagnostic).
 */
type EntryIssuerScope =
    { readonly scope: "match" } | { readonly scope: "unknown"; readonly diagnostic: string };

function checkEntryIssuerScope(
    entry: pkijs.RevokedCertificate,
    issuerSubjectHex: string,
    budget: DerDecodeBudget
): EntryIssuerScope {
    const extensions = entry.crlEntryExtensions?.extensions ?? [];
    const issuers = extensions.filter((extension) => extension.extnID === OID_CERTIFICATE_ISSUER);
    if (issuers.length === 0) return { scope: "match" };
    if (issuers.length > 1) {
        return {
            scope: "unknown",
            diagnostic:
                "CRL: revoked entry carries duplicate certificate issuer " +
                "extensions; revocation status unknown",
        };
    }
    const issuerExtension = issuers[0];
    if (issuerExtension === undefined) return { scope: "match" };
    const malformed =
        "CRL: revoked entry carries a malformed certificate issuer; " + "revocation status unknown";
    const outsideProfile =
        "CRL: revoked entry carries a certificate issuer outside the " +
        "direct-issuance profile; revocation status unknown";
    let parsed: asn1js.BaseBlock;
    try {
        const raw = new Uint8Array(issuerExtension.extnValue.valueBlock.valueHexView);
        parsed = parseCanonicalDERValue(raw, "CRL entry certificate issuer", { budget });
    } catch {
        return { scope: "unknown", diagnostic: malformed };
    }
    if (!(parsed instanceof asn1js.Sequence)) {
        return { scope: "unknown", diagnostic: malformed };
    }
    const names = parsed.valueBlock.value;
    if (names.length === 0 || names.length > MAX_CRL_CERT_ISSUER_NAMES) {
        return { scope: "unknown", diagnostic: malformed };
    }
    for (const child of names) {
        // Raw framing first (T07 fix round 3): pkijs decodes the
        // first Name inside [4] and drops trailers, so a split
        // wrapper fails before the decoded value is trusted. The
        // [0]/[5] wrappers need no gate here: any decoded choice but
        // directoryName already resolves outside the profile below.
        if (hasSplitDirectoryNameWrapper(child)) {
            return { scope: "unknown", diagnostic: malformed };
        }
        let name: pkijs.GeneralName;
        try {
            name = new pkijs.GeneralName({ schema: child });
        } catch {
            return { scope: "unknown", diagnostic: malformed };
        }
        if (name.type !== 4 || !(name.value instanceof pkijs.RelativeDistinguishedNames)) {
            return { scope: "unknown", diagnostic: outsideProfile };
        }
        if (!isWellFormedName(name.value)) {
            return { scope: "unknown", diagnostic: malformed };
        }
        if (name.value.toString() !== issuerSubjectHex) {
            return { scope: "unknown", diagnostic: outsideProfile };
        }
    }
    return { scope: "match" };
}

/**
 * Pre-selection gates for one revoked entry. RFC 5280 5.3 forbids using
 * a CRL for ANY certificate when a critical entry extension cannot be
 * processed, so every entry's extension list is gated BEFORE serial
 * selection: the scan cap, the empty-OID and unknown-critical
 * identifier checks, recognized-OID duplicate checks, and the payload
 * grammar of every CRITICAL recognized extension (reason, hold,
 * invalidity date; certificateIssuer payloads gate separately in the
 * scope walk at any criticality, since scope is verdict-relevant).
 * Non-critical recognized payloads on non-selected entries stay
 * verdict-neutral and are ignored here; the selected entry gets the
 * full grammar in checkMatchingEntryExtensions. Returns a full unknown
 * diagnostic, or null when the entry passes.
 */
function checkPreselectedEntryExtensions(
    entry: pkijs.RevokedCertificate,
    budget: DerDecodeBudget
): string | null {
    const extensions = entry.crlEntryExtensions?.extensions ?? [];
    if (extensions.length > MAX_CRL_EXTENSION_SCAN) {
        return (
            `CRL: revoked entry carries ${extensions.length.toString()} extensions, above ` +
            `the supported limit of ${MAX_CRL_EXTENSION_SCAN.toString()}; revocation status unknown`
        );
    }
    const unknownCritical = checkNoUnknownCriticalExtensions(
        extensions,
        RECOGNIZED_CRL_ENTRY_EXTENSIONS,
        "revoked entry"
    );
    if (unknownCritical !== null) return unknownCritical;
    const duplicates: [string, string][] = [
        [OID_REASON_CODE, "reason code"],
        [OID_HOLD_INSTRUCTION_CODE, "hold instruction"],
        [OID_INVALIDITY_DATE, "invalidity date"],
    ];
    for (const [oid, label] of duplicates) {
        if (extensions.filter((extension) => extension.extnID === oid).length > 1) {
            return (
                `CRL: revoked entry carries duplicate ${label} extensions; ` +
                "revocation status unknown"
            );
        }
    }
    for (const extension of extensions) {
        if (!extension.critical) continue;
        if (extension.extnID === OID_REASON_CODE) {
            const failure = checkEntryReasonCode(extension, budget, "revoked entry");
            if (failure !== null) return failure;
        } else if (extension.extnID === OID_HOLD_INSTRUCTION_CODE) {
            const failure = checkEntryHoldInstruction(extension, budget, "revoked entry");
            if (failure !== null) return failure;
        } else if (extension.extnID === OID_INVALIDITY_DATE) {
            const failure = checkEntryInvalidityDate(extension, budget, "revoked entry");
            if (failure !== null) return failure;
        }
    }
    return null;
}

/**
 * Processes the recognized payloads of the selected (serial-matching)
 * revoked entry: the reason code, hold instruction, and invalidity
 * date grammars at any criticality. The pre-selection scan already
 * gated this entry's cap, identifiers, duplicates, and critical
 * payloads; what remains here is the NON-critical recognized payloads,
 * which non-selected entries skip. Returns a full unknown diagnostic,
 * or null when acceptable.
 */
function checkMatchingEntryExtensions(
    entry: pkijs.RevokedCertificate,
    budget: DerDecodeBudget
): string | null {
    const extensions = entry.crlEntryExtensions?.extensions ?? [];
    const reason = extensions.find((extension) => extension.extnID === OID_REASON_CODE);
    if (reason !== undefined) {
        const failure = checkEntryReasonCode(reason, budget);
        if (failure !== null) return failure;
    }
    const hold = extensions.find((extension) => extension.extnID === OID_HOLD_INSTRUCTION_CODE);
    if (hold !== undefined) {
        const failure = checkEntryHoldInstruction(hold, budget);
        if (failure !== null) return failure;
    }
    const date = extensions.find((extension) => extension.extnID === OID_INVALIDITY_DATE);
    if (date !== undefined) {
        const failure = checkEntryInvalidityDate(date, budget);
        if (failure !== null) return failure;
    }
    return null;
}

/**
 * Distribution-scope binding between the certificate and the CRL: at
 * least one certificate distribution point must be in scope for this
 * direct-issuance full-CRL profile. A point is out of scope when it
 * uses nameRelativeToCRLIssuer (unsupported naming) or when it carries
 * cRLIssuer at all: RFC 5280 6.3.3(b)(1) requires a CRL matching a
 * cRLIssuer-bearing point to carry an issuing distribution point with
 * indirectCRL asserted, and indirect CRLs are outside this profile --
 * so no cRLIssuer-bearing point can bind here, even one naming the
 * verified issuer (conforming CAs MUST omit that redundant field
 * anyway, RFC 5280 4.2.1.13; OpenSSL 3.5.5 accepts it in both default
 * and extended modes, a leniency this strict profile deliberately does
 * not share). A point without cRLIssuer defaults to the certificate
 * issuer and is in scope. Distribution-point reasons are
 * verdict-neutral here by the scope-subset relation: the only
 * supported CRL shape is full-scope (any issuing-distribution-point
 * constraint already rejected the CRL above), and a full CRL covers
 * every reason flag. Malformed or over-limit distribution-point
 * metadata fails closed. Returns a full unknown diagnostic, or null
 * when bound.
 */
function checkDistributionScope(cert: pkijs.Certificate, budget: DerDecodeBudget): string | null {
    let points: DistributionPointMetadata[];
    try {
        points = getCRLDistributionPointMetadata(cert, { budget });
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return `${detail}; revocation status unknown`;
    }
    const bound = points.some((point) => {
        if (point.hasRelativeName) return false;
        if (point.crlIssuerDirectoryNames.length > 0 || point.hasUnbindableCrlIssuer) {
            return false;
        }
        return true;
    });
    if (!bound) {
        return "CRL: certificate has no in-scope CRL distribution point; revocation status unknown";
    }
    return null;
}

/**
 * Authenticates one CRL against the T05-verified issuer.
 *
 * Internal (not re-exported from the package entries): ValidationSession
 * calls it with the verified issuer for every collected CRL, cached or
 * fetched. Only an authenticated in-scope CRL yields good/revoked;
 * every other outcome -- malformed bytes, scope mismatch, staleness,
 * unauthorized issuer key use, bad signature, unsupported profile --
 * yields unknown with a diagnostic. Throws INVALID_ARGUMENT only for
 * programming errors (missing or non-finite inputs), never for evidence
 * problems.
 */
export async function validateCRLEvidence(
    crlBytes: Uint8Array,
    options: ValidateCRLOptions
): Promise<RevocationEvidenceResult> {
    if (!(crlBytes instanceof Uint8Array) || crlBytes.length === 0) {
        throw invalidArgument("validateCRLEvidence needs non-empty CRL bytes");
    }
    if (!(options.checkDate instanceof Date) || !Number.isFinite(options.checkDate.getTime())) {
        throw invalidArgument("validateCRLEvidence needs a finite checkDate");
    }
    if (!Number.isFinite(options.clockSkewMs) || options.clockSkewMs < 0) {
        throw invalidArgument("validateCRLEvidence needs a finite non-negative clockSkewMs");
    }

    try {
        return await evaluateCRLEvidence(crlBytes, options);
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return unknownEvidence(`${detail}; revocation status unknown`);
    }
}

async function evaluateCRLEvidence(
    crlBytes: Uint8Array,
    options: ValidateCRLOptions
): Promise<RevocationEvidenceResult> {
    // One shared DER budget bounds the outer CRL, every nested
    // extension payload, and the ECDSA-signature sub-parse as a single
    // aggregate (T03 F6). The issuer-Name grammar walk is the one
    // exception: it re-parses retained name bytes with raw fromBER
    // (bytes already counted in the outer parse, bounded by the outer
    // preflight plus the RDN/attribute caps). T08's OperationBudget
    // will additionally govern attempts, bytes, and deadlines across
    // certificates; per-CRL caps fail closed here.
    const budget = createDerDecodeBudget();
    let outer: asn1js.BaseBlock;
    try {
        outer = parseCanonicalDERSequenceTree(crlBytes, "CRL", { budget });
    } catch (error) {
        throw invalidCrl(error instanceof Error ? error.message : "CRL bytes are malformed");
    }
    if (!(outer instanceof asn1js.Sequence)) {
        throw invalidCrl("CRL bytes must be a SEQUENCE");
    }
    let crl: pkijs.CertificateRevocationList;
    try {
        crl = new pkijs.CertificateRevocationList({ schema: outer });
    } catch {
        throw invalidCrl("CRL bytes do not parse as a CertificateList");
    }
    try {
        // pkijs types CertificateRevocationList.toSchema() as `any`;
        // the double assertion recovers the documented SEQUENCE type.
        const reserialized = crl.toSchema() as unknown as asn1js.Sequence;
        requireSchemaRoundTrip(crlBytes, reserialized.toBER(false), "CRL");
    } catch (error) {
        throw invalidCrl(error instanceof Error ? error.message : "CRL framing is malformed");
    }
    const entries = crl.revokedCertificates ?? [];
    const crlExtensions = crl.crlExtensions?.extensions ?? [];
    const hasEntryExtensions = entries.some((entry) => entry.crlEntryExtensions !== undefined);
    // Version enforcement runs before completeness: the version selects
    // the schema the completeness check assumes. Identity is byte-exact
    // from the retained TBS: `valueDec` overflows past 32 bits (the
    // version 0x0100000000 reads back as 0), so the INTEGER content
    // must be exactly one octet. An absent version defaults to v1(0);
    // extensions (CRL or entry level) require v2 (RFC 5280 5.1.2.1).
    const tbsNode = outer.valueBlock.value[0];
    if (!(tbsNode instanceof asn1js.Sequence)) {
        throw invalidCrl("CRL TBSCertList is malformed");
    }
    const versionNode = tbsNode.valueBlock.value[0];
    if (versionNode instanceof asn1js.Integer) {
        const content = new Uint8Array(versionNode.valueBlock.valueHexView);
        const first = content.length === 1 ? content[0] : undefined;
        if (first === 0 || first === 1) {
            // Well-formed v1/v2; the v1-with-extensions gate below applies.
        } else if (first !== undefined && first < 0x80) {
            return unknownEvidence(
                `CRL: unsupported CRL version ${first.toString()}; revocation status unknown`
            );
        } else {
            return unknownEvidence(
                "CRL: CRL carries a malformed version; revocation status unknown"
            );
        }
    }
    if (crl.version !== 1 && (crl.crlExtensions !== undefined || hasEntryExtensions)) {
        return unknownEvidence(
            "CRL: CRL version 1 must not carry extensions; revocation status unknown"
        );
    }
    // Strict-only TBS completeness: the schema decoder reuses retained
    // TBS bytes, so it cannot see fields it ignored; forcing a
    // field-by-field re-encoding here exposes trailing or duplicated TBS
    // members, and the explicit Name walk covers the retained issuer
    // subtree. Structural LTV collection keeps accepting the bytes as
    // candidate material.
    const tbsFailure = checkCrlTbsCompleteness(crl);
    if (tbsFailure !== null) return unknownEvidence(tbsFailure);

    if (crlExtensions.length > MAX_CRL_EXTENSION_SCAN) {
        return unknownEvidence(
            `CRL: CRL carries ${crlExtensions.length.toString()} extensions, above ` +
                `the supported limit of ${MAX_CRL_EXTENSION_SCAN.toString()}; revocation status unknown`
        );
    }
    // Explicit delta deferral: a delta CRL is never a complete
    // revocation source (absence there proves nothing), and full
    // base/delta merging is deferred work with follow-up criteria in
    // MIGRATION.md -- never treated as complete here. OID-based
    // detection fires before value parsing or criticality filtering.
    if (crlExtensions.some((extension) => extension.extnID === OID_DELTA_CRL_INDICATOR)) {
        return unknownEvidence(
            "CRL: delta CRL is not a complete revocation source; revocation status unknown"
        );
    }
    const unknownCritical = checkNoUnknownCriticalExtensions(
        crlExtensions,
        RECOGNIZED_CRL_EXTENSIONS,
        "CRL"
    );
    if (unknownCritical !== null) return unknownEvidence(unknownCritical);

    const numbers = crlExtensions.filter((extension) => extension.extnID === OID_CRL_NUMBER);
    if (numbers.length > 1) {
        return unknownEvidence(
            "CRL: CRL carries duplicate CRL number extensions; revocation status unknown"
        );
    }
    const number = numbers[0];
    if (number !== undefined) {
        const failure = checkCrlNumber(number, budget);
        if (failure !== null) return unknownEvidence(failure);
    }
    const akis = crlExtensions.filter(
        (extension) => extension.extnID === OID_AUTHORITY_KEY_IDENTIFIER
    );
    if (akis.length > 1) {
        return unknownEvidence(
            "CRL: CRL carries duplicate authority key identifier extensions; " +
                "revocation status unknown"
        );
    }
    const aki = akis[0];
    if (aki !== undefined) {
        const failure = checkCrlAuthorityKeyIdentifier(aki, options.issuer, budget);
        if (failure !== null) return unknownEvidence(failure);
    }
    const idps = crlExtensions.filter(
        (extension) => extension.extnID === OID_ISSUING_DISTRIBUTION_POINT
    );
    if (idps.length > 1) {
        return unknownEvidence(
            "CRL: CRL carries duplicate issuing distribution point extensions; " +
                "revocation status unknown"
        );
    }
    const idp = idps[0];
    if (idp !== undefined) {
        const failure = checkIssuingDistributionPoint(idp, budget);
        if (failure !== null) return unknownEvidence(failure);
    }

    const issuerSubjectHex = options.issuer.subject.toString();
    const scopeFailure = checkDistributionScope(options.cert, budget);
    if (scopeFailure !== null) return unknownEvidence(scopeFailure);

    const freshnessFailure = checkCrlFreshness(
        crl.thisUpdate.value,
        crl.nextUpdate?.value,
        options.checkDate.getTime(),
        options.clockSkewMs
    );
    if (freshnessFailure !== null) return unknownEvidence(freshnessFailure);

    const keyUsages = (options.issuer.extensions ?? []).filter(
        (extension) => extension.extnID === OID_KEY_USAGE
    );
    if (keyUsages.length > 1) {
        return unknownEvidence(
            "CRL: issuer carries duplicate key usage extensions; revocation status unknown"
        );
    }
    const keyUsage = keyUsages[0];
    if (keyUsage !== undefined && !keyUsagePermitsCrlSign(keyUsage, budget)) {
        return unknownEvidence(
            "CRL: issuer key usage forbids CRL signing (cRLSign not set); " +
                "revocation status unknown"
        );
    }

    // Direct issuance only: the CRL issuer name must be the verified
    // issuer subject (the name itself proved well-formed above), and the
    // signature must verify with the verified issuer key. Indirect CRLs
    // were already rejected at the issuing-distribution-point gate.
    if (crl.issuer.toString() !== issuerSubjectHex) {
        return unknownEvidence(
            "CRL: CRL issuer does not match the certificate issuer; revocation status unknown"
        );
    }
    const sigAlgFailure = checkCrlSignatureAlgorithm(crl, options.issuer);
    if (sigAlgFailure !== null) return unknownEvidence(sigAlgFailure);
    // The framing gate runs explicitly here (precise diagnostics) as well
    // as inside verifyTbsSignature (defense in depth at the choke point).
    const framingFailure = checkSignatureValueEncoding(
        crl.signatureValue,
        crl.signatureAlgorithm,
        budget
    );
    if (framingFailure !== null) return unknownEvidence(framingFailure);
    // The issuer key executes below: its SPKI encoding gates first, so
    // backend-tolerated malformations never reach WebCrypto.
    const issuerKeyFailure = checkIssuerPublicKeyEncoding(
        options.issuer.subjectPublicKeyInfo,
        budget
    );
    if (issuerKeyFailure !== null) return unknownEvidence(issuerKeyFailure);
    await ensureWebCrypto();
    const verified = await verifyTbsSignature(
        new Uint8Array(crl.tbsView),
        crl.signatureValue,
        options.issuer.subjectPublicKeyInfo,
        crl.signatureAlgorithm,
        budget
    );
    if (!verified) {
        return unknownEvidence(
            "CRL: CRL signature does not verify with the issuer key; revocation status unknown"
        );
    }

    if (entries.length > MAX_CRL_REVOKED_ENTRIES) {
        return unknownEvidence(
            `CRL: CRL carries ${entries.length.toString()} revoked entries, above ` +
                `the supported limit of ${MAX_CRL_REVOKED_ENTRIES.toString()}; revocation status unknown`
        );
    }
    const wanted = serialIdentityBytes(options.cert.serialNumber);
    if (wanted === null) {
        return unknownEvidence(
            "CRL: certificate serial number is malformed; revocation status unknown"
        );
    }
    // Pre-selection scan: a good verdict reasons about absence, so
    // every entry is gated BEFORE any verdict is selected, uniformly
    // for good and revoked outcomes. Phase one validates serials (one
    // malformed entry undermines the whole scan) and rejects duplicate
    // serial identities up front, so duplicate diagnostics never depend
    // on entry order; within the surviving entry set every scope is the
    // CRL issuer, so a repeated serial is a repeated serial/issuer
    // identity. Phase two walks the entries in order, gating each
    // extension list (RFC 5280 5.3 forbids using the CRL when ANY
    // critical entry extension cannot be processed) and resolving
    // issuer scope (RFC 5280 5.3.3 inheritance; any foreign scope fails
    // the direct-only profile immediately, so no foreign scope can
    // propagate to an inheriting entry).
    const seenSerials = new Set<string>();
    for (const entry of entries) {
        const candidate = serialIdentityBytes(entry.userCertificate);
        if (candidate === null) {
            return unknownEvidence(
                "CRL: CRL entry carries a malformed serial number; revocation status unknown"
            );
        }
        const serialKey = bytesToHex(candidate);
        if (seenSerials.has(serialKey)) {
            return unknownEvidence(
                "CRL: CRL entry carries a duplicate serial number; revocation status unknown"
            );
        }
        seenSerials.add(serialKey);
    }
    let match: pkijs.RevokedCertificate | null = null;
    for (const entry of entries) {
        const candidate = serialIdentityBytes(entry.userCertificate);
        if (candidate === null) {
            return unknownEvidence(
                "CRL: CRL entry carries a malformed serial number; revocation status unknown"
            );
        }
        const entryFailure = checkPreselectedEntryExtensions(entry, budget);
        if (entryFailure !== null) return unknownEvidence(entryFailure);
        const scope = checkEntryIssuerScope(entry, issuerSubjectHex, budget);
        if (scope.scope === "unknown") return unknownEvidence(scope.diagnostic);
        if (bytesEqual(candidate, wanted)) match = entry;
    }
    if (match === null) {
        const status: RevocationStatus = "good";
        return { status, source: "CRL", errors: [] };
    }
    const matchFailure = checkMatchingEntryExtensions(match, budget);
    if (matchFailure !== null) return unknownEvidence(matchFailure);
    const dateFailure = checkRevocationDate(
        match.revocationDate.value,
        crl.thisUpdate.value.getTime(),
        options.clockSkewMs
    );
    if (dateFailure !== null) return unknownEvidence(dateFailure);
    const status: RevocationStatus = "revoked";
    return { status, source: "CRL", errors: [] };
}
