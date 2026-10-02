import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { TimestampError, TimestampErrorCode } from "../types.js";
import { toArrayBuffer } from "../utils.js";
import { ensureWebCrypto } from "../utils/web-crypto.js";
import { verifyIssuance } from "./cert-utils.js";
import {
    createDerDecodeBudget,
    parseCanonicalDERSequenceTree,
    parseCanonicalDERValue,
    requireSchemaRoundTrip,
    type DerDecodeBudget,
} from "./der-utils.js";
import {
    CertificateStatus,
    OCSP_NONCE_OID,
    classifySingleCertStatus,
    parseBasicOCSPResponse,
} from "./ocsp-utils.js";
import type { RevocationEvidenceResult, RevocationStatus } from "./validation-types.js";

/**
 * Strict OCSP evidence authentication (RFC 6960, T06).
 *
 * This module is deliberately NOT a thin wrapper around
 * `BasicOCSPResponse.verify`: auditing pkijs 3.4.1 shows that adapter
 * cannot express this session's policy. It throws unless the response
 * embeds certificates (our issuer-direct profile needs none), runs full
 * chain validation against caller trust anchors (this session carries no
 * trust store), requires authorization for EVERY SingleResponse rather
 * than the requested one, and checks no nonce, no request CertID, and no
 * freshness window. Signature verification here reuses only the same
 * public WebCrypto primitive (`verifyWithPublicKey` over the retained
 * `tbsView` bytes) that `Certificate.verify` uses; every policy decision
 * below is explicit, including responder-certificate validity (pkijs
 * default dates such as the 1899 quirk in T05 never stand in for parsed
 * validity periods).
 */

// ---------------------------------------------------------------------------
// Bounds. Legitimate traffic carries one SingleResponse, a couple of
// embedded certificates, and a couple of extensions; the caps below are
// generous multiples of that. They bound per-response work only: T08's
// OperationBudget will govern aggregate attempts, bytes, and deadlines
// across certificates, and the hook sites are marked there.
// ---------------------------------------------------------------------------

/** Maximum SingleResponse entries scanned for a CertID match. */
export const MAX_OCSP_SINGLE_RESPONSES = 32;

/** Maximum embedded certificates scanned for responder authorization. */
export const MAX_OCSP_EMBEDDED_CERTS = 32;

/** Maximum extensions walked in any single extension list. */
export const MAX_OCSP_EXTENSION_SCAN = 64;

/** Maximum RDNs walked in one strict Name grammar check. */
export const MAX_OCSP_NAME_RDNS = 64;

/** Maximum attribute type-and-value entries walked in one strict Name grammar check. */
export const MAX_OCSP_NAME_ATTRIBUTES = 256;

const OID_KEY_USAGE = "2.5.29.15";
const OID_EXTENDED_KEY_USAGE = "2.5.29.37";
const OID_OCSP_SIGNING_EKU = "1.3.6.1.5.5.7.3.9";
const OID_OCSP_NOCHECK = "1.3.6.1.5.5.7.48.1.5";
const OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const OID_RSASSA_PSS = "1.2.840.113549.1.1.10";

/**
 * RSASSA-PKCS1-v1_5 signature OIDs (SHA-1/256/384/512). Shared by the
 * response path and the delegate-certificate path (see
 * checkDelegateCertificateSignatureAlgorithm for the CA matrix rationale).
 */
const RSA_PKCS1V15_SIGNATURE_OIDS: ReadonlySet<string> = new Set([
    "1.2.840.113549.1.1.5",
    "1.2.840.113549.1.1.11",
    "1.2.840.113549.1.1.12",
    "1.2.840.113549.1.1.13",
]);

/**
 * ECDSA signature OIDs (SHA-1/256/384/512). Shared by the response
 * path and the delegate-certificate path.
 */
const ECDSA_SIGNATURE_OIDS: ReadonlySet<string> = new Set([
    "1.2.840.10045.4.1",
    "1.2.840.10045.4.3.2",
    "1.2.840.10045.4.3.3",
    "1.2.840.10045.4.3.4",
]);

/** Response extensions this profile actually processes: the nonce echo only. */
const RECOGNIZED_OCSP_RESPONSE_EXTENSIONS: ReadonlySet<string> = new Set([OCSP_NONCE_OID]);

/**
 * SingleResponse extensions this profile actually processes: none. The
 * nonce echo is read at the response level only, so even the nonce OID
 * is unrecognized (and critical-fatal) on a SingleResponse.
 */
const RECOGNIZED_OCSP_SINGLE_EXTENSIONS: ReadonlySet<string> = new Set([]);

/** Delegate certificate extensions this profile actually processes. */
const RECOGNIZED_DELEGATE_CERT_EXTENSIONS: ReadonlySet<string> = new Set([
    OID_KEY_USAGE,
    OID_EXTENDED_KEY_USAGE,
    OID_OCSP_NOCHECK,
]);

/**
 * Options for internal OCSP evidence authentication. Policy values come
 * from the ValidationSession options; the expected CertID and nonce are
 * read from the exact request bytes, never reconstructed.
 */
export interface ValidateOCSPOptions {
    /** Certificate the revocation status is evaluated for. */
    cert: pkijs.Certificate;
    /** T05-verified issuing certificate of `cert`. */
    issuer: pkijs.Certificate;
    /** Exact DER request bytes the session sent for this certificate. */
    requestBytes: Uint8Array;
    /** Moment the evidence must be fresh and live at. */
    checkDate: Date;
    /** Accepted clock skew in milliseconds, applied both directions. */
    clockSkewMs: number;
    /**
     * Freshness horizon for responses without nextUpdate: thisUpdate older
     * than checkDate minus skew minus this age is stale.
     */
    maxAgeWithoutNextUpdateMs: number;
}

interface OCSPRequestBinding {
    certId: pkijs.CertID;
    nonce: Uint8Array | null;
}

function unknownEvidence(diagnostic: string): RevocationEvidenceResult {
    return { status: "unknown", source: "OCSP", errors: [diagnostic] };
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

/**
 * Decodes one nonce extension value: an OCTET STRING wrapping the raw
 * nonce bytes (RFC 6960). Extension values require DER (RFC 5280 4.1),
 * and the outer preflight cannot see inside this OCTET STRING, so the
 * payload gets its own canonical framing and complete-consumption gate.
 * Throws INVALID_RESPONSE when malformed.
 */
function decodeNonceValue(extension: pkijs.Extension, where: string): Uint8Array {
    const raw = new Uint8Array(extension.extnValue.valueBlock.valueHexView);
    let parsed: asn1js.BaseBlock;
    try {
        parsed = parseCanonicalDERValue(raw, `${where} OCSP nonce`);
    } catch {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            `${where} carries a malformed OCSP nonce`
        );
    }
    if (!(parsed instanceof asn1js.OctetString) || parsed.idBlock.isConstructed) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            `${where} carries a malformed OCSP nonce`
        );
    }
    const inner = new Uint8Array(parsed.valueBlock.valueHexView);
    if (inner.length === 0) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            `${where} carries an empty OCSP nonce`
        );
    }
    return inner;
}

/**
 * Reads the expected CertID and nonce from the exact request bytes. The
 * supported profile is a single-request exchange: zero or multiple
 * request entries, duplicate nonces, and malformed nonce values fail
 * closed. Throws INVALID_RESPONSE; the caller maps that to unknown.
 */
function parseOCSPRequestBinding(
    requestBytes: Uint8Array,
    budget: DerDecodeBudget
): OCSPRequestBinding {
    const asn1 = parseCanonicalDERSequenceTree(requestBytes, "OCSP request", { budget });
    const request = new pkijs.OCSPRequest({ schema: asn1 });
    requireSchemaRoundTrip(requestBytes, request.toSchema().toBER(false), "OCSP request");
    // Forced TBS re-encoding: the default serialization above reuses the
    // retained TBS bytes, so duplicate or trailing TBS members would pass
    // through unseen. Compare against the original TBS encoding instead.
    requireSchemaRoundTrip(
        request.tbsRequest.tbsView,
        request.tbsRequest.toSchema(true).toBER(false),
        "OCSP request TBS"
    );
    // RFC 6960 defines only v1(0) for TBSRequest; pkijs accepts any
    // INTEGER here, so the version needs its own explicit check.
    if (request.tbsRequest.version !== undefined && request.tbsRequest.version !== 0) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "OCSP request version must be v1 (0)"
        );
    }
    if (request.tbsRequest.requestList.length !== 1) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "OCSP request must contain exactly one request"
        );
    }
    const first = request.tbsRequest.requestList[0];
    if (!first) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "OCSP request must contain exactly one request"
        );
    }
    const extensions = request.tbsRequest.requestExtensions ?? [];
    if (extensions.length > MAX_OCSP_EXTENSION_SCAN) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            `OCSP request carries ${extensions.length.toString()} extensions, above the supported limit of ${MAX_OCSP_EXTENSION_SCAN.toString()}`
        );
    }
    const nonces = extensions.filter((extension) => extension.extnID === OCSP_NONCE_OID);
    if (nonces.length > 1) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "OCSP request carries duplicate nonces"
        );
    }
    const only = nonces[0];
    return {
        certId: first.reqCert,
        nonce: only === undefined ? null : decodeNonceValue(only, "OCSP request"),
    };
}

/**
 * Freshness of one matching SingleResponse against the check date.
 * Returns a diagnostic fragment, or null when fresh. Boundary
 * comparisons are inclusive: a timestamp exactly at checkDate plus or
 * minus skew still counts as fresh.
 */
function checkSingleFreshness(
    thisUpdate: Date,
    nextUpdate: Date | undefined,
    producedAt: Date,
    checkMs: number,
    skewMs: number,
    maxAgeMs: number
): string | null {
    const thisMs = thisUpdate.getTime();
    const producedMs = producedAt.getTime();
    if (!Number.isFinite(thisMs) || !Number.isFinite(producedMs)) {
        return "response carries non-finite timestamps";
    }
    if (thisMs > checkMs + skewMs) {
        return "thisUpdate is after the check date";
    }
    if (thisMs > producedMs + skewMs) {
        return "thisUpdate is after producedAt";
    }
    if (producedMs > checkMs + skewMs) {
        return "producedAt is after the check date";
    }
    if (nextUpdate !== undefined) {
        const nextMs = nextUpdate.getTime();
        if (!Number.isFinite(nextMs)) {
            return "response carries non-finite timestamps";
        }
        if (nextMs < thisMs) {
            return "nextUpdate is before thisUpdate";
        }
        if (checkMs - skewMs > nextMs) {
            return "response is stale (nextUpdate has passed)";
        }
        return null;
    }
    if (checkMs - skewMs > thisMs + maxAgeMs) {
        return "response is stale (no nextUpdate and thisUpdate exceeds the maximum age)";
    }
    return null;
}

/**
 * True when GeneralizedTime content octets are the profile form:
 * `YYYYMMDDHHMMSSZ` with a real proleptic-Gregorian calendar date and
 * DER-midnight hours, plus an optional millisecond-precision fraction
 * (`.f`, `.ff`, or `.fff`). asn1js parses Feb-30, month 13, and `+0000`
 * offsets into a GeneralizedTime without error (silently normalizing),
 * so the raw octets gate the grammar instead of the parsed Date. The
 * calendar core mirrors the CRL invalidityDate grammar; the fraction
 * tail is required here because revocationTime feeds millisecond
 * comparisons (unlike the verdict-neutral invalidityDate), and this
 * stack emits `.fffZ` for non-zero milliseconds. Deliberately local
 * rather than shared (see the duplication note in crl-validation.ts).
 */
function isCanonicalGeneralizedTimeContent(content: Uint8Array): boolean {
    // Whole seconds (15 octets) or millisecond fraction (17-19).
    const wholeSeconds = content.length === 15;
    const fractionDigits = content.length - 16;
    const fractional = fractionDigits >= 1 && fractionDigits <= 3 && content[14] === 0x2e;
    if (!wholeSeconds && !fractional) return false;
    if (content[content.length - 1] !== 0x5a) return false;
    for (let index = 0; index < 14; index++) {
        const octet = content[index];
        if (octet === undefined || octet < 0x30 || octet > 0x39) return false;
    }
    if (fractional) {
        for (let index = 15; index < content.length - 1; index++) {
            const octet = content[index];
            if (octet === undefined || octet < 0x30 || octet > 0x39) return false;
        }
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
 * Revoked instant of one matching SingleResponse against thisUpdate.
 * Returns a diagnostic fragment, or null when the revocationTime is a
 * finite date with canonical calendar content no later than thisUpdate
 * plus skew (inclusive). Only revoked statuses reach here; grammar was
 * enforced before selection, so anything but a GeneralizedTime instant
 * is an unsupported shape.
 *
 * @internal Exported for direct unit tests of unreachable-via-DER
 * shapes; not part of any public entry.
 */
export function checkRevocationTime(
    certStatus: unknown,
    thisUpdate: Date,
    skewMs: number
): string | null {
    const revoked = certStatus instanceof asn1js.Constructed ? certStatus : null;
    const instant = revoked?.valueBlock.value[0];
    if (!(instant instanceof asn1js.GeneralizedTime)) {
        return "revocationTime has an unsupported shape";
    }
    const revMs = instant.toDate().getTime();
    if (!Number.isFinite(revMs)) {
        return "revocationTime is not a finite date";
    }
    // Placed after the finite check so the defense-in-depth non-finite
    // pin keeps its message; before the comparison so impossible
    // calendar dates never feed a verdict.
    if (!isCanonicalGeneralizedTimeContent(new Uint8Array(instant.valueBlock.valueHexView))) {
        return "revocationTime is not a canonical calendar date";
    }
    if (revMs > thisUpdate.getTime() + skewMs) {
        return "revocationTime is after thisUpdate";
    }
    return null;
}

/**
 * ResponderID match for one certificate. By-name compares the
 * encoded-name hex pkijs `PkiObject.toString()` returns (its default
 * `encoding` is "hex", not semantic DN text): strictly narrower than
 * semantic matching -- a PrintableString and a UTF8String spelling of
 * the same name compare UNEQUAL here while pkijs `isEqual()` would
 * return true. That only ever fails closed (a differently-encoded
 * legitimate name yields unknown, never a false GOOD); adopting
 * semantic matching would be a separate compatibility change. By-key
 * compares the RFC 6960 KeyHash (SHA-1 over the subjectPublicKey BIT
 * STRING contents). A malformed responder name matches nothing:
 * without that, a retained name subtree carrying ignored members
 * could match-or-bypass on a future pkijs comparison. Never throws;
 * any failure means no match.
 */
async function responderIdMatchesCert(
    responderID: unknown,
    cert: pkijs.Certificate
): Promise<boolean> {
    try {
        if (responderID instanceof pkijs.RelativeDistinguishedNames) {
            if (!isWellFormedName(responderID)) return false;
            return cert.subject.toString() === responderID.toString();
        }
        if (responderID instanceof asn1js.OctetString) {
            const contents = cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView;
            const digest = await globalThis.crypto.subtle.digest("SHA-1", toArrayBuffer(contents));
            return bytesEqual(
                new Uint8Array(digest),
                new Uint8Array(responderID.valueBlock.valueHexView)
            );
        }
        return false;
    } catch {
        return false;
    }
}

/**
 * True when the key usage extension permits digitalSignature (bit 0).
 * The BIT STRING payload must be canonical DER with complete
 * consumption (RFC 5280 4.1), primitive (constructed BIT STRINGs carry
 * per-segment unused-bit counts, so padding could not be checked), and
 * its padding bits zero: the low n bits of the last content octet must
 * be clear for n declared unused bits. Nonzero unused-bit counts stay
 * legal (`03 02 07 80` permits digitalSignature).
 */
function keyUsagePermitsDigitalSignature(extension: pkijs.Extension): boolean {
    try {
        const raw = new Uint8Array(extension.extnValue.valueBlock.valueHexView);
        const parsed = parseCanonicalDERValue(raw, "delegated responder key usage");
        if (!(parsed instanceof asn1js.BitString)) {
            return false;
        }
        if (parsed.idBlock.isConstructed || parsed.valueBlock.isConstructed) {
            return false;
        }
        // asn1js rejects unused-bit counts above 7 while parsing
        // (fail-closed upstream); the range check below pins that.
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
        return (first & 0x80) !== 0;
    } catch {
        return false;
    }
}

/**
 * Raw content octets of a parsed OBJECT IDENTIFIER. asn1js keeps only
 * the normalized dotted string in `valueBlock` (`valueHexView` is
 * empty for OIDs), so the exact content octets come from the retained
 * TLV (`valueBeforeDecodeView`) minus the tag+length header, whose
 * span is the retained length less `lenBlock.length`. Returns null
 * when the retained bytes are inconsistent; callers fail closed.
 */
function oidContentOctets(oid: asn1js.ObjectIdentifier): Uint8Array | null {
    const encoded = oid.valueBeforeDecodeView;
    const contentLength = oid.lenBlock.length;
    if (!Number.isInteger(contentLength) || contentLength < 0 || contentLength > encoded.length) {
        return null;
    }
    return encoded.subarray(encoded.length - contentLength);
}

/**
 * True when OBJECT IDENTIFIER content octets are canonical DER
 * (X.690 8.19). asn1js normalizes OID values on parse (a non-minimal
 * subidentifier still reads as id-kp-OCSPSigning) and re-emits an
 * empty `06 00` byte-identically, while the TLV preflight covers
 * framing but not OID contents -- so both gaps authorize without
 * this check. The content must be nonempty, every subidentifier must
 * terminate (an MSB-set octet with no successor means truncation),
 * and every subidentifier must use minimal base-128: a multi-octet
 * subidentifier whose first octet is 0x80 carries zero high bits and
 * could drop that octet (X.690 8.19.2 fewest-octets rule). There is
 * deliberately no first-octet range check: every first-subidentifier
 * value maps to a valid first arc (values at or above 80 are arc 2),
 * so a 119 cap would reject the legitimate 2.40+ space.
 */
function isCanonicalDerOidContent(content: Uint8Array): boolean {
    if (content.length === 0) return false;
    let index = 0;
    while (index < content.length) {
        const first = content[index];
        if (first === undefined) return false;
        if ((first & 0x80) === 0) {
            index += 1;
            continue;
        }
        if (first === 0x80) return false;
        index += 1;
        let terminated = false;
        while (index < content.length) {
            const octet = content[index];
            if (octet === undefined) return false;
            index += 1;
            if ((octet & 0x80) === 0) {
                terminated = true;
                break;
            }
        }
        if (!terminated) return false;
    }
    return true;
}

/**
 * True when the extended key usage explicitly lists id-kp-OCSPSigning.
 * anyExtendedKeyUsage alone does not satisfy this profile. The value
 * must be a canonical DER SEQUENCE (RFC 5280 4.1) of only OBJECT
 * IDENTIFIERs with complete consumption: a non-OID member fails the
 * whole extension instead of being skipped, as does any member whose
 * OID content is not canonical DER (empty, unterminated, or
 * non-minimal base-128).
 */
function ekuHasOCSPSigning(extension: pkijs.Extension): boolean {
    try {
        const raw = new Uint8Array(extension.extnValue.valueBlock.valueHexView);
        const parsed = parseCanonicalDERValue(raw, "delegated responder extended key usage");
        if (!(parsed instanceof asn1js.Sequence)) {
            return false;
        }
        let found = false;
        for (const child of parsed.valueBlock.value) {
            if (!(child instanceof asn1js.ObjectIdentifier)) {
                return false;
            }
            const content = oidContentOctets(child);
            if (content === null || !isCanonicalDerOidContent(content)) {
                return false;
            }
            if (child.valueBlock.toString() === OID_OCSP_SIGNING_EKU) {
                found = true;
            }
        }
        return found;
    } catch {
        return false;
    }
}

/**
 * True when the nocheck extension value is exactly the DER NULL bytes
 * `05 00` (RFC 6960 4.2.2.2.1: the value is NULL, so BOOLEAN FALSE
 * and padded encodings do not authorize). The comparison is on raw
 * bytes, not an asn1js parse: asn1js accepts `05 01 00` and
 * `05 81 00` as Null with a mere warning, and neither is DER.
 */
function isWellFormedNoCheck(extension: pkijs.Extension | undefined): boolean {
    if (extension === undefined) return false;
    try {
        const raw = new Uint8Array(extension.extnValue.valueBlock.valueHexView);
        return raw.length === 2 && raw[0] === 0x05 && raw[1] === 0x00;
    } catch {
        return false;
    }
}

/**
 * Rejects unsupported critical extensions in one extension list. Callers
 * pass the OIDs this profile actually processes; any other critical
 * extension fails closed (RFC 5280 4.2, RFC 6960 4.4). An empty extnID
 * rejects before criticality filtering: an OID value with no content
 * octets is malformed (X.690 8.19) even when noncritical. Empty-only
 * is deliberate, not a gap: pkijs retains no raw extnID bytes on
 * Extension objects (own keys are exactly extnID/critical/extnValue),
 * and OID-spelling normalization is verdict-neutral here -- every
 * branch decision uses payload bytes plus criticality, while unknown
 * IDs are ignored-or-critical-rejected by string either way. Returns
 * a full unknown diagnostic, or null when the list is acceptable.
 */
function checkNoUnknownCriticalExtensions(
    extensions: pkijs.Extension[],
    recognized: ReadonlySet<string>,
    where: string
): string | null {
    for (const extension of extensions) {
        if (extension.extnID === "") {
            return (
                `OCSP: ${where} carries an extension with an empty extension OID; ` +
                `revocation status unknown`
            );
        }
        if (extension.critical && !recognized.has(extension.extnID)) {
            return (
                `OCSP: ${where} carries an unsupported critical extension ` +
                `(${extension.extnID}); revocation status unknown`
            );
        }
    }
    return null;
}

/**
 * Strict Name grammar over the retained RDN subtree (RFC 5280 4.1.2.4).
 * pkijs retains parsed names verbatim (`valueBeforeDecode`) and re-emits
 * them on `toSchema()`, so the forced TBS round-trip cannot see extra or
 * duplicated name members. This walk runs over the original name bytes:
 * Name is a SEQUENCE of SETs (RDNs), each holding attribute
 * type-and-value SEQUENCEs of exactly { type OID, value }. Completeness
 * only: multi-valued RDNs, unusual-but-legal value types, long names,
 * and an entirely empty Name sequence all pass; an empty RDN SET
 * violates its minimum cardinality (RFC 5280 4.1.2.4) and fails, as do
 * extra members, missing members, non-OID types, type OIDs whose
 * content is not canonical DER (empty, unterminated, or non-minimal
 * base-128), and non-SET/non-SEQUENCE framing. Never throws; any
 * failure means malformed.
 */
function isWellFormedName(name: pkijs.RelativeDistinguishedNames): boolean {
    try {
        const retained = name.valueBeforeDecode;
        const bytes =
            retained.byteLength > 0
                ? new Uint8Array(retained)
                : new Uint8Array(name.toSchema().toBER(false));
        const parsed = asn1js.fromBER(toArrayBuffer(bytes));
        if (parsed.offset === -1 || parsed.offset !== bytes.length) return false;
        if (!(parsed.result instanceof asn1js.Sequence)) return false;
        const rdns = parsed.result.valueBlock.value;
        if (rdns.length > MAX_OCSP_NAME_RDNS) return false;
        let attributes = 0;
        for (const rdn of rdns) {
            if (!(rdn instanceof asn1js.Set)) return false;
            if (rdn.valueBlock.value.length === 0) return false;
            for (const member of rdn.valueBlock.value) {
                attributes += 1;
                if (attributes > MAX_OCSP_NAME_ATTRIBUTES) return false;
                if (!(member instanceof asn1js.Sequence)) return false;
                const parts = member.valueBlock.value;
                if (parts.length !== 2) return false;
                if (!(parts[0] instanceof asn1js.ObjectIdentifier)) return false;
                const typeContent = oidContentOctets(parts[0]);
                if (typeContent === null || !isCanonicalDerOidContent(typeContent)) return false;
            }
        }
        return true;
    } catch {
        return false;
    }
}

/**
 * Strict-only TBSCertificate completeness for the selected delegate.
 * The forced field-by-field re-encoding exposes trailing or duplicated
 * TBS members the schema decoder ignored (a second [3] extensions
 * wrapper, validity or extension-framing extras), while the explicit
 * issuer/subject Name walks cover the retained name subtrees that
 * re-encoding re-emits verbatim. Runs before any decoded extension is
 * trusted: the duplicate-wrapper case proves the extension list itself
 * is attacker-shaped without it. Original signature bytes stay
 * authoritative (verifyIssuance inputs unchanged), and the issuer, the
 * target, and structural collection are untouched. Returns a full
 * unknown diagnostic, or null when complete.
 */
function checkDelegateTbsCompleteness(candidate: pkijs.Certificate): string | null {
    let forced: Uint8Array;
    try {
        forced = new Uint8Array(candidate.encodeTBS().toBER(false));
    } catch {
        return (
            "OCSP: delegated responder certificate TBS is malformed; " + "revocation status unknown"
        );
    }
    if (!bytesEqual(new Uint8Array(candidate.tbsView), forced)) {
        return (
            "OCSP: delegated responder certificate TBS does not fully conform " +
            "to the certificate schema; revocation status unknown"
        );
    }
    if (!isWellFormedName(candidate.issuer) || !isWellFormedName(candidate.subject)) {
        return (
            "OCSP: delegated responder certificate carries a malformed " +
            "distinguished name; revocation status unknown"
        );
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
 * Validates the delegate certificate's own signature algorithms before
 * issuance verification runs. pkijs `Certificate.verify()` reads only
 * the OUTER signatureAlgorithm, and its WebCrypto adapter takes the
 * verification family from the issuer key and only the hash from the
 * declared OID -- so a relabelled outer OID (or an inner/outer pair
 * that merely disagrees) verifies under an algorithm that never
 * executed, where OpenSSL refuses. RFC 5280 section 4.1.1.2 requires
 * the inner (TBSCertificate.signature) and outer
 * (Certificate.signatureAlgorithm) identifiers to be the SAME
 * algorithm: the OIDs must match, and the parameters must both be
 * absent or carry byte-identical DER. NULL-vs-absent is a known
 * cross-signer variance (RSA signers emit NULL, ECDSA signers omit),
 * but within one certificate both identifiers come from a single
 * signing operation, so a certificate that mixes them fails closed
 * here. The agreed OID must then suit the ISSUER key family: RSA keys
 * pair only with RSASSA-PKCS1-v1_5 OIDs (parameters NULL or absent,
 * as on the response path), EC keys only with ECDSA OIDs (parameters
 * absent per RFC 5758). RSA-PSS, EdDSA, and unknown OIDs fail closed:
 * the backend cannot execute EdDSA at all, and PSS -- though
 * verifiable -- reads its salt and hash from the declared parameters
 * with silent defaults, which this strict profile does not model (the
 * same exclusion the response path already applies). Delegate-path-
 * local: shared `verifyIssuance` semantics used by T05 request binding
 * and AIA gating are unchanged. Returns a full unknown diagnostic, or
 * null when the pair may be executed.
 */
function checkDelegateCertificateSignatureAlgorithm(
    candidate: pkijs.Certificate,
    issuer: pkijs.Certificate
): string | null {
    const inner = candidate.signature;
    const outer = candidate.signatureAlgorithm;
    if (inner.algorithmId !== outer.algorithmId) {
        return (
            "OCSP: responder certificate carries inconsistent signature algorithms " +
            `(inner ${inner.algorithmId} vs outer ${outer.algorithmId}); ` +
            "revocation status unknown"
        );
    }
    if (!algorithmParametersEqual(inner, outer)) {
        return (
            "OCSP: responder certificate carries inconsistent signature algorithm " +
            `parameters for ${inner.algorithmId}; revocation status unknown`
        );
    }
    const params: unknown = outer.algorithmParams;
    const keyOid = issuer.subjectPublicKeyInfo.algorithm.algorithmId;
    const sigOid = inner.algorithmId;
    if (keyOid === OID_RSA_ENCRYPTION && RSA_PKCS1V15_SIGNATURE_OIDS.has(sigOid)) {
        // RSASSA-PKCS1-v1_5 parameters are NULL when present; pkijs-built
        // certificates omit them while real-world CAs encode NULL.
        if (
            params !== undefined &&
            !(params instanceof asn1js.Any) &&
            !(params instanceof asn1js.Null)
        ) {
            return (
                `OCSP: responder certificate signature algorithm ${sigOid} carries unsupported ` +
                "parameters for the issuer RSA key; revocation status unknown"
            );
        }
        return null;
    }
    if (keyOid === OID_EC_PUBLIC_KEY && ECDSA_SIGNATURE_OIDS.has(sigOid)) {
        // RFC 5758 section 3.1: ECDSA signature parameters MUST be absent.
        if (params !== undefined && !(params instanceof asn1js.Any)) {
            return (
                `OCSP: responder certificate signature algorithm ${sigOid} carries unexpected ` +
                "parameters for the issuer EC key; revocation status unknown"
            );
        }
        return null;
    }
    return (
        `OCSP: responder certificate signature algorithm ${sigOid} is not compatible with ` +
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
 * offset check) and matches schemas that ignore extra members, so both
 * shapes need their own complete-consumption gate: canonical DER framing
 * (definite minimal lengths, primitive minimal INTEGERs), exactly two
 * INTEGER members, and strictly positive values. The ECDSA range check
 * against the curve order stays with WebCrypto (oversized components
 * throw during raw conversion and fail closed there). Returns a full
 * unknown diagnostic, or null when the payload is well-formed.
 */
function checkIntegerPairEncoding(payload: Uint8Array, what: string): string | null {
    let tree: asn1js.BaseBlock;
    try {
        tree = parseCanonicalDERSequenceTree(payload, `OCSP ${what}`);
    } catch {
        return `OCSP: ${what} is malformed; revocation status unknown`;
    }
    if (!(tree instanceof asn1js.Sequence)) {
        return `OCSP: ${what} is malformed; revocation status unknown`;
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
        return `OCSP: ${what} must contain exactly two INTEGERs; revocation status unknown`;
    }
    if (
        !isStrictPositiveIntegerContent(new Uint8Array(first.valueBlock.valueHexView)) ||
        !isStrictPositiveIntegerContent(new Uint8Array(second.valueBlock.valueHexView))
    ) {
        return `OCSP: ${what} carries a non-positive INTEGER; revocation status unknown`;
    }
    return null;
}

/**
 * Strict signature BIT STRING framing for the two signatures this module
 * verifies: the BasicOCSPResponse signature and the delegated responder
 * certificate signatureValue. pkijs verifies over `valueHexView`, which
 * excludes the unused-bits octet, and its ECDSA path decodes the first
 * DER object while ignoring trailing bytes -- so a primitive, nonempty,
 * octet-aligned BIT STRING and (for ECDSA OIDs) a canonical two-INTEGER
 * payload with complete consumption are required BEFORE the WebCrypto
 * primitive runs. RSA payloads stay opaque here: they are raw fixed-length
 * bytes, so trailing garbage breaks verification naturally. Returns a
 * full unknown diagnostic, or null when the value may be executed.
 */
function checkSignatureValueEncoding(
    signature: asn1js.BitString,
    signatureAlgorithm: pkijs.AlgorithmIdentifier,
    where: string
): string | null {
    if (signature.idBlock.isConstructed || signature.valueBlock.isConstructed) {
        return `OCSP: ${where} signature is not a primitive BIT STRING; revocation status unknown`;
    }
    if (signature.valueBlock.unusedBits !== 0) {
        return `OCSP: ${where} signature BIT STRING is not octet-aligned; revocation status unknown`;
    }
    if (signature.valueBlock.valueHexView.byteLength === 0) {
        return `OCSP: ${where} signature is empty; revocation status unknown`;
    }
    if (ECDSA_SIGNATURE_OIDS.has(signatureAlgorithm.algorithmId)) {
        return checkIntegerPairEncoding(
            new Uint8Array(signature.valueBlock.valueHexView),
            `${where} ECDSA signature`
        );
    }
    return null;
}

/**
 * Strict-only encoding of the selected delegate public key. The TBS
 * completeness round-trip re-emits the SPKI BIT STRING payload verbatim
 * and preserves its unused-bit count, so payload garbage, non-NULL
 * parameters, and misalignment all survive to key import, where WebCrypto
 * tolerates them: RSA payloads need their own complete-consumption parse
 * (RSAPublicKey, RFC 3279 2.3.1), RSA parameters must be NULL or absent,
 * and EC parameters must be exactly the named-curve OID the import
 * consumes (anything else fails import fail-closed today, and curves the
 * backend cannot name do too). On-curve EC point validation stays with
 * key import, which enforces it. The caller-trusted issuer SPKI is
 * intentionally unchecked. Returns a full unknown diagnostic, or null
 * when the key may be executed.
 */
function checkDelegatePublicKeyEncoding(spki: pkijs.PublicKeyInfo): string | null {
    const keyOid = spki.algorithm.algorithmId;
    const params: unknown = spki.algorithm.algorithmParams;
    if (keyOid === OID_RSA_ENCRYPTION) {
        if (
            params !== undefined &&
            !(params instanceof asn1js.Any) &&
            !(params instanceof asn1js.Null)
        ) {
            return (
                "OCSP: delegated responder RSA public key carries unsupported " +
                "parameters; revocation status unknown"
            );
        }
    } else if (keyOid === OID_EC_PUBLIC_KEY) {
        if (!(params instanceof asn1js.ObjectIdentifier)) {
            return (
                "OCSP: delegated responder EC public key requires named-curve " +
                "parameters; revocation status unknown"
            );
        }
    } else {
        return (
            `OCSP: delegated responder key algorithm ${keyOid} is not supported; ` +
            "revocation status unknown"
        );
    }
    const keyBits = spki.subjectPublicKey;
    if (keyBits.idBlock.isConstructed || keyBits.valueBlock.isConstructed) {
        return (
            "OCSP: delegated responder public key is not a primitive BIT STRING; " +
            "revocation status unknown"
        );
    }
    if (keyBits.valueBlock.unusedBits !== 0) {
        return (
            "OCSP: delegated responder public key BIT STRING is not octet-aligned; " +
            "revocation status unknown"
        );
    }
    if (keyBits.valueBlock.valueHexView.byteLength === 0) {
        return "OCSP: delegated responder public key is empty; revocation status unknown";
    }
    if (keyOid === OID_RSA_ENCRYPTION) {
        return checkIntegerPairEncoding(
            new Uint8Array(keyBits.valueBlock.valueHexView),
            "delegated responder RSA public key"
        );
    }
    return null;
}

/**
 * RFC 6960 section 4.2.2.2 delegated-responder authorization against the
 * verified issuer: complete TBSCertificate schema consumption first,
 * then X.509 v3 (the mandatory extensions below cannot occur in a
 * conforming v1/v2 certificate), then direct issuance -- but only
 * after the delegate's own signature algorithms prove consistent with
 * each other and compatible with the issuer key, and its signatureValue
 * framing and public-key encoding prove strict -- then
 * digitalSignature key usage when the
 * extension is present, mandatory id-kp-OCSPSigning EKU, validity at
 * both the check date and producedAt (with skew, after the interval
 * itself proves non-inverted), and
 * id-pkix-ocsp-nocheck. The nocheck
 * requirement is the documented profile boundary: this session does not
 * implement delegate revocation checking, so a delegate that requires it
 * is unsupported, never silently trusted. Returns a full unknown
 * diagnostic, or null when authorized.
 */
async function checkDelegateAuthorization(
    candidate: pkijs.Certificate,
    issuer: pkijs.Certificate,
    checkMs: number,
    skewMs: number,
    producedMs: number
): Promise<string | null> {
    const tbsFailure = checkDelegateTbsCompleteness(candidate);
    if (tbsFailure !== null) return tbsFailure;
    // pkijs exposes an absent version as its v1(0) default, so one
    // comparison covers absent, v1/v2, and out-of-range versions alike.
    // The issuer is caller-trusted context and stays unchecked.
    if (candidate.version !== 2) {
        return "OCSP: delegated responder certificate must be X.509 v3; revocation status unknown";
    }
    const extensions = candidate.extensions ?? [];
    if (extensions.length > MAX_OCSP_EXTENSION_SCAN) {
        return (
            `OCSP: responder certificate carries ${extensions.length.toString()} extensions, ` +
            `above the supported limit of ${MAX_OCSP_EXTENSION_SCAN.toString()}; ` +
            "revocation status unknown"
        );
    }
    const unknownCritical = checkNoUnknownCriticalExtensions(
        extensions,
        RECOGNIZED_DELEGATE_CERT_EXTENSIONS,
        "responder certificate"
    );
    if (unknownCritical !== null) return unknownCritical;
    const certSigAlgFailure = checkDelegateCertificateSignatureAlgorithm(candidate, issuer);
    if (certSigAlgFailure !== null) return certSigAlgFailure;
    // The delegate signatureValue framing and key encoding are validated
    // before either is executed: both survive the TBS round-trip (the
    // signature sits outside the TBS, the key payload re-emits verbatim)
    // and pkijs/WebCrypto tolerate the malformations below. The OUTER
    // identifier decides the ECDSA grammar half: it is the one
    // `verifyIssuance` executes, and the consistency gate above proved it
    // equal to the inner one. Shared `verifyIssuance` semantics are
    // unchanged.
    const delegateSigFailure = checkSignatureValueEncoding(
        candidate.signatureValue,
        candidate.signatureAlgorithm,
        "delegated responder certificate"
    );
    if (delegateSigFailure !== null) return delegateSigFailure;
    const delegateKeyFailure = checkDelegatePublicKeyEncoding(candidate.subjectPublicKeyInfo);
    if (delegateKeyFailure !== null) return delegateKeyFailure;
    if (!(await verifyIssuance(candidate, issuer))) {
        return (
            "OCSP: delegated responder certificate was not issued by the certificate " +
            "issuer; revocation status unknown"
        );
    }
    const keyUsages = extensions.filter((extension) => extension.extnID === OID_KEY_USAGE);
    if (keyUsages.length > 1) {
        return (
            "OCSP: delegated responder certificate carries duplicate key usage extensions; " +
            "revocation status unknown"
        );
    }
    const keyUsage = keyUsages[0];
    if (keyUsage !== undefined && !keyUsagePermitsDigitalSignature(keyUsage)) {
        return (
            "OCSP: delegated responder key usage forbids digital signatures; " +
            "revocation status unknown"
        );
    }
    const ekus = extensions.filter((extension) => extension.extnID === OID_EXTENDED_KEY_USAGE);
    const eku = ekus[0];
    if (ekus.length !== 1 || eku === undefined || !ekuHasOCSPSigning(eku)) {
        return (
            "OCSP: delegated responder lacks the id-kp-OCSPSigning extended key usage; " +
            "revocation status unknown"
        );
    }
    const notBefore = candidate.notBefore.value.getTime();
    const notAfter = candidate.notAfter.value.getTime();
    // Inverted intervals are rejected before skew is applied: expanded
    // endpoints compared independently would otherwise admit a certificate
    // whose validity never begins (RFC 5280 4.1.2.5). Equal endpoints stay
    // valid. NaN endpoints compare false here and fall through to the
    // finite check below.
    if (notAfter < notBefore) {
        return (
            "OCSP: delegated responder certificate carries an inverted validity period " +
            "(notAfter is before notBefore); revocation status unknown"
        );
    }
    if (
        !Number.isFinite(notBefore) ||
        !Number.isFinite(notAfter) ||
        checkMs < notBefore - skewMs ||
        checkMs > notAfter + skewMs
    ) {
        return (
            "OCSP: delegated responder certificate is outside its validity period at the " +
            "check date; revocation status unknown"
        );
    }
    if (producedMs < notBefore - skewMs || producedMs > notAfter + skewMs) {
        return (
            "OCSP: delegated responder certificate is outside its validity period at " +
            "producedAt; revocation status unknown"
        );
    }
    const nochecks = extensions.filter((extension) => extension.extnID === OID_OCSP_NOCHECK);
    if (nochecks.length === 0) {
        return (
            "OCSP: delegated responder lacks id-pkix-ocsp-nocheck (delegate revocation " +
            "checking is an unsupported policy); revocation status unknown"
        );
    }
    if (nochecks.length > 1 || !isWellFormedNoCheck(nochecks[0])) {
        return (
            "OCSP: delegated responder id-pkix-ocsp-nocheck is malformed (exactly one " +
            "NULL-valued extension is required); revocation status unknown"
        );
    }
    return null;
}

/**
 * Validates the declared response signature algorithm against the
 * responder key before the WebCrypto primitive runs. pkijs selects the
 * verification family from the key and only the hash from this
 * identifier, so a relabelled OID would otherwise verify under an
 * algorithm that never executed. RSA-PSS and unrecognized OIDs are
 * unsupported by this profile. Returns a full unknown diagnostic, or
 * null when the pair may be executed.
 */
function checkSignatureAlgorithm(
    publicKeyInfo: pkijs.PublicKeyInfo,
    signatureAlgorithm: pkijs.AlgorithmIdentifier,
    keyDescription: string
): string | null {
    const keyOid = publicKeyInfo.algorithm.algorithmId;
    const sigOid = signatureAlgorithm.algorithmId;
    const params: unknown = signatureAlgorithm.algorithmParams;
    if (keyOid === OID_RSA_ENCRYPTION && RSA_PKCS1V15_SIGNATURE_OIDS.has(sigOid)) {
        // RSASSA-PKCS1-v1_5 parameters are NULL when present; pkijs-built
        // responses omit them while real-world responders encode NULL.
        if (params !== undefined && !(params instanceof asn1js.Null)) {
            return (
                `OCSP: response signature algorithm ${sigOid} carries unsupported ` +
                `parameters for the ${keyDescription} RSA key; revocation status unknown`
            );
        }
        return null;
    }
    if (keyOid === OID_EC_PUBLIC_KEY && ECDSA_SIGNATURE_OIDS.has(sigOid)) {
        // RFC 5758 section 3.1: ECDSA signature parameters MUST be absent.
        if (params !== undefined) {
            return (
                `OCSP: response signature algorithm ${sigOid} carries unexpected ` +
                `parameters for the ${keyDescription} EC key; revocation status unknown`
            );
        }
        return null;
    }
    if (sigOid === OID_RSASSA_PSS) {
        return (
            "OCSP: response signature uses RSA-PSS, which the supported profile " +
            "does not implement; revocation status unknown"
        );
    }
    return (
        `OCSP: response signature algorithm ${sigOid} is not compatible with ` +
        `the ${keyDescription} key (${keyOid}); revocation status unknown`
    );
}

/**
 * Combines an issuer-candidate failure with the delegate-path outcome so
 * the diagnostic reflects every attempted path instead of the first one
 * alone. A null issuer failure passes the delegate diagnostic through.
 */
function withIssuerContext(delegateDiagnostic: string, issuerFailure: string | null): string {
    if (issuerFailure === null) return delegateDiagnostic;
    const suffix = "; revocation status unknown";
    const issuerPart = issuerFailure.endsWith(suffix)
        ? issuerFailure.slice(0, -suffix.length)
        : issuerFailure;
    const delegatePart = delegateDiagnostic.startsWith("OCSP: ")
        ? delegateDiagnostic.slice("OCSP: ".length)
        : delegateDiagnostic;
    return `${issuerPart}; ${delegatePart}`;
}

/**
 * Verifies the BasicOCSPResponse signature over the retained TBS bytes
 * with the responder public key, using the same public pkijs WebCrypto
 * primitive as Certificate.verify. Strict framing and ECDSA grammar are
 * enforced before the primitive runs. Never throws; any failure
 * (including an unsupported algorithm or a missing engine) means
 * unverified.
 */
async function verifyTbsSignature(
    tbsView: Uint8Array,
    signature: asn1js.BitString,
    publicKeyInfo: pkijs.PublicKeyInfo,
    signatureAlgorithm: pkijs.AlgorithmIdentifier
): Promise<boolean> {
    try {
        if (tbsView.length === 0) return false;
        // Malformed framing or ECDSA grammar fails closed before the
        // WebCrypto primitive runs: both call sites (issuer and delegate
        // paths) share this choke point, so one gate covers both.
        if (checkSignatureValueEncoding(signature, signatureAlgorithm, "response") !== null) {
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
 * Authenticates one OCSP response against the exact request bytes.
 *
 * Internal (not re-exported from the package entries): ValidationSession
 * calls it with the T05-verified issuer and the request bytes it sent.
 * Only an authenticated matching response yields good/revoked; every
 * other outcome -- malformed bytes, CertID/nonce mismatch, staleness,
 * unauthorized responder, bad signature -- yields unknown with a
 * diagnostic. Throws INVALID_ARGUMENT only for programming errors
 * (missing or non-finite inputs), never for evidence problems.
 */
export async function validateOCSPEvidence(
    responseBytes: Uint8Array,
    options: ValidateOCSPOptions
): Promise<RevocationEvidenceResult> {
    if (!(responseBytes instanceof Uint8Array) || responseBytes.length === 0) {
        throw invalidArgument("validateOCSPEvidence needs non-empty response bytes");
    }
    if (!(options.requestBytes instanceof Uint8Array) || options.requestBytes.length === 0) {
        throw invalidArgument("validateOCSPEvidence needs non-empty request bytes");
    }
    if (!(options.checkDate instanceof Date) || !Number.isFinite(options.checkDate.getTime())) {
        throw invalidArgument("validateOCSPEvidence needs a finite checkDate");
    }
    if (!Number.isFinite(options.clockSkewMs) || options.clockSkewMs < 0) {
        throw invalidArgument("validateOCSPEvidence needs a finite non-negative clockSkewMs");
    }
    if (
        !Number.isFinite(options.maxAgeWithoutNextUpdateMs) ||
        options.maxAgeWithoutNextUpdateMs < 0
    ) {
        throw invalidArgument(
            "validateOCSPEvidence needs a finite non-negative maxAgeWithoutNextUpdateMs"
        );
    }

    try {
        return await evaluateOCSPEvidence(responseBytes, options);
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return unknownEvidence(`${detail}; revocation status unknown`);
    }
}

/**
 * Strict CertStatus grammar for the validator (RFC 6960 Section 4.2).
 * pkijs retains the parsed certStatus subtree verbatim and re-emits it
 * on `toSchema(true)`, so the forced TBS round-trip cannot see extra or
 * duplicated RevokedInfo members. This check runs before classification:
 * revoked is [1] carrying exactly revocationTime plus at most one [0]
 * EXPLICIT reason wrapper with exactly one ENUMERATED value; good is
 * primitive [0] with no content; unknown is primitive [2] with no
 * content ([2] IMPLICIT UnknownInfo, and UnknownInfo is NULL). The
 * shared structural classifier is untouched: LTV collection keeps
 * accepting the bytes as candidate material.
 */
function requireStrictCertStatusGrammar(certStatus: unknown): void {
    const malformed = new TimestampError(
        TimestampErrorCode.INVALID_RESPONSE,
        "OCSP response certificate status is malformed"
    );
    if (!(certStatus instanceof asn1js.Primitive) && !(certStatus instanceof asn1js.Constructed)) {
        throw malformed;
    }
    if (certStatus.idBlock.tagClass !== 3) {
        throw malformed;
    }
    switch (certStatus.idBlock.tagNumber) {
        case 0:
        case 2: {
            if (
                !(certStatus instanceof asn1js.Primitive) ||
                certStatus.valueBlock.valueHexView.byteLength !== 0
            ) {
                throw malformed;
            }
            return;
        }
        case 1: {
            if (!(certStatus instanceof asn1js.Constructed)) {
                throw malformed;
            }
            const children = certStatus.valueBlock.value;
            if (children.length < 1 || children.length > 2) {
                throw malformed;
            }
            if (!(children[0] instanceof asn1js.GeneralizedTime)) {
                throw malformed;
            }
            if (children.length === 1) {
                return;
            }
            const reason = children[1];
            if (
                !(reason instanceof asn1js.Constructed) ||
                reason.idBlock.tagClass !== 3 ||
                reason.idBlock.tagNumber !== 0
            ) {
                throw malformed;
            }
            const inner = reason.valueBlock.value;
            if (inner.length !== 1 || !(inner[0] instanceof asn1js.Enumerated)) {
                throw malformed;
            }
            return;
        }
        default: {
            throw malformed;
        }
    }
}

async function evaluateOCSPEvidence(
    responseBytes: Uint8Array,
    options: ValidateOCSPOptions
): Promise<RevocationEvidenceResult> {
    // One shared DER budget bounds the request, the outer response, and
    // the nested BasicOCSPResponse as a single aggregate (T03 F6).
    const budget = createDerDecodeBudget();
    const binding = parseOCSPRequestBinding(options.requestBytes, budget);
    const { basic } = parseBasicOCSPResponse(responseBytes, { budget });
    // Strict-only TBS completeness: the shared structural parser reuses
    // the retained TBS bytes (pkijs `toSchema()` defaults to
    // `encodeFlag = false`), so it cannot see fields the schema decoder
    // ignored. Forcing a field-by-field re-encoding here exposes
    // trailing or duplicated TBS members; the retained original bytes
    // stay authoritative for signatures, and structural LTV collection
    // keeps accepting the bytes as candidate material.
    const forcedTbs: unknown = basic.tbsResponseData.toSchema(true);
    if (!(forcedTbs instanceof asn1js.Sequence)) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "BasicOCSPResponse TBS is malformed"
        );
    }
    requireSchemaRoundTrip(
        basic.tbsResponseData.tbsView,
        forcedTbs.toBER(false),
        "BasicOCSPResponse TBS"
    );
    // RFC 6960 defines only v1(0) for ResponseData; pkijs accepts any
    // INTEGER here, so the version needs its own explicit check.
    if (basic.tbsResponseData.version !== undefined && basic.tbsResponseData.version !== 0) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "BasicOCSPResponse version must be v1 (0)"
        );
    }
    const tbs = basic.tbsResponseData;

    const singles = tbs.responses;
    if (singles.length > MAX_OCSP_SINGLE_RESPONSES) {
        return unknownEvidence(
            `OCSP: response carries ${singles.length.toString()} SingleResponses, above the ` +
                `supported limit of ${MAX_OCSP_SINGLE_RESPONSES.toString()}; revocation status unknown`
        );
    }
    const matches = singles.filter((single) => {
        try {
            return single.certID.isEqual(binding.certId);
        } catch {
            return false;
        }
    });
    if (matches.length === 0) {
        return unknownEvidence(
            "OCSP: no SingleResponse matches the request CertID; revocation status unknown"
        );
    }
    const statuses: CertificateStatus[] = [];
    for (const match of matches) {
        try {
            requireStrictCertStatusGrammar(match.certStatus);
            statuses.push(classifySingleCertStatus(match.certStatus));
        } catch {
            return unknownEvidence(
                "OCSP: matching SingleResponse has a malformed certificate status; " +
                    "revocation status unknown"
            );
        }
    }
    if (new Set(statuses).size > 1) {
        return unknownEvidence(
            "OCSP: conflicting SingleResponses match the request CertID; revocation status unknown"
        );
    }

    const responseExtensions = tbs.responseExtensions ?? [];
    if (responseExtensions.length > MAX_OCSP_EXTENSION_SCAN) {
        return unknownEvidence(
            `OCSP: response carries ${responseExtensions.length.toString()} extensions, above ` +
                `the supported limit of ${MAX_OCSP_EXTENSION_SCAN.toString()}; revocation status unknown`
        );
    }
    const unknownCriticalResponse = checkNoUnknownCriticalExtensions(
        responseExtensions,
        RECOGNIZED_OCSP_RESPONSE_EXTENSIONS,
        "response"
    );
    if (unknownCriticalResponse !== null) return unknownEvidence(unknownCriticalResponse);
    // Only the selected evidence is scanned: extensions on SingleResponses
    // that do not match the request CertID constrain nothing decisive.
    for (const match of matches) {
        const singleExtensions = match.singleExtensions ?? [];
        if (singleExtensions.length > MAX_OCSP_EXTENSION_SCAN) {
            return unknownEvidence(
                `OCSP: matching SingleResponse carries ${singleExtensions.length.toString()} extensions, above ` +
                    `the supported limit of ${MAX_OCSP_EXTENSION_SCAN.toString()}; revocation status unknown`
            );
        }
        const unknownCriticalSingle = checkNoUnknownCriticalExtensions(
            singleExtensions,
            RECOGNIZED_OCSP_SINGLE_EXTENSIONS,
            "matching SingleResponse"
        );
        if (unknownCriticalSingle !== null) return unknownEvidence(unknownCriticalSingle);
    }
    if (binding.nonce !== null) {
        const echoes = responseExtensions.filter(
            (extension) => extension.extnID === OCSP_NONCE_OID
        );
        if (echoes.length === 0) {
            return unknownEvidence(
                "OCSP: request nonce has no response echo; revocation status unknown"
            );
        }
        if (echoes.length > 1) {
            return unknownEvidence(
                "OCSP: response carries duplicate nonces; revocation status unknown"
            );
        }
        const echo = echoes[0];
        if (echo === undefined) {
            return unknownEvidence(
                "OCSP: request nonce has no response echo; revocation status unknown"
            );
        }
        let echoed: Uint8Array;
        try {
            echoed = decodeNonceValue(echo, "OCSP response");
        } catch (error) {
            const detail = error instanceof Error ? error.message : String(error);
            return unknownEvidence(`${detail}; revocation status unknown`);
        }
        if (!bytesEqual(echoed, binding.nonce)) {
            return unknownEvidence(
                "OCSP: response nonce does not match the request; revocation status unknown"
            );
        }
    }
    // Omit mode: the request carries no nonce, so response nonces are
    // unsolicited and ignored entirely.

    const checkMs = options.checkDate.getTime();
    for (const [index, match] of matches.entries()) {
        const stale = checkSingleFreshness(
            match.thisUpdate,
            match.nextUpdate,
            tbs.producedAt,
            checkMs,
            options.clockSkewMs,
            options.maxAgeWithoutNextUpdateMs
        );
        if (stale !== null) {
            return unknownEvidence(`OCSP: ${stale}; revocation status unknown`);
        }
        // A revoked verdict additionally requires the revocation
        // instant itself: finite and no later than thisUpdate plus
        // skew, evaluated for every matching SingleResponse.
        if (statuses[index] === CertificateStatus.REVOKED) {
            const badInstant = checkRevocationTime(
                match.certStatus,
                match.thisUpdate,
                options.clockSkewMs
            );
            if (badInstant !== null) {
                return unknownEvidence(`OCSP: ${badInstant}; revocation status unknown`);
            }
        }
    }

    await ensureWebCrypto();
    // The issuer is one candidate among the embedded delegates: when its
    // key does not verify, matching delegates still get their turn
    // instead of the first failure deciding alone.
    const issuerMatches = await responderIdMatchesCert(tbs.responderID, options.issuer);
    let issuerVerified = false;
    let issuerFailure: string | null = null;
    if (issuerMatches) {
        // Issuer-direct: the T05-verified issuer key decides. No key
        // usage, EKU, validity, or nocheck requirements apply to this
        // caller-trusted context; path validity stays with the caller.
        issuerFailure = checkSignatureAlgorithm(
            options.issuer.subjectPublicKeyInfo,
            basic.signatureAlgorithm,
            "issuer"
        );
        if (issuerFailure === null) {
            const verified = await verifyTbsSignature(
                tbs.tbsView,
                basic.signature,
                options.issuer.subjectPublicKeyInfo,
                basic.signatureAlgorithm
            );
            if (verified) {
                issuerVerified = true;
            } else {
                issuerFailure =
                    "OCSP: response signature does not verify with the issuer key; " +
                    "revocation status unknown";
            }
        }
    }
    if (!issuerVerified) {
        const embedded = basic.certs ?? [];
        if (embedded.length === 0 && issuerFailure !== null) {
            // No delegate path exists: the issuer failure decides alone.
            return unknownEvidence(issuerFailure);
        }
        if (embedded.length > MAX_OCSP_EMBEDDED_CERTS) {
            return unknownEvidence(
                withIssuerContext(
                    `OCSP: response embeds ${embedded.length.toString()} certificates, above the ` +
                        `supported limit of ${MAX_OCSP_EMBEDDED_CERTS.toString()}; revocation status unknown`,
                    issuerFailure
                )
            );
        }
        const candidates: pkijs.Certificate[] = [];
        for (const cert of embedded) {
            if (await responderIdMatchesCert(tbs.responderID, cert)) {
                candidates.push(cert);
            }
        }
        if (candidates.length === 0) {
            return unknownEvidence(
                withIssuerContext(
                    "OCSP: no responder certificate matches the ResponderID; revocation status unknown",
                    issuerFailure
                )
            );
        }
        let authorized = false;
        let firstFailure: string | null = null;
        for (const candidate of candidates) {
            const failure = await checkDelegateAuthorization(
                candidate,
                options.issuer,
                checkMs,
                options.clockSkewMs,
                tbs.producedAt.getTime()
            );
            if (failure !== null) {
                firstFailure ??= failure;
                continue;
            }
            const sigAlgFailure = checkSignatureAlgorithm(
                candidate.subjectPublicKeyInfo,
                basic.signatureAlgorithm,
                "delegated responder"
            );
            if (sigAlgFailure !== null) {
                firstFailure ??= sigAlgFailure;
                continue;
            }
            const verified = await verifyTbsSignature(
                tbs.tbsView,
                basic.signature,
                candidate.subjectPublicKeyInfo,
                basic.signatureAlgorithm
            );
            if (!verified) {
                firstFailure ??=
                    "OCSP: response signature does not verify with the delegated responder " +
                    "key; revocation status unknown";
                continue;
            }
            authorized = true;
            break;
        }
        if (!authorized) {
            return unknownEvidence(
                withIssuerContext(
                    firstFailure ??
                        "OCSP: delegated responder is not authorized; revocation status unknown",
                    issuerFailure
                )
            );
        }
    }

    const matched = statuses[0];
    let status: RevocationStatus = "unknown";
    if (matched === CertificateStatus.GOOD) {
        status = "good";
    } else if (matched === CertificateStatus.REVOKED) {
        status = "revoked";
    }
    if (status === "unknown") {
        return unknownEvidence(
            "OCSP: responder reports unknown for the certificate; revocation status unknown"
        );
    }
    return { status, source: "OCSP", errors: [] };
}
