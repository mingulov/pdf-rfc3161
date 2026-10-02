/* eslint-disable @typescript-eslint/no-deprecated -- compatibility alias coverage */
import { beforeAll, describe, expect, it } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { toArrayBuffer } from "../../../core/src/utils.js";
import { ValidationSession } from "../../../core/src/pki/validation-session.js";
import * as sessionModule from "../../../core/src/pki/validation-session.js";
import { MockFetcher } from "../../../core/src/pki/fetchers/mock-fetcher.js";
import { InMemoryValidationCache } from "../../../core/src/pki/fetchers/memory-cache.js";
import {
    createOCSPRequest,
    parseOCSPResponse,
    CertificateStatus,
    OCSP_NONCE_OID,
} from "../../../core/src/pki/ocsp-utils.js";
import type {
    RevocationDataFetcher,
    ValidationCache,
} from "../../../core/src/pki/validation-types.js";
import { TimestampErrorCode } from "../../../core/src/types.js";
import { completeLTVData } from "../../../core/src/pdf/ltv.js";
import {
    createDelegateResponder,
    createSignedOCSPResponse,
    createTestCA,
    createTestLeaf,
    corruptResponseSignature,
    distinguishedName,
    extendedKeyUsageExtension,
    generateECKeyPair,
    inspectOCSPRequest,
    nonceExtension,
    ocspNoCheckExtension,
    rawEkuExtension,
    rawKeyUsageExtension,
    rawNoCheckExtension,
    requestWithDuplicateEntries,
    requestWithDuplicateNonce,
    roundTripCertificate,
    type SignedOCSPResponseOptions,
    type TestCertificateAuthority,
    type TestKeyPair,
    type TestLeaf,
    type TestResponder,
    unknownExtension,
} from "../fixtures/signed-revocation-material.js";
import { generateRSAKeyPair } from "../utils/crypto.js";

// T06: OCSP evidence is authenticated (R1/R22). Only a response that is
// signed by the issuer or an authorized delegate, bound to the exact
// request CertID/nonce, and fresh at the check date yields good/revoked.
// Everything else stays unknown with diagnostics. No verdict parser is
// mocked in this file: every response carries real keys and real
// signatures round-tripped through DER.

const OCSP_URL = "http://ocsp.example.com/";
const CRL_URL = "http://crl.example.com/ca.crl";

// Fixed policy clock so every time boundary is deterministic.
const CHECK_DATE = new Date("2026-05-01T12:00:00Z");
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_AGE_WITHOUT_NEXT_UPDATE_MS = 24 * 60 * 60 * 1000;
const PRODUCED_AT = new Date("2026-05-01T11:00:00Z");
const THIS_UPDATE = new Date("2026-05-01T11:00:00Z");
const NEXT_UPDATE = new Date("2026-05-02T11:00:00Z");

type OcspValidationModule = typeof import("../../../core/src/pki/ocsp-validation.js");

/**
 * Loads the T06 validator. On BASE the module does not exist, so the
 * import rejects and the test fails with an assertion (module absence),
 * not an infrastructure error -- the same red discipline as the T04/T05
 * typeof guards, adapted to a brand-new module.
 */
async function expectValidator(): Promise<OcspValidationModule> {
    const loaded = await import("../../../core/src/pki/ocsp-validation.js").catch(
        () => null as OcspValidationModule | null
    );
    expect(loaded, "validateOCSPEvidence module exists (T06 implementation)").not.toBeNull();
    expect(typeof loaded?.validateOCSPEvidence).toBe("function");
    return loaded!;
}

function recordingFetcher(responses: {
    ocsp?: Uint8Array;
    crl?: Uint8Array;
}): RevocationDataFetcher & { ocspRequests: Uint8Array[]; ocspCalls: number; crlCalls: number } {
    const fetcher: RevocationDataFetcher & {
        ocspRequests: Uint8Array[];
        ocspCalls: number;
        crlCalls: number;
    } = {
        ocspRequests: [],
        ocspCalls: 0,
        crlCalls: 0,
        fetchOCSP: (_url: string, request: Uint8Array) => {
            fetcher.ocspCalls += 1;
            fetcher.ocspRequests.push(request);
            if (!responses.ocsp) return Promise.reject(new Error("no OCSP response"));
            return Promise.resolve(responses.ocsp);
        },
        fetchCRL: (_url: string) => {
            fetcher.crlCalls += 1;
            if (!responses.crl) return Promise.reject(new Error("no CRL response"));
            return Promise.resolve(responses.crl);
        },
    };
    return fetcher;
}

/** Re-encodes request bytes with extra padding extensions (cap fixture). */
function requestWithManyExtensions(requestBytes: Uint8Array, padding: number): Uint8Array {
    const asn1 = asn1js.fromBER(toArrayBuffer(requestBytes.slice()));
    if (asn1.offset === -1) throw new Error("request is not DER");
    const request = new pkijs.OCSPRequest({ schema: asn1.result });
    const extensions = [...(request.tbsRequest.requestExtensions ?? [])];
    for (let index = 0; index < padding; index++) {
        extensions.push(
            new pkijs.Extension({
                extnID: `1.2.3.4.${String(2000 + index)}`,
                critical: false,
                extnValue: new asn1js.Null().toBER(false),
            })
        );
    }
    request.tbsRequest.requestExtensions = extensions;
    request.tbsRequest.tbsView = new Uint8Array(0);
    return new Uint8Array(request.toSchema(true).toBER(false));
}

// --- Fix round 2 byte-surgery helpers (malformed-but-parseable profile probes) ---

/** Raw inner BasicOCSPResponse DER inside an outer OCSPResponse. */
function innerBasicDer(responseBytes: Uint8Array): Uint8Array {
    const outer = asn1js.fromBER(toArrayBuffer(responseBytes.slice()));
    if (outer.offset === -1) throw new Error("response is not DER");
    const response = new pkijs.OCSPResponse({ schema: outer.result });
    const inner = response.responseBytes?.response.valueBlock.valueHexView;
    if (!inner) throw new Error("response has no responseBytes");
    return new Uint8Array(inner);
}

function parseBasicSequence(innerDer: Uint8Array): asn1js.Sequence {
    const parsed = asn1js.fromBER(toArrayBuffer(innerDer.slice()));
    if (parsed.offset === -1) throw new Error("BasicOCSPResponse is not DER");
    if (!(parsed.result instanceof asn1js.Sequence)) {
        throw new Error("BasicOCSPResponse is not a SEQUENCE");
    }
    return parsed.result;
}

/** Re-wraps mutated inner BasicOCSPResponse DER in the outer OCSPResponse framing. */
function rewrapBasicResponse(responseBytes: Uint8Array, newInnerDer: Uint8Array): Uint8Array {
    const outer = asn1js.fromBER(toArrayBuffer(responseBytes.slice()));
    if (outer.offset === -1) throw new Error("response is not DER");
    const response = new pkijs.OCSPResponse({ schema: outer.result });
    response.responseBytes = new pkijs.ResponseBytes({
        responseType: "1.3.6.1.5.5.7.48.1.1",
        response: new asn1js.OctetString({ valueHex: toArrayBuffer(newInnerDer) }),
    });
    return new Uint8Array(response.toSchema().toBER(false));
}

/**
 * Relabels the unsigned outer signatureAlgorithm, preserving TBS and
 * signature bytes exactly (algorithm-confusion probe).
 */
function responseWithSigAlg(
    responseBytes: Uint8Array,
    algorithmId: string,
    params?: asn1js.BaseBlock
): Uint8Array {
    const basic = parseBasicSequence(innerBasicDer(responseBytes));
    const children = basic.valueBlock.value;
    if (children.length < 3) throw new Error("BasicOCSPResponse is truncated");
    const algorithm = new pkijs.AlgorithmIdentifier({ algorithmId });
    if (params !== undefined) algorithm.algorithmParams = params;
    children[1] = algorithm.toSchema();
    return rewrapBasicResponse(responseBytes, new Uint8Array(basic.toBER(false)));
}

/**
 * Appends a trailing NULL to the response TBS and re-signs over the
 * mutated bytes with an RSA key (fresh signature, ignored TBS field).
 */
async function responseWithTrailingNullTbs(
    responseBytes: Uint8Array,
    signerPrivateKey: CryptoKey
): Promise<Uint8Array> {
    const basic = parseBasicSequence(innerBasicDer(responseBytes));
    const children = basic.valueBlock.value;
    const tbs = children[0];
    if (!(tbs instanceof asn1js.Sequence)) throw new Error("response TBS is not a SEQUENCE");
    tbs.valueBlock.value.push(new asn1js.Null());
    const tbsBytes = new Uint8Array(tbs.toBER(false));
    const signature = await globalThis.crypto.subtle.sign(
        { name: "RSASSA-PKCS1-v1_5" },
        signerPrivateKey,
        toArrayBuffer(tbsBytes)
    );
    children[2] = new asn1js.BitString({ valueHex: signature });
    return rewrapBasicResponse(responseBytes, new Uint8Array(basic.toBER(false)));
}

function parseRequestSequence(requestBytes: Uint8Array): asn1js.Sequence {
    const parsed = asn1js.fromBER(toArrayBuffer(requestBytes.slice()));
    if (parsed.offset === -1) throw new Error("request is not DER");
    if (!(parsed.result instanceof asn1js.Sequence)) throw new Error("request is not a SEQUENCE");
    return parsed.result;
}

function requestTbs(request: asn1js.Sequence): asn1js.Sequence {
    const tbs = request.valueBlock.value[0];
    if (!(tbs instanceof asn1js.Sequence)) throw new Error("request TBS is not a SEQUENCE");
    return tbs;
}

/** Appends a trailing NULL to the request TBS (requests are unsigned: no resign needed). */
function requestWithTrailingNullTbs(requestBytes: Uint8Array): Uint8Array {
    const request = parseRequestSequence(requestBytes);
    requestTbs(request).valueBlock.value.push(new asn1js.Null());
    return new Uint8Array(request.toBER(false));
}

/** Appends a second [2] requestExtensions field carrying a different nonce. */
function requestWithDuplicateExtensionsField(
    requestBytes: Uint8Array,
    secondNonce: Uint8Array
): Uint8Array {
    const request = parseRequestSequence(requestBytes);
    const secondField = new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 2 },
        value: [new asn1js.Sequence({ value: [nonceExtension(secondNonce).toSchema()] })],
    });
    requestTbs(request).valueBlock.value.push(secondField);
    return new Uint8Array(request.toBER(false));
}

/** Sets the TBSRequest version explicitly (unsigned profile: re-encode from fields). */
function requestWithVersion(requestBytes: Uint8Array, version: number): Uint8Array {
    const parsed = asn1js.fromBER(toArrayBuffer(requestBytes.slice()));
    if (parsed.offset === -1) throw new Error("request is not DER");
    const request = new pkijs.OCSPRequest({ schema: parsed.result });
    request.tbsRequest.version = version;
    request.tbsRequest.tbsView = new Uint8Array(0);
    return new Uint8Array(request.toSchema(true).toBER(false));
}

/**
 * Decodes one certificate's DER and returns the parsed tree plus its TBS
 * (TBSCertificate is the first member of Certificate).
 */
function parseCertificateTree(cert: pkijs.Certificate): {
    tree: asn1js.Sequence;
    tbs: asn1js.Sequence;
} {
    const parsed = asn1js.fromBER(toArrayBuffer(new Uint8Array(cert.toSchema().toBER(false))));
    if (parsed.offset === -1) throw new Error("certificate is not DER");
    if (!(parsed.result instanceof asn1js.Sequence)) {
        throw new Error("certificate is not a SEQUENCE");
    }
    const tbs = parsed.result.valueBlock.value[0];
    if (!(tbs instanceof asn1js.Sequence)) throw new Error("certificate TBS is not a SEQUENCE");
    return { tree: parsed.result, tbs };
}

/**
 * Mutates a delegate TBS in place, re-signs it with the CA key, and
 * returns the re-parsed certificate: the malformation under test carries
 * a genuine CA signature, so only strict grammar (never signature
 * failure) may decide the verdict.
 */
async function mutateDelegateCertificate(
    base: pkijs.Certificate,
    issuerPrivateKey: CryptoKey,
    mutateTbs: (tbs: asn1js.Sequence) => void
): Promise<pkijs.Certificate> {
    const { tree, tbs } = parseCertificateTree(base);
    mutateTbs(tbs);
    const tbsBytes = new Uint8Array(tbs.toBER(false));
    const signature = await globalThis.crypto.subtle.sign(
        { name: "RSASSA-PKCS1-v1_5" },
        issuerPrivateKey,
        toArrayBuffer(tbsBytes)
    );
    const members = tree.valueBlock.value;
    if (members.length !== 3) throw new Error("mutated certificate lost its framing");
    members[2] = new asn1js.BitString({ valueHex: signature });
    const parsed = asn1js.fromBER(toArrayBuffer(new Uint8Array(tree.toBER(false))));
    if (parsed.offset === -1) throw new Error("mutated certificate is not DER");
    return new pkijs.Certificate({ schema: parsed.result });
}

/**
 * Reads one TBS member of a v3 delegate by fixed index (explicit [0]
 * version first: 0 version, 1 serial, 2 signature, 3 issuer, 4 validity,
 * 5 subject, 6 subjectPublicKeyInfo, 7 [3] extensions). Fails loudly when
 * the fixture TBS no longer has that shape.
 */
function v3DelegateTbsMember(tbs: asn1js.Sequence, index: number, what: string): asn1js.BaseBlock {
    const first = tbs.valueBlock.value[0];
    if (
        !(first instanceof asn1js.Constructed) ||
        first.idBlock.tagClass !== 3 ||
        first.idBlock.tagNumber !== 0
    ) {
        throw new Error("delegate TBS has no explicit version wrapper");
    }
    const member = tbs.valueBlock.value[index];
    if (member === undefined) throw new Error(`delegate TBS has no member ${what}`);
    return member;
}

/** Finds the [3] extensions wrapper of a delegate TBS (the first when duplicated). */
function delegateExtensionsWrapper(tbs: asn1js.Sequence): asn1js.Constructed {
    const wrapper = tbs.valueBlock.value.find(
        (child) => child.idBlock.tagClass === 3 && child.idBlock.tagNumber === 3
    );
    if (!(wrapper instanceof asn1js.Constructed)) {
        throw new Error("delegate TBS has no extensions wrapper");
    }
    return wrapper;
}

/** Pushes an extra NULL into the first attribute of a Name (subject or issuer). */
function pushNameAttributeNull(name: unknown, what: string): void {
    if (!(name instanceof asn1js.Sequence)) throw new Error(`${what} is not a SEQUENCE`);
    const rdn = name.valueBlock.value[0];
    if (!(rdn instanceof asn1js.Set)) throw new Error(`${what} has no RDN set`);
    const attribute = rdn.valueBlock.value[0];
    if (!(attribute instanceof asn1js.Sequence)) {
        throw new Error(`${what} has no attribute sequence`);
    }
    attribute.valueBlock.value.push(new asn1js.Null());
}

/** Builds a Name from RDN sets of { type OID, value } attributes. */
function nameFromSets(sets: { type: string; value: asn1js.BaseBlock }[][]): asn1js.Sequence {
    return new asn1js.Sequence({
        value: sets.map(
            (rdn) =>
                new asn1js.Set({
                    value: rdn.map(
                        ({ type, value }) =>
                            new asn1js.Sequence({
                                value: [new asn1js.ObjectIdentifier({ value: type }), value],
                            })
                    ),
                })
        ),
    });
}

/**
 * Pushes an extra NULL into the first attribute of the wire ResponderID
 * name and re-signs the response TBS with an RSA key (fresh signature,
 * ignored name subtree).
 */
async function responseWithResponderNameNull(
    responseBytes: Uint8Array,
    signerPrivateKey: CryptoKey
): Promise<Uint8Array> {
    const basic = parseBasicSequence(innerBasicDer(responseBytes));
    const children = basic.valueBlock.value;
    const tbs = children[0];
    if (!(tbs instanceof asn1js.Sequence)) throw new Error("response TBS is not a SEQUENCE");
    const responderId = tbs.valueBlock.value[0];
    if (
        !(responderId instanceof asn1js.Constructed) ||
        responderId.idBlock.tagClass !== 3 ||
        responderId.idBlock.tagNumber !== 1
    ) {
        throw new Error("response ResponderID is not byName");
    }
    pushNameAttributeNull(responderId.valueBlock.value[0], "ResponderID name");
    const tbsBytes = new Uint8Array(tbs.toBER(false));
    const signature = await globalThis.crypto.subtle.sign(
        { name: "RSASSA-PKCS1-v1_5" },
        signerPrivateKey,
        toArrayBuffer(tbsBytes)
    );
    children[2] = new asn1js.BitString({ valueHex: signature });
    return rewrapBasicResponse(responseBytes, new Uint8Array(basic.toBER(false)));
}

/**
 * Mutates the OUTER certificate signatureAlgorithm in place (TBS and
 * signature bytes untouched, no re-signing) and returns the re-parsed
 * certificate: an outer relabel keeps a genuine issuer signature over
 * byte-identical TBS, so only a consistency gate (never issuance
 * crypto) may decide the verdict.
 */
function relabelDelegateOuter(
    base: pkijs.Certificate,
    mutateOuter: (outer: asn1js.Sequence) => void
): pkijs.Certificate {
    const { tree } = parseCertificateTree(base);
    const members = tree.valueBlock.value;
    if (members.length !== 3) throw new Error("relabeled certificate lost its framing");
    const outer = members[1];
    if (!(outer instanceof asn1js.Sequence)) {
        throw new Error("outer signatureAlgorithm is not a SEQUENCE");
    }
    mutateOuter(outer);
    const parsed = asn1js.fromBER(toArrayBuffer(new Uint8Array(tree.toBER(false))));
    if (parsed.offset === -1) throw new Error("relabeled certificate is not DER");
    return new pkijs.Certificate({ schema: parsed.result });
}

/** Replaces the OID of an AlgorithmIdentifier SEQUENCE in place. */
function setAlgorithmOid(algorithm: asn1js.Sequence, oid: string): void {
    const id = algorithm.valueBlock.value[0];
    if (!(id instanceof asn1js.ObjectIdentifier)) {
        throw new Error("algorithm identifier has no OID");
    }
    algorithm.valueBlock.value[0] = new asn1js.ObjectIdentifier({ value: oid });
}

// --- Fix round 6 byte-surgery helpers (signature/SPKI framing probes) ---

/** Reads the BasicOCSPResponse signature BIT STRING (member 2). */
function responseSignatureBits(responseBytes: Uint8Array): asn1js.BitString {
    const basic = parseBasicSequence(innerBasicDer(responseBytes));
    const signature = basic.valueBlock.value[2];
    if (!(signature instanceof asn1js.BitString)) {
        throw new Error("response signature is not a BIT STRING");
    }
    return signature;
}

/**
 * Replaces the BasicOCSPResponse signature BIT STRING (member 2) with an
 * attacker-chosen encoding. Framing probes keep the genuine signature
 * bytes, so only strict BIT STRING grammar may decide the verdict.
 */
function responseWithSignatureBits(responseBytes: Uint8Array, bits: asn1js.BitString): Uint8Array {
    const basic = parseBasicSequence(innerBasicDer(responseBytes));
    const children = basic.valueBlock.value;
    if (!(children[2] instanceof asn1js.BitString)) {
        throw new Error("response signature is not a BIT STRING");
    }
    children[2] = bits;
    return rewrapBasicResponse(responseBytes, new Uint8Array(basic.toBER(false)));
}

/**
 * Replaces a certificate signatureValue (member 2) with an attacker-chosen
 * BIT STRING encoding (no re-signing: framing probes keep the genuine
 * issuer signature bytes).
 */
function certificateWithSignatureBits(
    base: pkijs.Certificate,
    bits: asn1js.BitString
): pkijs.Certificate {
    const { tree } = parseCertificateTree(base);
    const members = tree.valueBlock.value;
    if (members.length !== 3 || !(members[2] instanceof asn1js.BitString)) {
        throw new Error("certificate signatureValue is not a BIT STRING");
    }
    members[2] = bits;
    const parsed = asn1js.fromBER(toArrayBuffer(new Uint8Array(tree.toBER(false))));
    if (parsed.offset === -1) throw new Error("mutated certificate is not DER");
    return new pkijs.Certificate({ schema: parsed.result });
}

/** Re-encodes BIT STRING bytes with an attacker-chosen unused-bit count. */
function bitStringWithUnusedBits(source: asn1js.BitString, unusedBits: number): asn1js.BitString {
    return new asn1js.BitString({
        valueHex: source.valueBlock.valueHex.slice(0),
        unusedBits,
    });
}

/** Reads the subjectPublicKeyInfo (member 6) of a v3 delegate TBS. */
function delegateSpki(tbs: asn1js.Sequence): asn1js.Sequence {
    const spki = v3DelegateTbsMember(tbs, 6, "subjectPublicKeyInfo");
    if (!(spki instanceof asn1js.Sequence)) {
        throw new Error("subjectPublicKeyInfo is not a SEQUENCE");
    }
    return spki;
}

/** Reads the subjectPublicKey BIT STRING (member 1) of an SPKI SEQUENCE. */
function spkiSubjectPublicKey(spki: asn1js.Sequence): asn1js.BitString {
    const bits = spki.valueBlock.value[1];
    if (!(bits instanceof asn1js.BitString)) {
        throw new Error("subjectPublicKey is not a BIT STRING");
    }
    return bits;
}

/** Parses an RSA SPKI payload into its modulus/exponent INTEGERs. */
function rsaKeyIntegers(bits: asn1js.BitString): { n: asn1js.Integer; e: asn1js.Integer } {
    const parsed = asn1js.fromBER(bits.valueBlock.valueHex.slice(0));
    if (parsed.offset === -1 || !(parsed.result instanceof asn1js.Sequence)) {
        throw new Error("RSA public key payload is not a SEQUENCE");
    }
    const [n, e] = parsed.result.valueBlock.value;
    if (!(n instanceof asn1js.Integer) || !(e instanceof asn1js.Integer)) {
        throw new Error("RSA public key payload has no modulus/exponent");
    }
    return { n, e };
}

function concatBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
    const out = new Uint8Array(left.length + right.length);
    out.set(left, 0);
    out.set(right, left.length);
    return out;
}

describe("OCSP authentication (T06)", () => {
    let ca: TestCertificateAuthority;
    let leaf: TestLeaf;
    let otherLeaf: TestLeaf;
    let delegate: TestResponder;
    let wrongKeys: TestKeyPair;
    let rolloverOld: TestCertificateAuthority;
    let rolloverNew: TestCertificateAuthority;
    let rolloverLeaf: TestLeaf;

    beforeAll(async () => {
        ca = await createTestCA("T06 Test CA", { serial: 1001 });
        leaf = await createTestLeaf(ca, { serial: 2001, ocspUrl: OCSP_URL });
        // Same key as the leaf, different serial: CertID-distinct on purpose.
        otherLeaf = await createTestLeaf(ca, {
            commonName: "T06 Other Leaf",
            serial: 2002,
            keys: leaf.keys,
            ocspUrl: OCSP_URL,
        });
        delegate = await createDelegateResponder(ca, {});
        const wrongCA = await createTestCA("T06 Wrong CA", { serial: 9001 });
        wrongKeys = wrongCA.keys;
        // Same-subject rollover pair: the leaf is signed by the new key only.
        rolloverOld = await createTestCA("T06 Rollover CA", { serial: 1011 });
        rolloverNew = await createTestCA("T06 Rollover CA", { serial: 1012 });
        rolloverLeaf = await createTestLeaf(rolloverNew, {
            commonName: "T06 Rollover Leaf",
            serial: 2011,
            keys: leaf.keys,
            ocspUrl: OCSP_URL,
        });
    }, 60000);

    async function boundRequest(
        target: pkijs.Certificate = leaf.cert,
        issuerCert: pkijs.Certificate = ca.cert,
        includeNonce = true
    ): Promise<{ requestBytes: Uint8Array; nonce: Uint8Array | null }> {
        // Module absence must red before the R22 nonce assertions below can
        // mask it (the T04 masked-assertion precedent, disclosed).
        await expectValidator();
        const requestBytes = await createOCSPRequest(target, issuerCert, { includeNonce });
        const inspected = inspectOCSPRequest(requestBytes);
        expect(inspected.requestCount).toBe(1);
        expect(inspected.certId).not.toBeNull();
        if (includeNonce) {
            expect(inspected.nonces).toHaveLength(1);
            const nonce = inspected.nonces[0];
            expect(nonce?.length).toBe(32);
            return { requestBytes, nonce: nonce! };
        }
        expect(inspected.nonces).toHaveLength(0);
        return { requestBytes, nonce: null };
    }

    async function validateDirect(
        responseBytes: Uint8Array,
        options: {
            cert?: pkijs.Certificate;
            issuer?: pkijs.Certificate;
            requestBytes?: Uint8Array;
            checkDate?: Date;
            clockSkewMs?: number;
            maxAgeWithoutNextUpdateMs?: number;
        } = {}
    ) {
        const validator = await expectValidator();
        const requestBytes =
            options.requestBytes ?? (await boundRequest(options.cert, options.issuer)).requestBytes;
        return validator.validateOCSPEvidence(responseBytes, {
            cert: options.cert ?? leaf.cert,
            issuer: options.issuer ?? ca.cert,
            requestBytes,
            checkDate: options.checkDate ?? CHECK_DATE,
            clockSkewMs: options.clockSkewMs ?? CLOCK_SKEW_MS,
            maxAgeWithoutNextUpdateMs:
                options.maxAgeWithoutNextUpdateMs ?? MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
        });
    }

    describe("validateOCSPEvidence signatures and responder authorization", () => {
        it("accepts an issuer-signed GOOD response with no embedded responder certificate", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
                certs: [],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.source).toBe("OCSP");
            expect(result.errors).toEqual([]);
        });

        it("accepts an issuer-signed GOOD response identified by key hash with no embedded certificate", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                responderId: { form: "byKey" },
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
                certs: [],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts an issuer-signed REVOKED response", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "revoked",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                        revocationTime: new Date("2026-04-15T00:00:00Z"),
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("revoked");
            expect(result.errors).toEqual([]);
        });

        it("stays unknown when the responder reports unknown", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "unknown",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toContain("unknown");
        });

        it("accepts an authorized delegate identified by name", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: delegate.keys,
                responderCert: delegate.cert,
                responderId: { form: "byName" },
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts an authorized delegate identified by key hash", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: delegate.keys,
                responderCert: delegate.cert,
                responderId: { form: "byKey" },
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("rejects a corrupted response signature", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const signed = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(corruptResponseSignature(signed), { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/signature/i);
        });

        it("rejects a response signed with the wrong key", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: wrongKeys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/signature/i);
        });

        it("rejects a ResponderID that matches no known certificate", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                responderId: { form: "byName", name: distinguishedName("Nobody") },
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/ResponderID/i);
        });

        it("rejects a delegate whose key usage forbids signatures", async () => {
            const badKu = await createDelegateResponder(ca, {
                commonName: "T06 Bad KU Responder",
                serial: 3011,
                keyUsage: new Uint8Array([0x04]),
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: badKu.keys,
                responderCert: badKu.cert,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/key usage/i);
        });

        it("accepts a delegate with no key usage extension", async () => {
            const noKu = await createDelegateResponder(ca, {
                commonName: "T06 No KU Responder",
                serial: 3032,
                keyUsage: null,
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: noKu.keys,
                responderCert: noKu.cert,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts a delegate whose key usage spans multiple bytes", async () => {
            // Only the first octet's MSB (digitalSignature) decides;
            // trailing bits and bytes are ignored.
            const wideKu = await createDelegateResponder(ca, {
                commonName: "T06 Wide KU Responder",
                serial: 3033,
                keyUsage: new Uint8Array([0x80, 0x01]),
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: wideKu.keys,
                responderCert: wideKu.cert,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("rejects a delegate with the wrong extended key usage", async () => {
            const badEku = await createDelegateResponder(ca, {
                commonName: "T06 Bad EKU Responder",
                serial: 3012,
                eku: ["1.3.6.1.5.5.7.3.2"],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: badEku.keys,
                responderCert: badEku.cert,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/OCSPSigning/i);
        });

        it("rejects a delegate with no extended key usage at all", async () => {
            const noEku = await createDelegateResponder(ca, {
                commonName: "T06 No EKU Responder",
                serial: 3013,
                eku: null,
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: noEku.keys,
                responderCert: noEku.cert,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/OCSPSigning/i);
        });

        it("rejects a delegate with only anyExtendedKeyUsage", async () => {
            // Documented intentional incompatibility: anyEKU alone does
            // not satisfy the explicit id-kp-OCSPSigning requirement.
            const anyEku = await createDelegateResponder(ca, {
                commonName: "T06 Any EKU Responder",
                serial: 3031,
                eku: ["2.5.29.37.0"],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: anyEku.keys,
                responderCert: anyEku.cert,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/OCSPSigning/i);
        });

        it("rejects a delegate with duplicate extended key usage extensions", async () => {
            // Both copies list id-kp-OCSPSigning, so only the
            // exactly-one-EKU rule can reject this delegate.
            const base = await createDelegateResponder(ca, {
                commonName: "T06 Double EKU Responder",
                serial: 3034,
                eku: null,
            });
            const doubled = base.cert;
            doubled.extensions = [
                ...(doubled.extensions ?? []),
                extendedKeyUsageExtension(["1.3.6.1.5.5.7.3.9"]),
                extendedKeyUsageExtension(["1.3.6.1.5.5.7.3.9"]),
            ];
            await doubled.sign(ca.keys.privateKey, "SHA-256");
            const responderCert = roundTripCertificate(doubled);
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: base.keys,
                responderCert,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/OCSPSigning/i);
        });

        it("rejects a delegate outside its validity period", async () => {
            const expired = await createDelegateResponder(ca, {
                commonName: "T06 Expired Responder",
                serial: 3014,
                notBefore: new Date("2020-01-01T00:00:00Z"),
                notAfter: new Date("2021-01-01T00:00:00Z"),
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: expired.keys,
                responderCert: expired.cert,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/validity/i);
        });

        it("rejects a delegate the CA never issued", async () => {
            const foreignCA = await createTestCA("T06 Foreign CA", { serial: 9002 });
            const foreign = await createDelegateResponder(foreignCA, {
                commonName: "T06 Foreign Responder",
                serial: 3015,
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: foreign.keys,
                responderCert: foreign.cert,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/issued/i);
        });

        it("stays unknown for a delegate without id-pkix-ocsp-nocheck (unsupported revocation policy)", async () => {
            const checkable = await createDelegateResponder(ca, {
                commonName: "T06 Checkable Responder",
                serial: 3016,
                nocheck: false,
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: checkable.keys,
                responderCert: checkable.cert,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/nocheck|revocation policy/i);
        });
    });

    describe("validateOCSPEvidence request binding", () => {
        it("finds the matching response when it is not first", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: otherLeaf.cert,
                        issuer: ca.cert,
                        status: "revoked",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("stays unknown when no SingleResponse matches the request CertID", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: otherLeaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/CertID|match/i);
        });

        it("stays unknown when the response CertID uses a different hash algorithm", async () => {
            // The request CertID is SHA-1; a SHA-256 response CertID for
            // the same certificate must not match (no algorithm
            // confusion: pkijs CertID comparison covers the OIDs).
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
                certIdHash: "SHA-256",
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/CertID|match/i);
        });

        it("stays unknown when matching responses conflict", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "revoked",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/conflict/i);
        });

        it("rejects a CertID built for the same leaf under a different issuer", async () => {
            // Same-subject rollover: the request names the new key, the
            // response answers for the old key. CertID comparison must see
            // through the shared subject name to the different key hashes.
            const requestBytes = await createOCSPRequest(rolloverLeaf.cert, rolloverNew.cert);
            const inspected = inspectOCSPRequest(requestBytes);
            const nonce = inspected.nonces[0]!;
            const response = await createSignedOCSPResponse(rolloverOld.cert, {
                signerKeys: rolloverOld.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: rolloverLeaf.cert,
                        issuer: rolloverOld.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce,
            });
            const result = await validateDirect(response, {
                cert: rolloverLeaf.cert,
                issuer: rolloverNew.cert,
                requestBytes,
            });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/CertID|match/i);
        });

        it("rejects a request with more than one entry", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const multi = requestWithDuplicateEntries(requestBytes);
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes: multi });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/request/i);
        });

        it("rejects malformed request bytes", async () => {
            const { nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, {
                requestBytes: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
            });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/request/i);
        });
    });

    describe("validateOCSPEvidence nonce binding (R22)", () => {
        it("requires an exact echo of the 32-byte request nonce", async () => {
            const { requestBytes, nonce } = await boundRequest();
            expect(nonce?.length).toBe(32);
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
        });

        it("stays unknown when the response omits the requested nonce", async () => {
            const { requestBytes } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/nonce/i);
        });

        it("stays unknown when the echoed nonce differs", async () => {
            const { requestBytes } = await boundRequest();
            const wrong = new Uint8Array(32).fill(0xab);
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: wrong,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/nonce/i);
        });

        it("stays unknown when the response carries two nonces", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
                extraResponseExtensions: [nonceExtension(nonce!)],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/nonce/i);
        });

        it("stays unknown when the response nonce is constructed, not primitive", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const constructed = new asn1js.Constructed({
                idBlock: { tagClass: 1, tagNumber: 4 },
                value: [new asn1js.OctetString({ valueHex: toArrayBuffer(nonce!) })],
            });
            const badEcho = new pkijs.Extension({
                extnID: OCSP_NONCE_OID,
                critical: false,
                extnValue: constructed.toBER(false),
            });
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                extraResponseExtensions: [badEcho],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/malformed OCSP nonce/);
        });

        it("stays unknown when the response nonce is empty", async () => {
            const { requestBytes } = await boundRequest();
            const emptyEcho = new pkijs.Extension({
                extnID: OCSP_NONCE_OID,
                critical: false,
                extnValue: new asn1js.OctetString({ valueHex: new ArrayBuffer(0) }).toBER(false),
            });
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                extraResponseExtensions: [emptyEcho],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/empty OCSP nonce/);
        });

        it("stays unknown when the request carries two nonces", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const doubled = requestWithDuplicateNonce(requestBytes, nonce!);
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes: doubled });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/nonce/i);
        });

        it("omit mode: accepts a nonce-free exchange", async () => {
            const { requestBytes } = await boundRequest(leaf.cert, ca.cert, false);
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("omit mode: ignores a response nonce nobody asked for", async () => {
            const { requestBytes } = await boundRequest(leaf.cert, ca.cert, false);
            const unsolicited = new Uint8Array(32).fill(0x5a);
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: unsolicited,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });
    });

    describe("validateOCSPEvidence time policy", () => {
        async function timedResponse(options: {
            thisUpdate: Date;
            producedAt?: Date;
            nextUpdate?: Date | null;
        }): Promise<{ requestBytes: Uint8Array; response: Uint8Array }> {
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: options.producedAt ?? PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: options.thisUpdate,
                        ...(options.nextUpdate === undefined || options.nextUpdate === null
                            ? {}
                            : { nextUpdate: options.nextUpdate }),
                    },
                ],
                nonceEcho: nonce!,
            });
            return { requestBytes, response };
        }

        it("accepts thisUpdate and producedAt exactly at checkDate plus skew", async () => {
            const edge = new Date(CHECK_DATE.getTime() + CLOCK_SKEW_MS);
            const { requestBytes, response } = await timedResponse({
                thisUpdate: edge,
                producedAt: edge,
                nextUpdate: new Date(CHECK_DATE.getTime() + 3600_000),
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
        });

        it("rejects a thisUpdate past checkDate plus skew", async () => {
            const future = new Date(CHECK_DATE.getTime() + CLOCK_SKEW_MS + 1);
            const { requestBytes, response } = await timedResponse({
                thisUpdate: future,
                nextUpdate: new Date(future.getTime() + 3600_000),
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/thisUpdate/i);
        });

        it("rejects an inverted freshness window (nextUpdate before thisUpdate)", async () => {
            // P4b-shaped: the staleness gate alone would pass (checkDate
            // minus skew is 11:55, nextUpdate is 11:56), so only the
            // nextUpdate >= thisUpdate relation rejects this response.
            const { requestBytes, response } = await timedResponse({
                thisUpdate: new Date("2026-05-01T11:58:00Z"),
                producedAt: new Date("2026-05-01T11:57:00Z"),
                nextUpdate: new Date("2026-05-01T11:56:00Z"),
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/nextUpdate is before thisUpdate/);
        });

        it("accepts thisUpdate exactly at producedAt plus skew", async () => {
            const { requestBytes, response } = await timedResponse({
                thisUpdate: new Date("2026-05-01T11:05:00.000Z"),
                producedAt: new Date("2026-05-01T11:00:00.000Z"),
                nextUpdate: new Date("2026-05-01T12:00:00Z"),
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
        });

        it("rejects thisUpdate one millisecond past producedAt plus skew", async () => {
            const { requestBytes, response } = await timedResponse({
                thisUpdate: new Date("2026-05-01T11:05:00.001Z"),
                producedAt: new Date("2026-05-01T11:00:00.000Z"),
                nextUpdate: new Date("2026-05-01T12:00:00Z"),
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/thisUpdate is after producedAt/);
        });

        it("requires the delegate to be valid at producedAt as well as the check date", async () => {
            // P6-shaped: the delegate is live at the check date (12:00)
            // but its validity starts after producedAt (notBefore minus
            // skew is 11:00:00.000; the early producedAt is 1 ms before
            // that edge). Certificate validity is UTCTime (whole
            // seconds), so the millisecond lives in producedAt.
            const late = await createDelegateResponder(ca, {
                commonName: "T06 Late Responder",
                serial: 3023,
                notBefore: new Date("2026-05-01T11:05:00Z"),
            });
            const { requestBytes, nonce } = await boundRequest();
            async function validateAt(producedAt: Date) {
                const response = await createSignedOCSPResponse(ca.cert, {
                    signerKeys: late.keys,
                    responderCert: late.cert,
                    producedAt,
                    responses: [
                        {
                            cert: leaf.cert,
                            issuer: ca.cert,
                            status: "good",
                            thisUpdate: THIS_UPDATE,
                            nextUpdate: NEXT_UPDATE,
                        },
                    ],
                    nonceEcho: nonce!,
                });
                return validateDirect(response, { requestBytes });
            }
            const edge = await validateAt(new Date("2026-05-01T11:00:00.000Z"));
            expect(edge.status).toBe("good");
            const early = await validateAt(new Date("2026-05-01T10:59:59.999Z"));
            expect(early.status).toBe("unknown");
            expect(early.errors.join("\n")).toMatch(/validity period at producedAt/);
        });

        it("rejects a producedAt past checkDate plus skew", async () => {
            const future = new Date(CHECK_DATE.getTime() + CLOCK_SKEW_MS + 1);
            const { requestBytes, response } = await timedResponse({
                thisUpdate: THIS_UPDATE,
                producedAt: future,
                nextUpdate: NEXT_UPDATE,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/producedAt/i);
        });

        it("accepts a nextUpdate exactly at checkDate minus skew", async () => {
            const edge = new Date(CHECK_DATE.getTime() - CLOCK_SKEW_MS);
            const { requestBytes, response } = await timedResponse({
                thisUpdate: new Date(edge.getTime() - 3600_000),
                nextUpdate: edge,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
        });

        it("rejects a response whose nextUpdate has passed", async () => {
            const stale = new Date(CHECK_DATE.getTime() - CLOCK_SKEW_MS - 1);
            const { requestBytes, response } = await timedResponse({
                thisUpdate: new Date(stale.getTime() - 3600_000),
                nextUpdate: stale,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/stale/i);
        });

        it("bounds a missing nextUpdate by thisUpdate plus maxAge", async () => {
            const edge = new Date(
                CHECK_DATE.getTime() - CLOCK_SKEW_MS - MAX_AGE_WITHOUT_NEXT_UPDATE_MS
            );
            const fresh = await timedResponse({ thisUpdate: edge, nextUpdate: null });
            const freshResult = await validateDirect(fresh.response, {
                requestBytes: fresh.requestBytes,
            });
            expect(freshResult.status).toBe("good");

            const aged = await timedResponse({
                thisUpdate: new Date(edge.getTime() - 1),
                nextUpdate: null,
            });
            const agedResult = await validateDirect(aged.response, {
                requestBytes: aged.requestBytes,
            });
            expect(agedResult.status).toBe("unknown");
            expect(agedResult.errors.join("\n")).toMatch(/stale|age/i);
        });

        it("applies clock skew to the delegate validity period", async () => {
            // Certificate validity is UTCTime (whole seconds), so the
            // millisecond lives in the check date, which is never
            // serialized: notAfter sits exactly at checkDate minus skew
            // and the same bytes are evaluated at both check dates.
            const edged = await createDelegateResponder(ca, {
                commonName: "T06 Skew Edged Responder",
                serial: 3021,
                notAfter: new Date(CHECK_DATE.getTime() - CLOCK_SKEW_MS),
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: edged.keys,
                responderCert: edged.cert,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            expect((await validateDirect(response, { requestBytes })).status).toBe("good");

            const deadResult = await validateDirect(response, {
                requestBytes,
                checkDate: new Date(CHECK_DATE.getTime() + 1),
            });
            expect(deadResult.status).toBe("unknown");
            expect(deadResult.errors.join("\n")).toMatch(/validity/i);
        });

        it("pins the delegate notBefore skew edge in both directions", async () => {
            // P3 direction at 1 ms, shared with F7 (no duplicate test):
            // notBefore sits exactly at checkDate plus skew and the
            // millisecond lives in the check date (certificate validity
            // is UTCTime, whole seconds; the check date is never
            // serialized). The passing edge also pins the F3 producedAt
            // window: producedAt is exactly at notBefore minus skew.
            const edged = await createDelegateResponder(ca, {
                commonName: "T06 NotBefore Edged Responder",
                serial: 3024,
                notBefore: new Date(CHECK_DATE.getTime() + CLOCK_SKEW_MS),
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: edged.keys,
                responderCert: edged.cert,
                producedAt: CHECK_DATE,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: CHECK_DATE,
                        nextUpdate: new Date(CHECK_DATE.getTime() + 60_000),
                    },
                ],
                nonceEcho: nonce!,
            });
            expect((await validateDirect(response, { requestBytes })).status).toBe("good");

            const earlyResult = await validateDirect(response, {
                requestBytes,
                checkDate: new Date(CHECK_DATE.getTime() - 1),
            });
            expect(earlyResult.status).toBe("unknown");
            expect(earlyResult.errors.join("\n")).toMatch(/validity/i);
        });
    });

    describe("validateOCSPEvidence structure, bounds, and arguments", () => {
        it("stays unknown for malformed response bytes", async () => {
            const { requestBytes } = await boundRequest();
            const result = await validateDirect(new Uint8Array([0xde, 0xad, 0xbe, 0xef]), {
                requestBytes,
            });
            expect(result.status).toBe("unknown");
            expect(result.source).toBe("OCSP");
            expect(result.errors.length).toBeGreaterThan(0);
        });

        it("stays unknown for a non-successful OCSP status", async () => {
            const { requestBytes } = await boundRequest();
            // Bare OCSPResponse with TRY_LATER and no responseBytes.
            const tryLater = new Uint8Array([0x30, 0x03, 0x0a, 0x01, 0x03]);
            const result = await validateDirect(tryLater, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.length).toBeGreaterThan(0);
        });

        it("caps the SingleResponse scan instead of walking an unbounded array", async () => {
            const validator = await expectValidator();
            const { requestBytes, nonce } = await boundRequest();
            const filler = [];
            for (let index = 0; index <= validator.MAX_OCSP_SINGLE_RESPONSES; index++) {
                filler.push({
                    cert: otherLeaf.cert,
                    issuer: ca.cert,
                    status: "good" as const,
                    thisUpdate: THIS_UPDATE,
                    nextUpdate: NEXT_UPDATE,
                });
            }
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: filler,
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/limit|bound|too many/i);
        });

        it("caps the embedded certificate scan", async () => {
            const validator = await expectValidator();
            const { requestBytes, nonce } = await boundRequest();
            const certs: pkijs.Certificate[] = [];
            for (let index = 0; index <= validator.MAX_OCSP_EMBEDDED_CERTS; index++) {
                certs.push(delegate.cert);
            }
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: delegate.keys,
                responderCert: delegate.cert,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
                certs,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/limit|bound|too many/i);
        });

        it("caps the response extension walk", async () => {
            const validator = await expectValidator();
            const { requestBytes, nonce } = await boundRequest();
            const padding: pkijs.Extension[] = [];
            for (let index = 0; index <= validator.MAX_OCSP_EXTENSION_SCAN; index++) {
                padding.push(
                    new pkijs.Extension({
                        extnID: `1.2.3.4.${String(1000 + index)}`,
                        critical: false,
                        extnValue: new Uint8Array([0x05, 0x00]).buffer as ArrayBuffer,
                    })
                );
            }
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
                extraResponseExtensions: padding,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/limit|bound|too many/i);
        });

        it("caps the request extension walk", async () => {
            const validator = await expectValidator();
            const { requestBytes, nonce } = await boundRequest();
            // One nonce extension plus padding to exactly one past the
            // cap: the diagnostic must name both counts.
            const over = requestWithManyExtensions(requestBytes, validator.MAX_OCSP_EXTENSION_SCAN);
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes: over });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(
                /carries 65 extensions, above the supported limit of 64/
            );
        });

        it("rejects invalid arguments instead of evaluating", async () => {
            const validator = await expectValidator();
            const { requestBytes } = await boundRequest();
            const response = new Uint8Array([0x30, 0x00]);
            await expect(
                validator.validateOCSPEvidence(response, {
                    cert: leaf.cert,
                    issuer: ca.cert,
                    requestBytes,
                    checkDate: new Date(Number.NaN),
                    clockSkewMs: CLOCK_SKEW_MS,
                    maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
                })
            ).rejects.toMatchObject({ code: TimestampErrorCode.INVALID_ARGUMENT });
            await expect(
                validator.validateOCSPEvidence(response, {
                    cert: leaf.cert,
                    issuer: ca.cert,
                    requestBytes,
                    checkDate: CHECK_DATE,
                    clockSkewMs: -1,
                    maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
                })
            ).rejects.toMatchObject({ code: TimestampErrorCode.INVALID_ARGUMENT });
        });
    });

    function echoResponder(options: {
        cert?: pkijs.Certificate;
        issuer?: pkijs.Certificate;
        signerKeys: TestKeyPair;
        responderCert?: pkijs.Certificate;
        status?: "good" | "revoked" | "unknown";
        producedAt?: Date;
        thisUpdate?: Date;
        nextUpdate?: Date | null;
        nonceMode?: "echo" | "omit" | "wrong";
        extraResponseExtensions?: pkijs.Extension[];
    }): RevocationDataFetcher & {
        ocspRequests: Uint8Array[];
        ocspCalls: number;
        crlCalls: number;
    } {
        const fetcher: RevocationDataFetcher & {
            ocspRequests: Uint8Array[];
            ocspCalls: number;
            crlCalls: number;
        } = {
            ocspRequests: [],
            ocspCalls: 0,
            crlCalls: 0,
            fetchOCSP: async (_url: string, request: Uint8Array) => {
                fetcher.ocspCalls += 1;
                fetcher.ocspRequests.push(request);
                const inspected = inspectOCSPRequest(request);
                const requestNonce = inspected.nonces[0] ?? null;
                const nonceMode = options.nonceMode ?? "echo";
                const nonceEcho =
                    nonceMode === "echo"
                        ? (requestNonce ?? undefined)
                        : nonceMode === "wrong"
                          ? new Uint8Array(32).fill(0x77)
                          : undefined;
                return createSignedOCSPResponse(options.issuer ?? ca.cert, {
                    signerKeys: options.signerKeys,
                    ...(options.responderCert === undefined
                        ? {}
                        : { responderCert: options.responderCert }),
                    producedAt: options.producedAt ?? PRODUCED_AT,
                    responses: [
                        {
                            cert: options.cert ?? leaf.cert,
                            issuer: options.issuer ?? ca.cert,
                            status: options.status ?? "good",
                            thisUpdate: options.thisUpdate ?? THIS_UPDATE,
                            ...(options.nextUpdate === undefined || options.nextUpdate === null
                                ? options.nextUpdate === null
                                    ? {}
                                    : { nextUpdate: NEXT_UPDATE }
                                : { nextUpdate: options.nextUpdate }),
                        },
                    ],
                    ...(nonceEcho === undefined ? {} : { nonceEcho }),
                    ...(options.extraResponseExtensions === undefined
                        ? {}
                        : { extraResponseExtensions: options.extraResponseExtensions }),
                });
            },
            fetchCRL: (_url: string) => {
                fetcher.crlCalls += 1;
                return Promise.reject(new Error("no CRL response"));
            },
        };
        return fetcher;
    }

    describe("ValidationSession OCSP evidence routing", () => {
        it("reports good for an authenticated OCSP response", async () => {
            const fetcher = echoResponder({ signerKeys: ca.keys });
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
            });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("good");
            expect(result?.isValid).toBe(true);
            expect(result?.sources).toEqual(["OCSP"]);
            expect(result?.ocspResponses).toHaveLength(1);
            expect(result?.errors).toEqual([]);
            expect(fetcher.ocspCalls).toBe(1);
            // The default request carries a 32-byte nonce.
            expect(inspectOCSPRequest(fetcher.ocspRequests[0]!).nonces).toHaveLength(1);
        });

        it("reports revoked for an authenticated REVOKED response", async () => {
            const fetcher = echoResponder({ signerKeys: ca.keys, status: "revoked" });
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
            });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("revoked");
            expect(result?.isValid).toBe(false);
            expect(result?.sources).toEqual(["OCSP"]);
            expect(result?.ocspResponses).toHaveLength(1);
        });

        it("keeps unknown, bytes, and diagnostics for a wrongly signed response", async () => {
            const fetcher = echoResponder({ signerKeys: wrongKeys });
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
            });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(result?.sources).toEqual(["OCSP"]);
            expect(result?.ocspResponses).toHaveLength(1);
            expect(result?.errors.join("\n")).toMatch(/signature/i);
            // Candidate material survives strict-unknown for LTV embedding.
            expect(session.exportLTVData().ocspResponses).toHaveLength(1);
        });

        it("skips CRL once OCSP is decisive", async () => {
            const both = await createTestLeaf(ca, {
                commonName: "T06 Both Endpoints",
                serial: 2003,
                keys: leaf.keys,
                ocspUrl: OCSP_URL,
                crlUrls: [CRL_URL],
            });
            const fetcher = echoResponder({ signerKeys: ca.keys, cert: both.cert });
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
            });
            session.queueCertificate(both.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("good");
            expect(fetcher.ocspCalls).toBe(1);
            expect(fetcher.crlCalls).toBe(0);
        });

        it("falls back to CRL when OCSP stays unknown", async () => {
            const both = await createTestLeaf(ca, {
                commonName: "T06 Fallback Leaf",
                serial: 2004,
                keys: leaf.keys,
                ocspUrl: OCSP_URL,
                crlUrls: [CRL_URL],
            });
            const fetcher = echoResponder({
                signerKeys: wrongKeys,
                cert: both.cert,
            });
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
            });
            session.queueCertificate(both.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(fetcher.ocspCalls).toBe(1);
            expect(fetcher.crlCalls).toBe(1);
        });

        it("binds the request CertID to the verified rollover issuer", async () => {
            // queueChain stores both same-subject CAs; only the new key
            // verifies the leaf, so the request and the verdict follow it.
            const fetcher = echoResponder({
                cert: rolloverLeaf.cert,
                issuer: rolloverNew.cert,
                signerKeys: rolloverNew.keys,
            });
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
            });
            session.queueChain([rolloverLeaf.cert, rolloverOld.cert, rolloverNew.cert]);

            const results = await session.validateAll();
            const leafResult = session.getResultForCert(rolloverLeaf.cert);
            expect(leafResult?.revocationStatus).toBe("good");
            expect(results).toHaveLength(3);
            expect(fetcher.ocspCalls).toBe(1);

            const sent = inspectOCSPRequest(fetcher.ocspRequests[0]!);
            const expected = inspectOCSPRequest(
                await createOCSPRequest(rolloverLeaf.cert, rolloverNew.cert, {
                    includeNonce: false,
                })
            );
            expect(sent.certId?.isEqual(expected.certId!)).toBe(true);
            const rejected = inspectOCSPRequest(
                await createOCSPRequest(rolloverLeaf.cert, rolloverOld.cert, {
                    includeNonce: false,
                })
            );
            expect(sent.certId?.isEqual(rejected.certId!)).toBe(false);
        });

        it("validates through a separately parsed issuer twin", async () => {
            // Mixed representations must not regress request binding (T05
            // P8): the issuer arrives as fresh DER bytes, the verdict
            // still lands.
            const issuerDer = new Uint8Array(ca.cert.toSchema(true).toBER(false));
            const asn1 = asn1js.fromBER(toArrayBuffer(issuerDer.slice()));
            if (asn1.offset === -1) throw new Error("issuer DER did not parse");
            const twin = new pkijs.Certificate({ schema: asn1.result });
            expect(twin).not.toBe(ca.cert);

            const fetcher = echoResponder({ signerKeys: ca.keys });
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
            });
            session.queueChain([leaf.cert, twin]);

            const results = await session.validateAll();
            expect(results).toHaveLength(2);
            expect(session.getResultForCert(leaf.cert)?.revocationStatus).toBe("good");
        });

        it("explains a certificate with no revocation endpoints (T04 F3)", async () => {
            const bare = await createTestLeaf(ca, {
                commonName: "T06 Bare Leaf",
                serial: 2005,
                keys: leaf.keys,
            });
            const fetcher = echoResponder({ signerKeys: ca.keys });
            const session = new ValidationSession({ fetcher, checkDate: CHECK_DATE });
            session.queueCertificate(bare.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.sources).toEqual([]);
            expect(fetcher.ocspCalls).toBe(0);
            expect(fetcher.crlCalls).toBe(0);
            expect(result?.errors).toHaveLength(1);
            expect(result?.errors.join("\n")).toMatch(/no revocation endpoints/i);
        });

        it("supports explicit nonce omit mode end to end", async () => {
            const fetcher = echoResponder({ signerKeys: ca.keys, nonceMode: "omit" });
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
                includeOCSPNonce: false,
            });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("good");
            const sent = inspectOCSPRequest(fetcher.ocspRequests[0]!);
            expect(sent.nonces).toHaveLength(0);
        });

        it("ignores an unsolicited echo in session omit mode", async () => {
            const fetcher = echoResponder({ signerKeys: ca.keys, nonceMode: "wrong" });
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
                includeOCSPNonce: false,
            });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("good");
        });

        it("applies the nonce profile to fetched responses", async () => {
            const fetcher = echoResponder({ signerKeys: ca.keys, nonceMode: "wrong" });
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
            });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.errors.join("\n")).toMatch(/nonce/i);
            expect(fetcher.ocspCalls).toBe(1);
        });

        it("applies the nonce profile to cached responses without refetching", async () => {
            // Structurally valid and correctly signed, but the echo cannot
            // match the fresh random request nonce, so it stays unknown.
            const cached = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: new Uint8Array(32).fill(0x41),
            });
            const poisoned: ValidationCache = {
                getOCSP: () => cached.slice(),
                setOCSP: () => {},
                getCRL: () => null,
                setCRL: () => {},
                clear: () => {},
            };
            const fetcher = recordingFetcher({});
            const session = new ValidationSession({
                fetcher,
                cache: poisoned,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
            });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.errors.join("\n")).toMatch(/nonce/i);
            expect(fetcher.ocspCalls).toBe(0);
        });

        it("misses the cache for consecutive real requests (true random nonces)", async () => {
            // T05 deferred this until R22 serialized the nonce: two real
            // requests must now differ and miss each other.
            const first = await createOCSPRequest(leaf.cert, ca.cert);
            const second = await createOCSPRequest(leaf.cert, ca.cert);
            expect(first).not.toEqual(second);
            expect(inspectOCSPRequest(first).nonces[0]?.length).toBe(32);
            expect(inspectOCSPRequest(second).nonces[0]?.length).toBe(32);

            const cache = new InMemoryValidationCache();
            const response = new Uint8Array([0x30, 0x00]);
            cache.setOCSP(OCSP_URL, first, response);
            expect(cache.getOCSP(OCSP_URL, second)).toBeNull();
            expect(cache.getOCSP(OCSP_URL, first.slice())).toEqual(response);
        });

        it("rejects invalid OCSP policy options", () => {
            const fetcher = new MockFetcher();
            expect(
                () =>
                    new ValidationSession({
                        fetcher,
                        clockSkewMs: -1,
                    })
            ).toThrow(expect.objectContaining({ code: TimestampErrorCode.INVALID_ARGUMENT }));
            expect(
                () =>
                    new ValidationSession({
                        fetcher,
                        maxAgeWithoutNextUpdateMs: Number.NaN,
                    })
            ).toThrow(expect.objectContaining({ code: TimestampErrorCode.INVALID_ARGUMENT }));
            expect(
                () =>
                    new ValidationSession({
                        fetcher,
                        checkDate: new Date(Number.NaN),
                    })
            ).toThrow(expect.objectContaining({ code: TimestampErrorCode.INVALID_ARGUMENT }));
        });

        it("evaluates freshness at the session checkDate", async () => {
            // nextUpdate sits between the two check dates: the same bytes
            // are fresh for the early session and stale for the late one.
            const fetcherEarly = echoResponder({ signerKeys: ca.keys });
            const early = new ValidationSession({
                fetcher: fetcherEarly,
                checkDate: new Date("2026-05-01T12:00:00Z"),
                clockSkewMs: 0,
                maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
            });
            early.queueCertificate(leaf.cert, { issuer: ca.cert });
            const [earlyResult] = await early.validateAll();
            expect(earlyResult?.revocationStatus).toBe("good");

            const fetcherLate = echoResponder({ signerKeys: ca.keys });
            const late = new ValidationSession({
                fetcher: fetcherLate,
                checkDate: new Date("2026-06-01T12:00:00Z"),
                clockSkewMs: 0,
                maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
            });
            late.queueCertificate(leaf.cert, { issuer: ca.cert });
            const [lateResult] = await late.validateAll();
            expect(lateResult?.revocationStatus).toBe("unknown");
            expect(lateResult?.errors.join("\n")).toMatch(/stale/i);
        });

        it("evaluates missing nextUpdate against the session maxAge", async () => {
            const persistent = echoResponder({
                signerKeys: ca.keys,
                nextUpdate: null,
                thisUpdate: new Date("2026-04-29T12:00:00Z"),
                producedAt: new Date("2026-04-29T12:00:00Z"),
            });
            const strict = new ValidationSession({
                fetcher: persistent,
                checkDate: new Date("2026-05-01T12:00:00Z"),
                clockSkewMs: 0,
                maxAgeWithoutNextUpdateMs: 24 * 60 * 60 * 1000,
            });
            strict.queueCertificate(leaf.cert, { issuer: ca.cert });
            const [strictResult] = await strict.validateAll();
            expect(strictResult?.revocationStatus).toBe("unknown");

            const lenient = new ValidationSession({
                fetcher: echoResponder({
                    signerKeys: ca.keys,
                    nextUpdate: null,
                    thisUpdate: new Date("2026-04-29T12:00:00Z"),
                    producedAt: new Date("2026-04-29T12:00:00Z"),
                }),
                checkDate: new Date("2026-05-01T12:00:00Z"),
                clockSkewMs: 0,
                maxAgeWithoutNextUpdateMs: 7 * 24 * 60 * 60 * 1000,
            });
            lenient.queueCertificate(leaf.cert, { issuer: ca.cert });
            const [lenientResult] = await lenient.validateAll();
            expect(lenientResult?.revocationStatus).toBe("good");
        });

        it("keeps an unsigned certificate unknown even with an explicit issuer", async () => {
            // T05 concern, respected here: an explicit issuer that never
            // signed the target yields unknown plus an issuer diagnostic.
            const unsigned = new pkijs.Certificate();
            unsigned.version = 2;
            unsigned.serialNumber = new asn1js.Integer({ value: 2999 });
            unsigned.subject = distinguishedName("T06 Unsigned Leaf");
            unsigned.issuer = ca.cert.subject;
            const assertion = new pkijs.InfoAccess({
                accessDescriptions: [
                    new pkijs.AccessDescription({
                        accessMethod: "1.3.6.1.5.5.7.48.1",
                        accessLocation: new pkijs.GeneralName({ type: 6, value: OCSP_URL }),
                    }),
                ],
            });
            unsigned.extensions = [
                new pkijs.Extension({
                    extnID: "1.3.6.1.5.5.7.1.1",
                    critical: false,
                    extnValue: assertion.toSchema().toBER(false),
                }),
            ];
            const fetcher = recordingFetcher({});
            const session = new ValidationSession({ fetcher, checkDate: CHECK_DATE });
            session.queueCertificate(unsigned, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.errors.join("\n")).toMatch(/did not issue/i);
            expect(fetcher.ocspCalls).toBe(0);
        });
    });

    describe("session OCSP policy defaults", () => {
        it("documents a 5-minute skew and a 7-day missing-nextUpdate age", () => {
            expect(sessionModule.DEFAULT_OCSP_CLOCK_SKEW_MS).toBe(5 * 60 * 1000);
            expect(sessionModule.DEFAULT_OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_MS).toBe(
                7 * 24 * 60 * 60 * 1000
            );
        });

        it("applies the default maxAge to a nextUpdate-free response", async () => {
            const nowTruncated = Math.floor(Date.now() / 1000) * 1000;
            const sixDaysAgo = new Date(nowTruncated - 6 * 24 * 60 * 60 * 1000);
            const eightDaysAgo = new Date(nowTruncated - 8 * 24 * 60 * 60 * 1000);

            const freshSession = new ValidationSession({
                fetcher: echoResponder({
                    signerKeys: ca.keys,
                    nextUpdate: null,
                    thisUpdate: sixDaysAgo,
                    producedAt: sixDaysAgo,
                }),
            });
            freshSession.queueCertificate(leaf.cert, { issuer: ca.cert });
            const [freshResult] = await freshSession.validateAll();
            expect(freshResult?.revocationStatus).toBe("good");

            const agedSession = new ValidationSession({
                fetcher: echoResponder({
                    signerKeys: ca.keys,
                    nextUpdate: null,
                    thisUpdate: eightDaysAgo,
                    producedAt: eightDaysAgo,
                }),
            });
            agedSession.queueCertificate(leaf.cert, { issuer: ca.cert });
            const [agedResult] = await agedSession.validateAll();
            expect(agedResult?.revocationStatus).toBe("unknown");
            expect(agedResult?.errors.join("\n")).toMatch(/stale|age/i);
        });
    });

    describe("structural collection stays independent of strict validation (C06)", () => {
        it("still parses strict-unknown responses structurally", async () => {
            // A stale, wrongly echoed response is strict-unknown, yet the
            // structural collector API keeps reporting its GOOD status: the
            // two channels are deliberately distinct.
            const { requestBytes } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: wrongKeys,
                producedAt: new Date("2020-02-01T00:00:00Z"),
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: new Date("2020-02-01T00:00:00Z"),
                        nextUpdate: new Date("2020-02-02T00:00:00Z"),
                    },
                ],
                nonceEcho: new Uint8Array(32).fill(0x99),
            });
            const parsed = parseOCSPResponse(response);
            expect(parsed.certStatus).toBe(CertificateStatus.GOOD);

            const strict = await validateDirect(response, { requestBytes });
            expect(strict.status).toBe("unknown");
        });

        it("collects strict-unknown material through completeLTVData", async () => {
            // Ordinary signing never depends on nonce echo or strict
            // validation: a structurally GOOD candidate with a wrong signer
            // and a wrong nonce still joins the DSS with diagnostics.
            const candidate = await createSignedOCSPResponse(ca.cert, {
                signerKeys: wrongKeys,
                producedAt: new Date("2020-02-01T00:00:00Z"),
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: new Date("2020-02-01T00:00:00Z"),
                        nextUpdate: new Date("2020-02-02T00:00:00Z"),
                    },
                ],
                nonceEcho: new Uint8Array(32).fill(0x99),
            });
            const leafDer = new Uint8Array(leaf.cert.toSchema(true).toBER(false));
            const caDer = new Uint8Array(ca.cert.toSchema(true).toBER(false));
            const completed = await completeLTVData(
                { certificates: [leafDer, caDer], crls: [], ocspResponses: [] },
                {
                    fetchers: {
                        ocspFetcher: () => Promise.resolve(candidate),
                        crlFetcher: () => Promise.reject(new Error("no CRL")),
                        certFetcher: () => Promise.reject(new Error("no AIA")),
                    },
                }
            );
            expect(completed.data.ocspResponses).toHaveLength(1);
            expect(completed.data.ocspResponses[0]).toEqual(candidate);
        });

        it("collects the supported responder profile through both channels", async () => {
            // The same issuer-signed exchange validates strictly and
            // collects structurally: both channels serve the profile.
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const strict = await validateDirect(response, { requestBytes });
            expect(strict.status).toBe("good");

            const leafDer = new Uint8Array(leaf.cert.toSchema(true).toBER(false));
            const caDer = new Uint8Array(ca.cert.toSchema(true).toBER(false));
            const completed = await completeLTVData(
                { certificates: [leafDer, caDer], crls: [], ocspResponses: [] },
                {
                    fetchers: {
                        ocspFetcher: () => Promise.resolve(response),
                        crlFetcher: () => Promise.reject(new Error("no CRL")),
                        certFetcher: () => Promise.reject(new Error("no AIA")),
                    },
                }
            );
            expect(completed.data.ocspResponses).toHaveLength(1);
        });
    });

    // --- Fix round 2 shared builders ---

    async function goodResponseForLeaf(
        nonce: Uint8Array,
        extra: Partial<SignedOCSPResponseOptions> = {}
    ): Promise<Uint8Array> {
        return createSignedOCSPResponse(ca.cert, {
            signerKeys: ca.keys,
            producedAt: PRODUCED_AT,
            responses: [
                {
                    cert: leaf.cert,
                    issuer: ca.cert,
                    status: "good",
                    thisUpdate: THIS_UPDATE,
                    nextUpdate: NEXT_UPDATE,
                },
            ],
            nonceEcho: nonce,
            ...extra,
        });
    }

    async function delegateGoodResponse(
        responder: TestResponder,
        nonce: Uint8Array,
        form: "byName" | "byKey" = "byName"
    ): Promise<Uint8Array> {
        return createSignedOCSPResponse(ca.cert, {
            signerKeys: responder.keys,
            responderCert: responder.cert,
            responderId: { form },
            producedAt: PRODUCED_AT,
            responses: [
                {
                    cert: leaf.cert,
                    issuer: ca.cert,
                    status: "good",
                    thisUpdate: THIS_UPDATE,
                    nextUpdate: NEXT_UPDATE,
                },
            ],
            nonceEcho: nonce,
        });
    }

    describe("fix round 2: unknown critical extensions (P1)", () => {
        it("stays unknown on an unknown critical response extension", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await goodResponseForLeaf(nonce!, {
                extraResponseExtensions: [unknownExtension("1.2.3.4.5.7", true)],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/critical/i);
        });

        it("stays unknown on an unknown critical matching single extension", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await goodResponseForLeaf(nonce!, {
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                        singleExtensions: [unknownExtension("1.2.3.4.5.8", true)],
                    },
                ],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/critical/i);
        });

        it("stays unknown on a critical nonce-OID single extension (unprocessed there)", async () => {
            // The nonce OID is recognized at the response level, where the
            // echo is processed -- but no SingleResponse extension is ever
            // processed, so a critical one there must fail closed.
            const { requestBytes, nonce } = await boundRequest();
            const response = await goodResponseForLeaf(nonce!, {
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                        singleExtensions: [unknownExtension(OCSP_NONCE_OID, true)],
                    },
                ],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/critical/i);
        });

        it("stays unknown on an unknown critical delegate certificate extension", async () => {
            const marked = await createDelegateResponder(ca, {
                serial: 3009,
                extraExtensions: [unknownExtension("1.2.3.4.5.9", true)],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(marked, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/critical/i);
        });

        it("caps the matching singleExtensions walk", async () => {
            const validator = await expectValidator();
            const padding: pkijs.Extension[] = [];
            for (let index = 0; index <= validator.MAX_OCSP_EXTENSION_SCAN; index++) {
                padding.push(unknownExtension(`1.2.3.4.${String(3000 + index)}`, false));
            }
            const { requestBytes, nonce } = await boundRequest();
            const response = await goodResponseForLeaf(nonce!, {
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                        singleExtensions: padding,
                    },
                ],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/limit|bound|too many/i);
        });

        it("ignores unknown non-critical extensions in all three positions", async () => {
            const marked = await createDelegateResponder(ca, {
                serial: 3010,
                extraExtensions: [unknownExtension("1.2.3.4.5.9", false)],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: marked.keys,
                responderCert: marked.cert,
                responderId: { form: "byName" },
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                        singleExtensions: [unknownExtension("1.2.3.4.5.8", false)],
                    },
                ],
                nonceEcho: nonce!,
                extraResponseExtensions: [unknownExtension("1.2.3.4.5.7", false)],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts recognized critical delegate extensions (key usage)", async () => {
            // The default delegate carries a CRITICAL digitalSignature key
            // usage: recognized extensions stay valid when critical.
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(delegate, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("ignores critical extensions on non-matching SingleResponses", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await goodResponseForLeaf(nonce!, {
                responses: [
                    {
                        cert: otherLeaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                        singleExtensions: [unknownExtension("1.2.3.4.5.8", true)],
                    },
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 2: TBS completeness and versions (P2-2)", () => {
        it("stays unknown when the request carries a duplicate requestExtensions field", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const second = nonce!.slice();
            second[0] = ((second[0] ?? 0) ^ 0xff) & 0xff;
            const doubled = requestWithDuplicateExtensionsField(requestBytes, second);
            // The response echoes only the first nonce, exactly as sent.
            const response = await goodResponseForLeaf(nonce!);
            const result = await validateDirect(response, { requestBytes: doubled });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown on a trailing NULL in the request TBS", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const padded = requestWithTrailingNullTbs(requestBytes);
            const response = await goodResponseForLeaf(nonce!);
            const result = await validateDirect(response, { requestBytes: padded });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown on a trailing NULL in the response TBS", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const clean = await goodResponseForLeaf(nonce!);
            const mutated = await responseWithTrailingNullTbs(clean, ca.keys.privateKey);
            const result = await validateDirect(mutated, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown when the response version is not v1", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await goodResponseForLeaf(nonce!, { responseVersion: 1 });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown when the request version is not v1", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const versioned = requestWithVersion(requestBytes, 1);
            const response = await goodResponseForLeaf(nonce!);
            const result = await validateDirect(response, { requestBytes: versioned });
            expect(result.status).toBe("unknown");
        });

        it("accepts an explicitly encoded request version v1", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const versioned = requestWithVersion(requestBytes, 0);
            const response = await goodResponseForLeaf(nonce!);
            const result = await validateDirect(response, { requestBytes: versioned });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts an explicitly encoded response version v1", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await goodResponseForLeaf(nonce!, { responseVersion: 0 });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 2: strict delegate authorization encodings (P2-3)", () => {
        it("stays unknown when nocheck carries BOOLEAN FALSE instead of NULL", async () => {
            const liar = await createDelegateResponder(ca, {
                serial: 3011,
                nocheck: false,
                extraExtensions: [
                    rawNoCheckExtension(new asn1js.Boolean({ value: false }).toBER(false)),
                ],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(liar, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown on a duplicated nocheck extension", async () => {
            const doubled = await createDelegateResponder(ca, {
                serial: 3012,
                nocheck: false,
                extraExtensions: [ocspNoCheckExtension(), ocspNoCheckExtension()],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(doubled, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown when EKU mixes OCSPSigning with a non-OID member", async () => {
            const mixed = new asn1js.Sequence({
                value: [
                    new asn1js.ObjectIdentifier({ value: "1.3.6.1.5.5.7.3.9" }),
                    new asn1js.Null(),
                ],
            });
            const slippery = await createDelegateResponder(ca, {
                serial: 3013,
                eku: null,
                extraExtensions: [rawEkuExtension(mixed.toBER(false))],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(slippery, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown when EKU carries trailing garbage", async () => {
            const clean = new asn1js.Sequence({
                value: [new asn1js.ObjectIdentifier({ value: "1.3.6.1.5.5.7.3.9" })],
            }).toBER(false);
            const dirty = new Uint8Array(clean.byteLength + 1);
            dirty.set(new Uint8Array(clean));
            dirty[clean.byteLength] = 0x00;
            const trailer = await createDelegateResponder(ca, {
                serial: 3014,
                eku: null,
                extraExtensions: [rawEkuExtension(toArrayBuffer(dirty))],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(trailer, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("accepts a delegate with correct nocheck NULL and clean EKU", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(delegate, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 2: issuer-as-candidate fall-through (P2-4)", () => {
        it("falls through to a same-name authorized delegate by name", async () => {
            const sameName = await createDelegateResponder(ca, {
                commonName: "T06 Test CA",
                serial: 3015,
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(sameName, nonce!, "byName");
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("still accepts the same-name delegate by key hash", async () => {
            const sameName = await createDelegateResponder(ca, {
                commonName: "T06 Test CA",
                serial: 3016,
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(sameName, nonce!, "byKey");
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("prefers the issuer signature when it verifies despite embedded delegates", async () => {
            const sameName = await createDelegateResponder(ca, {
                commonName: "T06 Test CA",
                serial: 3017,
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await goodResponseForLeaf(nonce!, { certs: [sameName.cert] });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("reports the tried paths when neither issuer nor delegate verifies", async () => {
            const sameName = await createDelegateResponder(ca, {
                commonName: "T06 Test CA",
                serial: 3018,
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: wrongKeys,
                responderCert: sameName.cert,
                responderId: { form: "byName" },
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            const diagnostic = result.errors.join("\n");
            expect(diagnostic).toMatch(/issuer/i);
            expect(diagnostic).toMatch(/delegat/i);
        });
    });

    describe("fix round 2: signature algorithm policy (P2-5)", () => {
        it("stays unknown when an RSA response is relabelled ECDSA", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const clean = await goodResponseForLeaf(nonce!);
            const relabelled = responseWithSigAlg(clean, "1.2.840.10045.4.3.2");
            const result = await validateDirect(relabelled, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown when an ECDSA response is relabelled RSA", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const clean = await delegateGoodResponse(delegate, nonce!);
            const relabelled = responseWithSigAlg(clean, "1.2.840.113549.1.1.11");
            const result = await validateDirect(relabelled, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown on ECDSA parameters that must be absent", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const clean = await delegateGoodResponse(delegate, nonce!);
            const relabelled = responseWithSigAlg(clean, "1.2.840.10045.4.3.2", new asn1js.Null());
            const result = await validateDirect(relabelled, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("accepts RSA signatures with explicit NULL parameters", async () => {
            // Real-world RSA responders encode NULL parameters; pkijs
            // fixtures omit them. Both spellings must verify.
            const { requestBytes, nonce } = await boundRequest();
            const clean = await goodResponseForLeaf(nonce!);
            const nulled = responseWithSigAlg(clean, "1.2.840.113549.1.1.11", new asn1js.Null());
            const result = await validateDirect(nulled, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("stays unknown on an unrecognized signature algorithm OID", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const clean = await goodResponseForLeaf(nonce!);
            const relabelled = responseWithSigAlg(clean, "1.2.3.4.5.99");
            const result = await validateDirect(relabelled, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown on RSA-PSS, which the profile does not support", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const clean = await goodResponseForLeaf(nonce!);
            const relabelled = responseWithSigAlg(clean, "1.2.840.113549.1.1.10");
            const result = await validateDirect(relabelled, { requestBytes });
            expect(result.status).toBe("unknown");
        });
    });

    describe("fix round 3: exact DER NULL nocheck (P2-1)", () => {
        it("stays unknown when nocheck carries 05 01 00 (non-zero-length NULL)", async () => {
            const liar = await createDelegateResponder(ca, {
                serial: 3041,
                nocheck: false,
                extraExtensions: [
                    rawNoCheckExtension(toArrayBuffer(new Uint8Array([0x05, 0x01, 0x00]))),
                ],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(liar, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown when nocheck carries 05 81 00 (non-minimal-length NULL)", async () => {
            const liar = await createDelegateResponder(ca, {
                serial: 3042,
                nocheck: false,
                extraExtensions: [
                    rawNoCheckExtension(toArrayBuffer(new Uint8Array([0x05, 0x81, 0x00]))),
                ],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(liar, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("accepts a delegate with raw 05 00 nocheck bytes", async () => {
            const exact = await createDelegateResponder(ca, {
                serial: 3043,
                nocheck: false,
                extraExtensions: [rawNoCheckExtension(toArrayBuffer(new Uint8Array([0x05, 0x00])))],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(exact, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 3: strict CertStatus grammar (P2-2)", () => {
        const REVOCATION_TIME = new Date("2026-04-15T00:00:00Z");

        function reasonWrapper(values: asn1js.BaseBlock[]): asn1js.Constructed {
            return new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 0 },
                value: values,
            });
        }

        function revokedStatus(children: asn1js.BaseBlock[]): asn1js.Constructed {
            return new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 1 },
                value: children,
            });
        }

        async function revokedResponseForLeaf(
            nonce: Uint8Array,
            certStatus: asn1js.BaseBlock
        ): Promise<Uint8Array> {
            return createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "revoked",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                        certStatusOverride: certStatus,
                    },
                ],
                nonceEcho: nonce,
            });
        }

        it("stays unknown on RevokedInfo with an extra NULL after the reason", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await revokedResponseForLeaf(
                nonce!,
                revokedStatus([
                    new asn1js.GeneralizedTime({ valueDate: REVOCATION_TIME }),
                    reasonWrapper([new asn1js.Enumerated({ value: 1 })]),
                    new asn1js.Null(),
                ])
            );
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown on RevokedInfo with duplicated reason wrappers", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await revokedResponseForLeaf(
                nonce!,
                revokedStatus([
                    new asn1js.GeneralizedTime({ valueDate: REVOCATION_TIME }),
                    reasonWrapper([new asn1js.Enumerated({ value: 1 })]),
                    reasonWrapper([new asn1js.Enumerated({ value: 1 })]),
                ])
            );
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown on RevokedInfo with an extra NULL inside the reason wrapper", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await revokedResponseForLeaf(
                nonce!,
                revokedStatus([
                    new asn1js.GeneralizedTime({ valueDate: REVOCATION_TIME }),
                    reasonWrapper([new asn1js.Enumerated({ value: 1 }), new asn1js.Null()]),
                ])
            );
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("still reports revoked with a valid single reason", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "revoked",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                        revocationTime: REVOCATION_TIME,
                        revocationReason: 1,
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("revoked");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 4: delegate certificate TBS completeness (P2)", () => {
        async function mutatedDelegateResponse(
            serial: number,
            mutateTbs: (tbs: asn1js.Sequence) => void,
            form: "byName" | "byKey" = "byName"
        ): Promise<{ response: Uint8Array; requestBytes: Uint8Array }> {
            const base = await createDelegateResponder(ca, { serial });
            const mutated = await mutateDelegateCertificate(
                base.cert,
                ca.keys.privateKey,
                mutateTbs
            );
            // Genuine CA signature: only strict grammar may reject, never issuance crypto.
            expect(await mutated.verify(ca.cert)).toBe(true);
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(
                { cert: mutated, keys: base.keys },
                nonce!,
                form
            );
            return { response, requestBytes };
        }

        it("stays unknown on a duplicate [3] extensions wrapper with an unsupported critical OID", async () => {
            const { response, requestBytes } = await mutatedDelegateResponse(3101, (tbs) => {
                const malicious = new pkijs.Extension({
                    extnID: "1.2.3.444",
                    critical: true,
                    extnValue: new asn1js.Null().toBER(false),
                }).toSchema();
                tbs.valueBlock.value.push(
                    new asn1js.Constructed({
                        idBlock: { tagClass: 3, tagNumber: 3 },
                        value: [new asn1js.Sequence({ value: [malicious] })],
                    })
                );
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown on a trailing NULL in the delegate TBS", async () => {
            const { response, requestBytes } = await mutatedDelegateResponse(3102, (tbs) => {
                tbs.valueBlock.value.push(new asn1js.Null());
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown on an extra NULL in the delegate validity", async () => {
            const { response, requestBytes } = await mutatedDelegateResponse(3103, (tbs) => {
                const validity = v3DelegateTbsMember(tbs, 4, "validity");
                if (!(validity instanceof asn1js.Sequence)) {
                    throw new Error("validity is not a SEQUENCE");
                }
                validity.valueBlock.value.push(new asn1js.Null());
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown on an extra NULL in the delegate extensions wrapper", async () => {
            const { response, requestBytes } = await mutatedDelegateResponse(3104, (tbs) => {
                delegateExtensionsWrapper(tbs).valueBlock.value.push(new asn1js.Null());
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown on an extra NULL inside a delegate extension member", async () => {
            const { response, requestBytes } = await mutatedDelegateResponse(3105, (tbs) => {
                const inner = delegateExtensionsWrapper(tbs).valueBlock.value[0];
                if (!(inner instanceof asn1js.Sequence)) {
                    throw new Error("extensions inner sequence is missing");
                }
                const first = inner.valueBlock.value[0];
                if (!(first instanceof asn1js.Sequence)) {
                    throw new Error("first extension is not a SEQUENCE");
                }
                first.valueBlock.value.push(new asn1js.Null());
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown on a trailing NULL in a subject-name attribute (byKey)", async () => {
            const { response, requestBytes } = await mutatedDelegateResponse(
                3106,
                (tbs) => pushNameAttributeNull(v3DelegateTbsMember(tbs, 5, "subject"), "subject"),
                "byKey"
            );
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown on a trailing NULL in a subject-name attribute (byName pair)", async () => {
            const { response, requestBytes } = await mutatedDelegateResponse(3107, (tbs) =>
                pushNameAttributeNull(v3DelegateTbsMember(tbs, 5, "subject"), "subject")
            );
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("stays unknown (never throws) on a malformed wire responderID name", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const clean = await goodResponseForLeaf(nonce!);
            const mutated = await responseWithResponderNameNull(clean, ca.keys.privateKey);
            const result = await validateDirect(mutated, { requestBytes });
            expect(result.status).toBe("unknown");
        });

        it("accepts the unmodified delegate (round-4 control)", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(delegate, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts a delegate with a multi-valued RDN (two attributes, one SET)", async () => {
            const { response, requestBytes } = await mutatedDelegateResponse(3111, (tbs) => {
                const members = tbs.valueBlock.value;
                members[5] = nameFromSets([
                    [
                        {
                            type: "2.5.4.3",
                            value: new asn1js.PrintableString({ value: "T06 Multi" }),
                        },
                        {
                            type: "2.5.4.11",
                            value: new asn1js.PrintableString({ value: "OCSP Unit" }),
                        },
                    ],
                ]);
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts a delegate with many RDNs and UTF8String values (long-name control)", async () => {
            const { response, requestBytes } = await mutatedDelegateResponse(3112, (tbs) => {
                const sets: { type: string; value: asn1js.BaseBlock }[][] = [
                    [
                        {
                            type: "2.5.4.3",
                            value: new asn1js.Utf8String({ value: "T06 Long-Lived Responder" }),
                        },
                    ],
                    [
                        {
                            type: "2.5.4.10",
                            value: new asn1js.Utf8String({ value: "Example Organization" }),
                        },
                    ],
                ];
                for (let unit = 0; unit < 8; unit++) {
                    sets.push([
                        {
                            type: "2.5.4.11",
                            value: new asn1js.PrintableString({ value: `Unit ${String(unit)}` }),
                        },
                    ]);
                }
                tbs.valueBlock.value[5] = nameFromSets(sets);
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 5: empty RDN SETs (P2-1)", () => {
        async function emptyRdnDelegateResponse(
            serial: number,
            subject: asn1js.Sequence,
            form: "byName" | "byKey" = "byKey"
        ): Promise<{ response: Uint8Array; requestBytes: Uint8Array }> {
            const base = await createDelegateResponder(ca, { serial });
            const mutated = await mutateDelegateCertificate(
                base.cert,
                ca.keys.privateKey,
                (tbs) => {
                    v3DelegateTbsMember(tbs, 5, "subject");
                    tbs.valueBlock.value[5] = subject;
                }
            );
            // Genuine CA signature: only strict grammar may reject, never issuance crypto.
            expect(await mutated.verify(ca.cert)).toBe(true);
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(
                { cert: mutated, keys: base.keys },
                nonce!,
                form
            );
            return { response, requestBytes };
        }

        it("stays unknown on an empty-RDN delegate subject (byKey)", async () => {
            const { response, requestBytes } = await emptyRdnDelegateResponse(
                3201,
                nameFromSets([[]])
            );
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/malformed.*distinguished name/);
        });

        it("stays unknown on an empty SET plus a valid RDN (byKey)", async () => {
            const { response, requestBytes } = await emptyRdnDelegateResponse(
                3202,
                nameFromSets([
                    [],
                    [
                        {
                            type: "2.5.4.3",
                            value: new asn1js.PrintableString({ value: "T06 Responder" }),
                        },
                    ],
                ])
            );
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/malformed.*distinguished name/);
        });

        it("matches nothing on an empty-RDN responder name (byName)", async () => {
            const { response, requestBytes } = await emptyRdnDelegateResponse(
                3203,
                nameFromSets([[]]),
                "byName"
            );
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/no responder certificate matches/);
        });

        it("accepts an entirely empty delegate Name (byKey control)", async () => {
            const { response, requestBytes } = await emptyRdnDelegateResponse(
                3204,
                nameFromSets([])
            );
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts an entirely empty delegate Name (byName control)", async () => {
            const { response, requestBytes } = await emptyRdnDelegateResponse(
                3205,
                nameFromSets([]),
                "byName"
            );
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 5: delegate signature-algorithm consistency (P2-2)", () => {
        const ECDSA_SHA256 = "1.2.840.10045.4.3.2";

        async function delegateGoodResponseFor(
            issuerCert: pkijs.Certificate,
            target: pkijs.Certificate,
            responder: TestResponder,
            nonce: Uint8Array
        ): Promise<Uint8Array> {
            return createSignedOCSPResponse(issuerCert, {
                signerKeys: responder.keys,
                responderCert: responder.cert,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: target,
                        issuer: issuerCert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce,
            });
        }

        function innerSignature(tbs: asn1js.Sequence): asn1js.Sequence {
            const inner = v3DelegateTbsMember(tbs, 2, "signature");
            if (!(inner instanceof asn1js.Sequence)) {
                throw new Error("inner signature is not a SEQUENCE");
            }
            return inner;
        }

        it("stays unknown on an outer-relabelled delegate (RSA inner, ECDSA outer)", async () => {
            const base = await createDelegateResponder(ca, { serial: 3301 });
            const relabelled = relabelDelegateOuter(base.cert, (outer) =>
                setAlgorithmOid(outer, ECDSA_SHA256)
            );
            // pkijs still verifies (family from the key, hash from the OID):
            // only the new consistency gate may reject.
            expect(await relabelled.verify(ca.cert)).toBe(true);
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(
                { cert: relabelled, keys: base.keys },
                nonce!
            );
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/inconsistent signature algorithms/);
        });

        it("stays unknown on an outer-relabelled delegate through the session", async () => {
            const base = await createDelegateResponder(ca, { serial: 3302 });
            const relabelled = relabelDelegateOuter(base.cert, (outer) =>
                setAlgorithmOid(outer, ECDSA_SHA256)
            );
            expect(await relabelled.verify(ca.cert)).toBe(true);
            const fetcher = echoResponder({ signerKeys: base.keys, responderCert: relabelled });
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
            });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(result?.errors.join("\n")).toMatch(/inconsistent signature algorithms/);
        });

        it("stays unknown when the outer identifier gains parameters the inner lacks", async () => {
            const base = await createDelegateResponder(ca, { serial: 3303 });
            const relabelled = relabelDelegateOuter(base.cert, (outer) => {
                outer.valueBlock.value.push(new asn1js.Null());
            });
            expect(await relabelled.verify(ca.cert)).toBe(true);
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(
                { cert: relabelled, keys: base.keys },
                nonce!
            );
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/inconsistent signature algorithm parameters/);
        });

        it("stays unknown when the inner identifier gains parameters the outer lacks", async () => {
            const base = await createDelegateResponder(ca, { serial: 3304 });
            const mutated = await mutateDelegateCertificate(
                base.cert,
                ca.keys.privateKey,
                (tbs) => {
                    innerSignature(tbs).valueBlock.value.push(new asn1js.Null());
                }
            );
            expect(await mutated.verify(ca.cert)).toBe(true);
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse({ cert: mutated, keys: base.keys }, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/inconsistent signature algorithm parameters/);
        });

        it("stays unknown when both identifiers claim ECDSA under an RSA issuer key", async () => {
            const base = await createDelegateResponder(ca, { serial: 3305 });
            const innerMutated = await mutateDelegateCertificate(
                base.cert,
                ca.keys.privateKey,
                (tbs) => {
                    setAlgorithmOid(innerSignature(tbs), ECDSA_SHA256);
                }
            );
            const relabelled = relabelDelegateOuter(innerMutated, (outer) =>
                setAlgorithmOid(outer, ECDSA_SHA256)
            );
            // Genuine RSA signature over the relabelled TBS: pkijs still verifies.
            expect(await relabelled.verify(ca.cert)).toBe(true);
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(
                { cert: relabelled, keys: base.keys },
                nonce!
            );
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/not compatible with the issuer key/);
        });

        it("accepts an ECDSA-issued delegate (EC family positive)", async () => {
            const ecCA = await createTestCA("T06 EC CA", {
                serial: 1061,
                keys: await generateECKeyPair(),
            });
            const ecLeaf = await createTestLeaf(ecCA, {
                commonName: "T06 EC Leaf",
                serial: 2061,
            });
            const ecDelegate = await createDelegateResponder(ecCA, { serial: 3361 });
            const { requestBytes, nonce } = await boundRequest(ecLeaf.cert, ecCA.cert);
            const response = await delegateGoodResponseFor(
                ecCA.cert,
                ecLeaf.cert,
                ecDelegate,
                nonce!
            );
            const result = await validateDirect(response, {
                requestBytes,
                cert: ecLeaf.cert,
                issuer: ecCA.cert,
            });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("stays unknown on a genuine RSA-PSS delegate (unsupported family)", async () => {
            const pssPair = await globalThis.crypto.subtle.generateKey(
                {
                    name: "RSA-PSS",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                    hash: "SHA-256",
                },
                true,
                ["sign", "verify"]
            );
            const pssCA = await createTestCA("T06 PSS CA", {
                serial: 1062,
                keys: { publicKey: pssPair.publicKey, privateKey: pssPair.privateKey },
            });
            const pssLeaf = await createTestLeaf(pssCA, {
                commonName: "T06 PSS Leaf",
                serial: 2062,
            });
            const pssDelegate = await createDelegateResponder(pssCA, { serial: 3362 });
            const { requestBytes, nonce } = await boundRequest(pssLeaf.cert, pssCA.cert);
            const response = await delegateGoodResponseFor(
                pssCA.cert,
                pssLeaf.cert,
                pssDelegate,
                nonce!
            );
            const result = await validateDirect(response, {
                requestBytes,
                cert: pssLeaf.cert,
                issuer: pssCA.cert,
            });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/not compatible with the issuer key/);
        });

        it("accepts the unmodified RSA-issued delegate (round-5 RSA control)", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(delegate, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 5: delegate version enforcement (P2-3)", () => {
        async function versionDelegateResponse(
            serial: number,
            version: number | "absent"
        ): Promise<{ response: Uint8Array; requestBytes: Uint8Array }> {
            const base = await createDelegateResponder(ca, { serial });
            const mutated = await mutateDelegateCertificate(
                base.cert,
                ca.keys.privateKey,
                (tbs) => {
                    if (version === "absent") {
                        const first = tbs.valueBlock.value[0];
                        if (
                            !(first instanceof asn1js.Constructed) ||
                            first.idBlock.tagClass !== 3 ||
                            first.idBlock.tagNumber !== 0
                        ) {
                            throw new Error("delegate TBS has no explicit version wrapper");
                        }
                        tbs.valueBlock.value.splice(0, 1);
                        return;
                    }
                    const wrapper = v3DelegateTbsMember(tbs, 0, "version");
                    if (!(wrapper instanceof asn1js.Constructed)) {
                        throw new Error("version is not [0] EXPLICIT");
                    }
                    wrapper.valueBlock.value[0] = new asn1js.Integer({ value: version });
                }
            );
            // Genuine CA signature: only the version gate may reject, never issuance crypto.
            expect(await mutated.verify(ca.cert)).toBe(true);
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse({ cert: mutated, keys: base.keys }, nonce!);
            return { response, requestBytes };
        }

        const badVersions: (number | "absent")[] = [-1, 1, 3, 99, "absent"];
        for (const [index, version] of badVersions.entries()) {
            const label = version === "absent" ? "absent" : `v${String(version)}`;
            it(`stays unknown on a ${label} delegate carrying EKU and nocheck`, async () => {
                const { response, requestBytes } = await versionDelegateResponse(
                    3401 + index,
                    version
                );
                const result = await validateDirect(response, { requestBytes });
                expect(result.status).toBe("unknown");
                expect(result.errors.join("\n")).toMatch(/X\.509 v3/);
            });
        }

        it("accepts an explicit version-2 delegate (v3 control)", async () => {
            const { response, requestBytes } = await versionDelegateResponse(3410, 2);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 6: signature BIT STRING framing (P2-1)", () => {
        interface EcWorld {
            ecCA: TestCertificateAuthority;
            ecLeaf: TestLeaf;
            ecDelegate: TestResponder;
        }

        async function createEcWorld(serialBase: number): Promise<EcWorld> {
            const ecCA = await createTestCA("T06 EC CA", {
                serial: serialBase,
                keys: await generateECKeyPair(),
            });
            const ecLeaf = await createTestLeaf(ecCA, {
                commonName: "T06 EC Leaf",
                serial: serialBase + 1000,
            });
            const ecDelegate = await createDelegateResponder(ecCA, {
                serial: serialBase + 2000,
            });
            return { ecCA, ecLeaf, ecDelegate };
        }

        async function ecDelegateGoodResponse(
            world: EcWorld,
            responderCert: pkijs.Certificate,
            nonce: Uint8Array
        ): Promise<Uint8Array> {
            return createSignedOCSPResponse(world.ecCA.cert, {
                signerKeys: world.ecDelegate.keys,
                responderCert,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: world.ecLeaf.cert,
                        issuer: world.ecCA.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                nonceEcho: nonce,
            });
        }

        for (const unusedBits of [1, 7]) {
            it(`stays unknown on an RSA response signature with ${String(unusedBits)} unused bits`, async () => {
                const { requestBytes, nonce } = await boundRequest();
                const clean = await goodResponseForLeaf(nonce!);
                const tampered = responseWithSignatureBits(
                    clean,
                    bitStringWithUnusedBits(responseSignatureBits(clean), unusedBits)
                );
                const result = await validateDirect(tampered, { requestBytes });
                expect(result.status).toBe("unknown");
                expect(result.errors.join("\n")).toMatch(/does not verify/);
            });

            it(`stays unknown on an ECDSA response signature with ${String(unusedBits)} unused bits`, async () => {
                const { requestBytes, nonce } = await boundRequest();
                const clean = await delegateGoodResponse(delegate, nonce!);
                const tampered = responseWithSignatureBits(
                    clean,
                    bitStringWithUnusedBits(responseSignatureBits(clean), unusedBits)
                );
                const result = await validateDirect(tampered, { requestBytes });
                expect(result.status).toBe("unknown");
                expect(result.errors.join("\n")).toMatch(/does not verify/);
            });
        }

        it("stays unknown on an ECDSA response signature with trailing bytes", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const clean = await delegateGoodResponse(delegate, nonce!);
            const payload = new Uint8Array(responseSignatureBits(clean).valueBlock.valueHexView);
            const tampered = responseWithSignatureBits(
                clean,
                new asn1js.BitString({
                    valueHex: toArrayBuffer(concatBytes(payload, new Uint8Array([0x05, 0x00]))),
                })
            );
            const result = await validateDirect(tampered, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/does not verify/);
        });

        it("stays unknown through the session on a response signature with unused bits", async () => {
            const inner = echoResponder({ signerKeys: ca.keys });
            const fetcher: RevocationDataFetcher & {
                ocspRequests: Uint8Array[];
                ocspCalls: number;
                crlCalls: number;
            } = {
                ...inner,
                fetchOCSP: async (url: string, request: Uint8Array) => {
                    const clean = await inner.fetchOCSP(url, request);
                    return responseWithSignatureBits(
                        clean,
                        bitStringWithUnusedBits(responseSignatureBits(clean), 1)
                    );
                },
            };
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
            });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
        });

        for (const unusedBits of [1, 7]) {
            it(`stays unknown on a delegate certificate signature with ${String(unusedBits)} unused bits`, async () => {
                const base = await createDelegateResponder(ca, { serial: 3501 + unusedBits });
                const mutated = certificateWithSignatureBits(
                    base.cert,
                    bitStringWithUnusedBits(base.cert.signatureValue, unusedBits)
                );
                // Genuine CA signature bytes: pkijs still verifies, only the
                // new framing gate may reject.
                expect(await mutated.verify(ca.cert)).toBe(true);
                const { requestBytes, nonce } = await boundRequest();
                const response = await delegateGoodResponse(
                    { cert: mutated, keys: base.keys },
                    nonce!
                );
                const result = await validateDirect(response, { requestBytes });
                expect(result.status).toBe("unknown");
                expect(result.errors.join("\n")).toMatch(/not octet-aligned/);
            });
        }

        it("stays unknown on an ECDSA delegate-certificate signature with unused bits", async () => {
            const world = await createEcWorld(3561);
            const mutated = certificateWithSignatureBits(
                world.ecDelegate.cert,
                bitStringWithUnusedBits(world.ecDelegate.cert.signatureValue, 1)
            );
            expect(await mutated.verify(world.ecCA.cert)).toBe(true);
            const { requestBytes, nonce } = await boundRequest(world.ecLeaf.cert, world.ecCA.cert);
            const response = await ecDelegateGoodResponse(world, mutated, nonce!);
            const result = await validateDirect(response, {
                requestBytes,
                cert: world.ecLeaf.cert,
                issuer: world.ecCA.cert,
            });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/not octet-aligned/);
        });

        it("stays unknown on an ECDSA delegate-certificate signature with trailing bytes", async () => {
            const world = await createEcWorld(3571);
            const payload = new Uint8Array(
                world.ecDelegate.cert.signatureValue.valueBlock.valueHexView
            );
            const mutated = certificateWithSignatureBits(
                world.ecDelegate.cert,
                new asn1js.BitString({
                    valueHex: toArrayBuffer(concatBytes(payload, new Uint8Array([0x05, 0x00]))),
                })
            );
            expect(await mutated.verify(world.ecCA.cert)).toBe(true);
            const { requestBytes, nonce } = await boundRequest(world.ecLeaf.cert, world.ecCA.cert);
            const response = await ecDelegateGoodResponse(world, mutated, nonce!);
            const result = await validateDirect(response, {
                requestBytes,
                cert: world.ecLeaf.cert,
                issuer: world.ecCA.cert,
            });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/ECDSA signature/);
        });

        it("accepts unmodified RSA and ECDSA response signatures (round-6 framing controls)", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const rsa = await validateDirect(await goodResponseForLeaf(nonce!), { requestBytes });
            expect(rsa.status).toBe("good");
            expect(rsa.errors).toEqual([]);
            const ecdsa = await validateDirect(await delegateGoodResponse(delegate, nonce!), {
                requestBytes,
            });
            expect(ecdsa.status).toBe("good");
            expect(ecdsa.errors).toEqual([]);
        });
    });

    describe("fix round 6: delegate SPKI encoding (P2-2)", () => {
        async function rsaDelegate(serial: number): Promise<TestResponder> {
            return createDelegateResponder(ca, { serial, keys: await generateRSAKeyPair() });
        }

        function spkiAlgorithm(spki: asn1js.Sequence): asn1js.Sequence {
            const algorithm = spki.valueBlock.value[0];
            if (!(algorithm instanceof asn1js.Sequence)) {
                throw new Error("SPKI algorithm is not a SEQUENCE");
            }
            return algorithm;
        }

        async function resignedSpkiResponse(
            base: TestResponder,
            mutateSpki: (spki: asn1js.Sequence) => void
        ): Promise<{ response: Uint8Array; requestBytes: Uint8Array }> {
            const mutated = await mutateDelegateCertificate(
                base.cert,
                ca.keys.privateKey,
                (tbs) => {
                    mutateSpki(delegateSpki(tbs));
                }
            );
            // Genuine CA signature over the mutated TBS: only the new SPKI
            // grammar gate may reject, never issuance crypto.
            expect(await mutated.verify(ca.cert)).toBe(true);
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse({ cert: mutated, keys: base.keys }, nonce!);
            return { response, requestBytes };
        }

        it("stays unknown on an RSA key payload with an extra NULL member", async () => {
            const base = await rsaDelegate(3601);
            const { response, requestBytes } = await resignedSpkiResponse(base, (spki) => {
                const { n, e } = rsaKeyIntegers(spkiSubjectPublicKey(spki));
                spki.valueBlock.value[1] = new asn1js.BitString({
                    valueHex: new asn1js.Sequence({ value: [n, e, new asn1js.Null()] }).toBER(
                        false
                    ),
                });
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/RSA public key/);
        });

        it("stays unknown on an RSA key payload with an extra INTEGER member", async () => {
            const base = await rsaDelegate(3602);
            const { response, requestBytes } = await resignedSpkiResponse(base, (spki) => {
                const { n, e } = rsaKeyIntegers(spkiSubjectPublicKey(spki));
                spki.valueBlock.value[1] = new asn1js.BitString({
                    valueHex: new asn1js.Sequence({
                        value: [n, e, new asn1js.Integer({ value: 42 })],
                    }).toBER(false),
                });
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/RSA public key/);
        });

        it("stays unknown on an RSA key payload with a trailing NULL", async () => {
            const base = await rsaDelegate(3603);
            const { response, requestBytes } = await resignedSpkiResponse(base, (spki) => {
                const { n, e } = rsaKeyIntegers(spkiSubjectPublicKey(spki));
                const inner = new Uint8Array(new asn1js.Sequence({ value: [n, e] }).toBER(false));
                const nul = new Uint8Array(new asn1js.Null().toBER(false));
                spki.valueBlock.value[1] = new asn1js.BitString({
                    valueHex: toArrayBuffer(concatBytes(inner, nul)),
                });
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/RSA public key/);
        });

        it("stays unknown on RSA SPKI parameters carrying an INTEGER", async () => {
            const base = await rsaDelegate(3604);
            const { response, requestBytes } = await resignedSpkiResponse(base, (spki) => {
                spkiAlgorithm(spki).valueBlock.value[1] = new asn1js.Integer({ value: 5 });
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/unsupported parameters/);
        });

        it("stays unknown on RSA SPKI parameters carrying a SEQUENCE", async () => {
            const base = await rsaDelegate(3605);
            const { response, requestBytes } = await resignedSpkiResponse(base, (spki) => {
                spkiAlgorithm(spki).valueBlock.value[1] = new asn1js.Sequence({ value: [] });
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/unsupported parameters/);
        });

        for (const unusedBits of [1, 7]) {
            it(`stays unknown on an RSA delegate key with ${String(unusedBits)} unused bits`, async () => {
                const base = await rsaDelegate(3610 + unusedBits);
                const { response, requestBytes } = await resignedSpkiResponse(base, (spki) => {
                    spki.valueBlock.value[1] = bitStringWithUnusedBits(
                        spkiSubjectPublicKey(spki),
                        unusedBits
                    );
                });
                const result = await validateDirect(response, { requestBytes });
                expect(result.status).toBe("unknown");
                expect(result.errors.join("\n")).toMatch(/not octet-aligned/);
            });

            it(`stays unknown on an EC delegate key with ${String(unusedBits)} unused bits`, async () => {
                const base = await createDelegateResponder(ca, { serial: 3620 + unusedBits });
                const { response, requestBytes } = await resignedSpkiResponse(base, (spki) => {
                    spki.valueBlock.value[1] = bitStringWithUnusedBits(
                        spkiSubjectPublicKey(spki),
                        unusedBits
                    );
                });
                const result = await validateDirect(response, { requestBytes });
                expect(result.status).toBe("unknown");
                expect(result.errors.join("\n")).toMatch(/not octet-aligned/);
            });
        }

        it("accepts RSA delegates with NULL or absent SPKI parameters (round-6 controls)", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const nulled = await rsaDelegate(3631);
            const nulledResult = await validateDirect(await delegateGoodResponse(nulled, nonce!), {
                requestBytes,
            });
            expect(nulledResult.status).toBe("good");
            expect(nulledResult.errors).toEqual([]);
            const base = await rsaDelegate(3632);
            const absent = await resignedSpkiResponse(base, (spki) => {
                spkiAlgorithm(spki).valueBlock.value.splice(1, 1);
            });
            const absentResult = await validateDirect(absent.response, {
                requestBytes: absent.requestBytes,
            });
            expect(absentResult.status).toBe("good");
            expect(absentResult.errors).toEqual([]);
        });

        it("accepts an EC delegate with named-curve parameters (round-6 control)", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const result = await validateDirect(await delegateGoodResponse(delegate, nonce!), {
                requestBytes,
            });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 6: delegate validity interval (P2-3)", () => {
        const NOON = new Date("2026-05-01T12:00:00Z");

        async function noonDelegateResponse(
            responder: TestResponder,
            nonce: Uint8Array
        ): Promise<Uint8Array> {
            return createSignedOCSPResponse(ca.cert, {
                signerKeys: responder.keys,
                responderCert: responder.cert,
                producedAt: NOON,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: NOON,
                        nextUpdate: new Date("2026-05-02T12:00:00Z"),
                    },
                ],
                nonceEcho: nonce,
            });
        }

        it("stays unknown on an inverted delegate validity interval within skew", async () => {
            const inverted = await createDelegateResponder(ca, {
                serial: 3701,
                notBefore: new Date("2026-05-01T12:01:00Z"),
                notAfter: new Date("2026-05-01T11:59:00Z"),
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await noonDelegateResponse(inverted, nonce!);
            const result = await validateDirect(response, {
                requestBytes,
                checkDate: NOON,
                clockSkewMs: CLOCK_SKEW_MS,
            });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/inverted validity period/);
        });

        it("accepts a delegate whose validity endpoints are equal (P2-3 control)", async () => {
            const equal = await createDelegateResponder(ca, {
                serial: 3702,
                notBefore: NOON,
                notAfter: NOON,
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await noonDelegateResponse(equal, nonce!);
            const result = await validateDirect(response, {
                requestBytes,
                checkDate: NOON,
                clockSkewMs: CLOCK_SKEW_MS,
            });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 7: extension-payload canonicality (P2)", () => {
        /** Canonical OCSPSigning OID TLV, wrapped in attacker-chosen SEQUENCE framing. */
        function ocspsigningOidTlv(): Uint8Array {
            const tlv = new Uint8Array(
                new asn1js.ObjectIdentifier({ value: "1.3.6.1.5.5.7.3.9" }).toBER(false)
            );
            expect(tlv).toHaveLength(10);
            return tlv;
        }

        /** Re-encodes request bytes with an attacker-chosen nonce extnValue (unsigned: no resign). */
        function requestWithRawNonce(
            requestBytes: Uint8Array,
            rawExtnValue: ArrayBuffer
        ): Uint8Array {
            const parsed = asn1js.fromBER(toArrayBuffer(requestBytes.slice()));
            if (parsed.offset === -1) throw new Error("request is not DER");
            const request = new pkijs.OCSPRequest({ schema: parsed.result });
            request.tbsRequest.requestExtensions = [
                new pkijs.Extension({
                    extnID: OCSP_NONCE_OID,
                    critical: false,
                    extnValue: rawExtnValue,
                }),
            ];
            request.tbsRequest.tbsView = new Uint8Array(0);
            return new Uint8Array(request.toSchema(true).toBER(false));
        }

        it("stays unknown on KU 03 02 07 FF (nonzero padding in declared unused bits)", async () => {
            const padded = await createDelegateResponder(ca, {
                serial: 3801,
                keyUsage: null,
                extraExtensions: [
                    rawKeyUsageExtension(toArrayBuffer(Uint8Array.of(0x03, 0x02, 0x07, 0xff))),
                ],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(padded, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/forbids digital signatures/);
        });

        it("stays unknown on KU with non-minimal long-form length (03 81 02 00 80)", async () => {
            const framed = await createDelegateResponder(ca, {
                serial: 3802,
                keyUsage: null,
                extraExtensions: [
                    rawKeyUsageExtension(
                        toArrayBuffer(Uint8Array.of(0x03, 0x81, 0x02, 0x00, 0x80))
                    ),
                ],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(framed, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/forbids digital signatures/);
        });

        it("stays unknown on EKU in an indefinite-length SEQUENCE", async () => {
            const tlv = ocspsigningOidTlv();
            const indefinite = concatBytes(
                Uint8Array.of(0x30, 0x80),
                concatBytes(tlv, Uint8Array.of(0x00, 0x00))
            );
            const ber = await createDelegateResponder(ca, {
                serial: 3803,
                eku: null,
                extraExtensions: [rawEkuExtension(toArrayBuffer(indefinite))],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(ber, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/id-kp-OCSPSigning/);
        });

        it("stays unknown on EKU with non-minimal long-form length (30 81 0A)", async () => {
            const tlv = ocspsigningOidTlv();
            const nonMinimal = concatBytes(Uint8Array.of(0x30, 0x81, tlv.length), tlv);
            const framed = await createDelegateResponder(ca, {
                serial: 3804,
                eku: null,
                extraExtensions: [rawEkuExtension(toArrayBuffer(nonMinimal))],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(framed, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/id-kp-OCSPSigning/);
        });

        it("stays unknown on a response nonce echo with non-minimal length (04 81 20)", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const badEcho = new pkijs.Extension({
                extnID: OCSP_NONCE_OID,
                critical: false,
                extnValue: toArrayBuffer(concatBytes(Uint8Array.of(0x04, 0x81, 0x20), nonce!)),
            });
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                extraResponseExtensions: [badEcho],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/malformed OCSP nonce/);
        });

        it("stays unknown on a request nonce with non-minimal length (04 81 20)", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const rebound = requestWithRawNonce(
                requestBytes,
                toArrayBuffer(concatBytes(Uint8Array.of(0x04, 0x81, 0x20), nonce!))
            );
            const response = await goodResponseForLeaf(nonce!);
            const result = await validateDirect(response, { requestBytes: rebound });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/malformed OCSP nonce/);
        });

        it("accepts KU 03 02 07 80 (7 unused bits, only digitalSignature set)", async () => {
            const sparse = await createDelegateResponder(ca, {
                serial: 3811,
                keyUsage: null,
                extraExtensions: [
                    rawKeyUsageExtension(toArrayBuffer(Uint8Array.of(0x03, 0x02, 0x07, 0x80))),
                ],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(sparse, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts a 9-bit KU with valid zero padding (03 03 07 80 80)", async () => {
            const nineBit = await createDelegateResponder(ca, {
                serial: 3812,
                keyUsage: null,
                extraExtensions: [
                    rawKeyUsageExtension(
                        toArrayBuffer(Uint8Array.of(0x03, 0x03, 0x07, 0x80, 0x80))
                    ),
                ],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(nineBit, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts a 16-bit KU with zero unused bits (03 03 00 80 01)", async () => {
            const wide = await createDelegateResponder(ca, {
                serial: 3813,
                keyUsage: null,
                extraExtensions: [
                    rawKeyUsageExtension(
                        toArrayBuffer(Uint8Array.of(0x03, 0x03, 0x00, 0x80, 0x01))
                    ),
                ],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(wide, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 8: OID content canonicality (P2)", () => {
        /** Canonical OCSPSigning OID TLV, wrapped in attacker-chosen SEQUENCE framing. */
        function ocspsigningOidTlv(): Uint8Array {
            const tlv = new Uint8Array(
                new asn1js.ObjectIdentifier({ value: "1.3.6.1.5.5.7.3.9" }).toBER(false)
            );
            expect(tlv).toHaveLength(10);
            return tlv;
        }

        /** Wraps OID-member TLVs in a DER EKU SEQUENCE payload (short form only). */
        function ekuPayload(...members: Uint8Array[]): Uint8Array {
            let total = 0;
            for (const member of members) total += member.length;
            if (total >= 128) throw new Error("fixture EKU payload exceeds short-form length");
            const content = new Uint8Array(total);
            let offset = 0;
            for (const member of members) {
                content.set(member, offset);
                offset += member.length;
            }
            return concatBytes(Uint8Array.of(0x30, total), content);
        }

        /** Builds a delegate whose subject is one attribute with attacker-chosen type-OID content. */
        async function delegateWithRawSubjectTypeOid(
            serial: number,
            typeContent: Uint8Array
        ): Promise<TestResponder> {
            const base = await createDelegateResponder(ca, { serial });
            // A Primitive, not an ObjectIdentifier: toBER re-encodes OID
            // objects from the normalized dotted string, which would
            // canonicalize the malformation away before signing, while a
            // Primitive emits valueHex verbatim onto the signed TBS.
            const subject = new asn1js.Sequence({
                value: [
                    new asn1js.Set({
                        value: [
                            new asn1js.Sequence({
                                value: [
                                    new asn1js.Primitive({
                                        idBlock: { tagClass: 1, tagNumber: 6 },
                                        valueHex: toArrayBuffer(typeContent),
                                    }),
                                    new asn1js.Utf8String({ value: "Round8 responder" }),
                                ],
                            }),
                        ],
                    }),
                ],
            });
            const mutated = await mutateDelegateCertificate(
                base.cert,
                ca.keys.privateKey,
                (tbs) => {
                    v3DelegateTbsMember(tbs, 5, "subject");
                    tbs.valueBlock.value[5] = subject;
                }
            );
            // Genuine CA signature: only strict grammar may reject, never issuance crypto.
            expect(await mutated.verify(ca.cert)).toBe(true);
            return { cert: mutated, keys: base.keys };
        }

        it("stays unknown on EKU 30 0B 06 09 2B 80 06 ... (non-minimal subidentifier)", async () => {
            const nonMinimal = Uint8Array.of(
                0x30,
                0x0b,
                0x06,
                0x09,
                0x2b,
                0x80,
                0x06,
                0x01,
                0x05,
                0x05,
                0x07,
                0x03,
                0x09
            );
            const framed = await createDelegateResponder(ca, {
                serial: 3901,
                eku: null,
                extraExtensions: [rawEkuExtension(toArrayBuffer(nonMinimal))],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(framed, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/id-kp-OCSPSigning/);
        });

        it("stays unknown on EKU 30 0B 06 09 80 2B ... (leading-0x80 first subidentifier)", async () => {
            const nonMinimal = Uint8Array.of(
                0x30,
                0x0b,
                0x06,
                0x09,
                0x80,
                0x2b,
                0x06,
                0x01,
                0x05,
                0x05,
                0x07,
                0x03,
                0x09
            );
            const framed = await createDelegateResponder(ca, {
                serial: 3902,
                eku: null,
                extraExtensions: [rawEkuExtension(toArrayBuffer(nonMinimal))],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(framed, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/id-kp-OCSPSigning/);
        });

        it("stays unknown on EKU pairing OCSPSigning with an empty OID (06 00)", async () => {
            const payload = ekuPayload(ocspsigningOidTlv(), Uint8Array.of(0x06, 0x00));
            const framed = await createDelegateResponder(ca, {
                serial: 3903,
                eku: null,
                extraExtensions: [rawEkuExtension(toArrayBuffer(payload))],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(framed, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/id-kp-OCSPSigning/);
        });

        it("stays unknown on EKU pairing OCSPSigning with an unterminated OID (06 01 80)", async () => {
            const payload = ekuPayload(ocspsigningOidTlv(), Uint8Array.of(0x06, 0x01, 0x80));
            const framed = await createDelegateResponder(ca, {
                serial: 3904,
                eku: null,
                extraExtensions: [rawEkuExtension(toArrayBuffer(payload))],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(framed, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/id-kp-OCSPSigning/);
        });

        it("stays unknown on an empty attribute-type OID in the delegate subject (byKey)", async () => {
            const responder = await delegateWithRawSubjectTypeOid(3905, new Uint8Array(0));
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(responder, nonce!, "byKey");
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/malformed distinguished name/);
        });

        it("stays unknown on an empty attribute-type OID in a matching byName pair", async () => {
            const responder = await delegateWithRawSubjectTypeOid(3906, new Uint8Array(0));
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(responder, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/no responder certificate matches/);
        });

        it("accepts a raw canonical OCSPSigning EKU (round-8 control)", async () => {
            const payload = ekuPayload(ocspsigningOidTlv());
            const clean = await createDelegateResponder(ca, {
                serial: 3911,
                eku: null,
                extraExtensions: [rawEkuExtension(toArrayBuffer(payload))],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(clean, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts EKU pairing OCSPSigning with a large-subidentifier OID (2.100.3)", async () => {
            const payload = ekuPayload(
                ocspsigningOidTlv(),
                Uint8Array.of(0x06, 0x03, 0x81, 0x34, 0x03)
            );
            const clean = await createDelegateResponder(ca, {
                serial: 3912,
                eku: null,
                extraExtensions: [rawEkuExtension(toArrayBuffer(payload))],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(clean, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts EKU pairing OCSPSigning with first-octet 120 (2.40.3)", async () => {
            const payload = ekuPayload(ocspsigningOidTlv(), Uint8Array.of(0x06, 0x02, 0x78, 0x03));
            const clean = await createDelegateResponder(ca, {
                serial: 3913,
                eku: null,
                extraExtensions: [rawEkuExtension(toArrayBuffer(payload))],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(clean, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 9: empty extension OID (P2)", () => {
        /**
         * The Astra round-9 attack extension: empty OID, noncritical,
         * NULL payload. Pins the exact wire bytes
         * `30 06 06 00 04 02 05 00` so the fixture cannot silently
         * normalize the malformation away before signing.
         */
        function emptyOidExtension(): pkijs.Extension {
            const extension = new pkijs.Extension({
                extnID: "",
                critical: false,
                extnValue: toArrayBuffer(Uint8Array.of(0x05, 0x00)),
            });
            const ber = new Uint8Array(extension.toSchema().toBER(false));
            expect(ber).toEqual(Uint8Array.of(0x30, 0x06, 0x06, 0x00, 0x04, 0x02, 0x05, 0x00));
            return extension;
        }

        it("stays unknown on an empty-OID response extension", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await goodResponseForLeaf(nonce!, {
                extraResponseExtensions: [emptyOidExtension()],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/empty extension OID/);
        });

        it("stays unknown on an empty-OID matching single extension", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await goodResponseForLeaf(nonce!, {
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                        singleExtensions: [emptyOidExtension()],
                    },
                ],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/empty extension OID/);
        });

        it("stays unknown on an empty-OID delegate certificate extension", async () => {
            const marked = await createDelegateResponder(ca, {
                serial: 3921,
                extraExtensions: [emptyOidExtension()],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await delegateGoodResponse(marked, nonce!);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/empty extension OID/);
        });

        it("reports invalid through ValidationSession on an empty-OID response extension", async () => {
            const fetcher = echoResponder({
                signerKeys: ca.keys,
                extraResponseExtensions: [emptyOidExtension()],
            });
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
            });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(result?.errors.join("\n")).toMatch(/empty extension OID/);
        });

        it("ignores valid unknown noncritical OIDs in all three positions (round-9 control)", async () => {
            const marked = await createDelegateResponder(ca, {
                serial: 3922,
                extraExtensions: [unknownExtension("1.2.3.4.5.19", false)],
            });
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: marked.keys,
                responderCert: marked.cert,
                responderId: { form: "byName" },
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "good",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                        singleExtensions: [unknownExtension("1.2.3.4.5.18", false)],
                    },
                ],
                nonceEcho: nonce!,
                extraResponseExtensions: [unknownExtension("1.2.3.4.5.17", false)],
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });
    });

    describe("T09b revocationTime evaluation (item 5)", () => {
        const REVOCATION_BOUNDARY = new Date(THIS_UPDATE.getTime() + CLOCK_SKEW_MS);

        async function revokedResponse(
            revocationTime: Date
        ): Promise<{ response: Uint8Array; requestBytes: Uint8Array }> {
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "revoked",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                        revocationTime,
                    },
                ],
                nonceEcho: nonce!,
            });
            return { response, requestBytes };
        }

        it("reports revoked when revocationTime exactly equals thisUpdate plus skew", async () => {
            const { response, requestBytes } = await revokedResponse(REVOCATION_BOUNDARY);
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("revoked");
            expect(result.errors).toEqual([]);
        });

        it("reports revoked when revocationTime is one millisecond before thisUpdate plus skew", async () => {
            const { response, requestBytes } = await revokedResponse(
                new Date(REVOCATION_BOUNDARY.getTime() - 1)
            );
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("revoked");
            expect(result.errors).toEqual([]);
        });

        it("reports unknown when revocationTime is one millisecond past thisUpdate plus skew", async () => {
            const { response, requestBytes } = await revokedResponse(
                new Date(REVOCATION_BOUNDARY.getTime() + 1)
            );
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/revocationTime/);
        });

        it("reports unknown when revocationTime is far past thisUpdate plus skew", async () => {
            const { response, requestBytes } = await revokedResponse(
                new Date("2027-01-01T00:00:00Z")
            );
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/revocationTime/);
        });

        it.each(["20260230120000Z", "20260230120000.123Z"])(
            "reports unknown on a Feb-30 revocationTime %s instead of normalizing to revoked",
            async (text) => {
                // asn1js parses Feb-30 into a GeneralizedTime (normalizing
                // to Mar-2, inside the freshness window), so the raw octets
                // gate the calendar grammar -- the CRL invalidityDate bar,
                // with the millisecond-fraction tail this compared field
                // requires.
                const { requestBytes, nonce } = await boundRequest();
                const feb30 = new TextEncoder().encode(text).slice().buffer;
                const response = await createSignedOCSPResponse(ca.cert, {
                    signerKeys: ca.keys,
                    producedAt: PRODUCED_AT,
                    responses: [
                        {
                            cert: leaf.cert,
                            issuer: ca.cert,
                            status: "revoked",
                            thisUpdate: THIS_UPDATE,
                            nextUpdate: NEXT_UPDATE,
                            certStatusOverride: new asn1js.Constructed({
                                idBlock: { tagClass: 3, tagNumber: 1 },
                                value: [new asn1js.GeneralizedTime({ valueHex: feb30 })],
                            }),
                        },
                    ],
                    nonceEcho: nonce!,
                });
                const result = await validateDirect(response, { requestBytes });
                expect(result.status).toBe("unknown");
                expect(result.errors.join("\n")).toMatch(/revocationTime/);
            }
        );

        it("treats non-finite and misshapen revocationTime as unknown (direct unit)", async () => {
            // Unreachable via DER (asn1js throws on unparseable
            // GeneralizedTime and serializing an Invalid Date throws
            // too), pinned directly as defense-in-depth.
            const { checkRevocationTime } =
                await import("../../../core/src/pki/ocsp-validation.js");
            const nonFinite = new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 1 },
                value: [new asn1js.GeneralizedTime({ valueDate: new Date(NaN) })],
            });
            expect(checkRevocationTime(nonFinite, THIS_UPDATE, CLOCK_SKEW_MS)).toBe(
                "revocationTime is not a finite date"
            );
            expect(checkRevocationTime(new asn1js.Null(), THIS_UPDATE, CLOCK_SKEW_MS)).toBe(
                "revocationTime has an unsupported shape"
            );
            const feb30 = new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 1 },
                value: [
                    new asn1js.GeneralizedTime({
                        valueHex: new TextEncoder().encode("20260230120000Z").slice().buffer,
                    }),
                ],
            });
            expect(checkRevocationTime(feb30, THIS_UPDATE, CLOCK_SKEW_MS)).toBe(
                "revocationTime is not a canonical calendar date"
            );
            const exact = new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 1 },
                value: [new asn1js.GeneralizedTime({ valueDate: REVOCATION_BOUNDARY })],
            });
            expect(checkRevocationTime(exact, THIS_UPDATE, CLOCK_SKEW_MS)).toBeNull();
        });

        it("evaluates the revocationTime of every matching SingleResponse", async () => {
            const { requestBytes, nonce } = await boundRequest();
            const response = await createSignedOCSPResponse(ca.cert, {
                signerKeys: ca.keys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "revoked",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                        revocationTime: new Date("2026-04-15T00:00:00Z"),
                    },
                    {
                        cert: leaf.cert,
                        issuer: ca.cert,
                        status: "revoked",
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                        revocationTime: new Date("2027-01-01T00:00:00Z"),
                    },
                ],
                nonceEcho: nonce!,
            });
            const result = await validateDirect(response, { requestBytes });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/revocationTime/);
        });
    });
});
