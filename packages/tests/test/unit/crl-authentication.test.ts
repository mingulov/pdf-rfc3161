/* eslint-disable @typescript-eslint/no-deprecated -- compatibility alias coverage */
import { beforeAll, describe, expect, it } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { toArrayBuffer, bytesToHex } from "../../../core/src/utils.js";
import { ValidationSession } from "../../../core/src/pki/validation-session.js";
import { DefaultFetcher } from "../../../core/src/pki/fetchers/default-fetcher.js";
import { MockFetcher } from "../../../core/src/pki/fetchers/mock-fetcher.js";
import { InMemoryValidationCache } from "../../../core/src/pki/fetchers/memory-cache.js";
import type {
    RevocationDataFetcher,
    ValidationCache,
} from "../../../core/src/pki/validation-types.js";
import { TimestampErrorCode } from "../../../core/src/types.js";
import { completeLTVData } from "../../../core/src/pdf/ltv.js";
import {
    OPENSSL_INTEROP_CA_BASE64,
    OPENSSL_INTEROP_EMPTY_CRL_BASE64,
    OPENSSL_INTEROP_LEAF_BASE64,
    OPENSSL_INTEROP_REVOKED_CRL_BASE64,
    decodeInteropDer,
} from "../fixtures/openssl-crl-interop.js";
import {
    akiExtension,
    certificateIssuerExtension,
    createSignedCRL,
    createSignedOCSPResponse,
    createTestCA,
    createTestLeaf,
    corruptCRLSignature,
    crlDistributionPointsExtensionFromPoints,
    crlNumberExtension,
    deltaCrlIndicatorExtension,
    directoryNameGeneralName,
    generateECKeyPair,
    holdInstructionExtension,
    inspectOCSPRequest,
    invalidityDateExtension,
    issuingDistributionPointExtension,
    keyUsageExtension,
    rawKeyUsageExtension,
    rawReasonFlagsContent,
    reasonCodeExtension,
    reasonFlagsBitString,
    unknownExtension,
    type CrlEntrySpec,
    type SignedCRLOptions,
    type TestCertificateAuthority,
    type TestKeyPair,
    type TestLeaf,
} from "../fixtures/signed-revocation-material.js";

// T07: CRL evidence is authenticated (R1/R20/R21). Only a CRL that is
// issued directly by the T05-verified issuer key, in scope for the
// certificate distribution point, fresh at the check date, and completely
// consumed yields good/revoked. Everything else -- wrong key, forged
// signature, stale/future/missing dates, missing cRLSign, unknown
// critical extensions, scope mismatch, indirect/partitioned/delta CRLs --
// stays unknown with diagnostics, never good-by-absence. No verdict
// parser is mocked in this file: every CRL carries real keys and real
// signatures round-tripped through DER.

const CRL_URL = "http://crl.example.com/ca.crl";
const CRL_URL_2 = "http://crl.example.com/ca2.crl";
const OCSP_URL = "http://ocsp.example.com/";

// Fixed policy clock so every time boundary is deterministic. CRL dates
// are whole seconds (UTCTime); 1 ms edges are pinned by shifting the
// check date, the T06 F6 technique.
const CHECK_DATE = new Date("2026-05-01T12:00:00Z");
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const THIS_UPDATE = new Date("2026-05-01T11:00:00Z");
const NEXT_UPDATE = new Date("2026-05-02T11:00:00Z");

type CrlValidationModule = typeof import("../../../core/src/pki/crl-validation.js");

/**
 * Loads the T07 validator. On BASE the module does not exist, so the
 * import rejects and the test fails with an assertion (module absence),
 * not an infrastructure error -- the T06 red discipline for a new module.
 */
async function expectValidator(): Promise<CrlValidationModule> {
    const loaded = await import("../../../core/src/pki/crl-validation.js").catch(
        () => null as CrlValidationModule | null
    );
    expect(loaded, "validateCRLEvidence module exists (T07 implementation)").not.toBeNull();
    expect(typeof loaded?.validateCRLEvidence).toBe("function");
    return loaded!;
}

function concatBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
    const out = new Uint8Array(left.length + right.length);
    out.set(left, 0);
    out.set(right, left.length);
    return out;
}

/** Parses outer CRL framing; throws on anything but a 3-child SEQUENCE. */
function parseOuterCrl(crlBytes: Uint8Array): asn1js.Sequence {
    const asn1 = asn1js.fromBER(toArrayBuffer(crlBytes.slice()));
    if (asn1.offset === -1 || !(asn1.result instanceof asn1js.Sequence)) {
        throw new Error("CRL is not DER");
    }
    if (asn1.result.valueBlock.value.length !== 3) throw new Error("CRL framing is not 3-child");
    return asn1.result;
}

function outerChild(outer: asn1js.Sequence, index: number): asn1js.BaseBlock {
    const child = outer.valueBlock.value[index];
    if (!child) throw new Error("CRL outer child is missing");
    return child;
}

/**
 * Reassembles outer CRL framing from nodes. asn1js re-emits a mutated
 * retained SEQUENCE with its original length FORM (an outer that shrank
 * below 128 bytes keeps a stale long-form length), so every surgery
 * helper rebuilds ancestors fresh: children re-emit verbatim, lengths
 * stay minimal, and only the intended malformation survives.
 */
function rebuildOuterCrl(
    tbs: asn1js.BaseBlock,
    sigAlg: asn1js.BaseBlock,
    signature: asn1js.BaseBlock
): Uint8Array {
    const outer = new asn1js.Sequence({ value: [tbs, sigAlg, signature] });
    return new Uint8Array(outer.toBER(false));
}

/** Replaces the outer signatureAlgorithm OID, keeping TBS+signature bytes. */
function crlWithOuterSigAlgOid(crlBytes: Uint8Array, oid: string): Uint8Array {
    const outer = parseOuterCrl(crlBytes);
    const outerAlg = outerChild(outer, 1);
    if (!(outerAlg instanceof asn1js.Sequence)) throw new Error("outer signatureAlgorithm");
    const algOid = outerAlg.valueBlock.value[0];
    if (!(algOid instanceof asn1js.ObjectIdentifier)) throw new Error("outer OID");
    outerAlg.valueBlock.value[0] = new asn1js.ObjectIdentifier({ value: oid });
    const freshAlg = new asn1js.Sequence({ value: [...outerAlg.valueBlock.value] });
    return rebuildOuterCrl(outerChild(outer, 0), freshAlg, outerChild(outer, 2));
}

/** Replaces the signatureValue BIT STRING with attacker-chosen raw DER. */
function crlWithSignatureBits(crlBytes: Uint8Array, bitStringDer: Uint8Array): Uint8Array {
    const outer = parseOuterCrl(crlBytes);
    const parsed = asn1js.fromBER(toArrayBuffer(bitStringDer.slice()));
    if (parsed.offset === -1 || !(parsed.result instanceof asn1js.BitString)) {
        throw new Error("replacement signature is not a BIT STRING");
    }
    return rebuildOuterCrl(outerChild(outer, 0), outerChild(outer, 1), parsed.result);
}

function bitStringDer(unusedBits: number, data: Uint8Array): Uint8Array {
    const contentLength = data.length + 1;
    const lengthBytes =
        contentLength < 0x80
            ? [contentLength]
            : [
                  0x80 | (contentLength > 0xff ? 2 : 1),
                  ...(contentLength > 0xff
                      ? [(contentLength >> 8) & 0xff, contentLength & 0xff]
                      : [contentLength & 0xff]),
              ];
    const out = new Uint8Array(1 + lengthBytes.length + 1 + data.length);
    out[0] = 0x03;
    out.set(lengthBytes, 1);
    out[1 + lengthBytes.length] = unusedBits;
    out.set(data, 1 + lengthBytes.length + 1);
    return out;
}

/**
 * Re-signs a CRL over mutated TBS bytes with a real RSA key: parses the
 * outer framing, lets the test mutate the TBSCertList children, then
 * signs the re-encoded TBS with WebCrypto and splices the fresh
 * signatureValue back. The malformation is genuinely signed. TBS and
 * outer are rebuilt fresh so ancestor lengths stay minimal no matter
 * how the mutation resized them (see rebuildOuterCrl).
 */
async function resignCrlTbs(
    crlBytes: Uint8Array,
    mutateTbs: (tbsChildren: asn1js.BaseBlock[]) => void,
    signerKeys: TestKeyPair
): Promise<Uint8Array> {
    if (signerKeys.privateKey.algorithm.name !== "RSASSA-PKCS1-v1_5") {
        throw new Error("resignCrlTbs supports RSA keys only");
    }
    const outer = parseOuterCrl(crlBytes);
    const tbs = outerChild(outer, 0);
    if (!(tbs instanceof asn1js.Sequence)) throw new Error("TBSCertList is not a SEQUENCE");
    mutateTbs(tbs.valueBlock.value);
    const freshTbs = new asn1js.Sequence({ value: [...tbs.valueBlock.value] });
    const tbsBytes = new Uint8Array(freshTbs.toBER(false));
    const signature = await globalThis.crypto.subtle.sign(
        { name: "RSASSA-PKCS1-v1_5" },
        signerKeys.privateKey,
        toArrayBuffer(tbsBytes)
    );
    return rebuildOuterCrl(
        freshTbs,
        outerChild(outer, 1),
        new asn1js.BitString({ valueHex: signature })
    );
}

/** Finds the issuer RDNSequence inside TBSCertList children. */
function issuerNameNode(tbsChildren: asn1js.BaseBlock[]): asn1js.Sequence {
    for (const child of tbsChildren) {
        if (!(child instanceof asn1js.Sequence)) continue;
        const members = child.valueBlock.value;
        if (members.length > 0 && members.every((member) => member instanceof asn1js.Set)) {
            return child;
        }
    }
    throw new Error("CRL issuer name not found in TBS");
}

/** Finds the revokedCertificates SEQ OF inside TBSCertList children. */
function revokedCertificatesNode(tbsChildren: asn1js.BaseBlock[]): asn1js.Sequence {
    for (const child of tbsChildren) {
        if (!(child instanceof asn1js.Sequence)) continue;
        const first = child.valueBlock.value[0];
        if (
            first instanceof asn1js.Sequence &&
            first.valueBlock.value[0] instanceof asn1js.Integer
        ) {
            return child;
        }
    }
    throw new Error("revokedCertificates not found in TBS");
}

/** Parses one Extension SEQUENCE from raw wire bytes (pins the exact attack bytes). */
function extensionNodeFromDer(wire: number[]): asn1js.BaseBlock {
    const parsed = asn1js.fromBER(new Uint8Array(wire).slice().buffer);
    if (parsed.offset === -1 || parsed.offset !== wire.length) {
        throw new Error("extension fixture is not DER");
    }
    return parsed.result;
}

/** The T06 round-9 attack bytes: empty OID, noncritical, NULL payload. */
function emptyOidExtensionNode(): asn1js.BaseBlock {
    return extensionNodeFromDer([0x30, 0x06, 0x06, 0x00, 0x04, 0x02, 0x05, 0x00]);
}

/** Wraps one Extension node in a [0] EXPLICIT Extensions wrapper. */
function extensionsWrapperWith(extension: asn1js.BaseBlock): asn1js.Constructed {
    return new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [new asn1js.Sequence({ value: [extension] })],
    });
}

/** Finds the [0] EXPLICIT crlExtensions wrapper inside TBSCertList children. */
function crlExtensionsNode(tbsChildren: asn1js.BaseBlock[]): asn1js.Constructed {
    for (const child of tbsChildren) {
        if (
            child instanceof asn1js.Constructed &&
            child.idBlock.tagClass === 3 &&
            child.idBlock.tagNumber === 0
        ) {
            return child;
        }
    }
    throw new Error("crlExtensions wrapper not found in TBS");
}

/**
 * Builds a genuinely RSA-signed CRL whose inner and outer signature
 * AlgorithmIdentifiers both carry explicit NULL parameters (the
 * real-world CA shape; pkijs sign() emits absent parameters).
 */
async function createRsaCrlWithNullParams(
    issuer: TestCertificateAuthority,
    options: { entries?: CrlEntrySpec[]; crlExtensions?: pkijs.Extension[] }
): Promise<Uint8Array> {
    const nullAlg = (): pkijs.AlgorithmIdentifier =>
        new pkijs.AlgorithmIdentifier({
            algorithmId: "1.2.840.113549.1.1.11",
            algorithmParams: new asn1js.Null(),
        });
    const revokedCertificates = (options.entries ?? []).map(
        (entry) =>
            new pkijs.RevokedCertificate({
                userCertificate: new asn1js.Integer({ value: entry.serial ?? 2001 }),
                revocationDate: new pkijs.Time({
                    value: entry.revocationDate ?? new Date("2026-04-01T00:00:00Z"),
                }),
            })
    );
    const crl = new pkijs.CertificateRevocationList({
        version: options.crlExtensions === undefined ? 0 : 1,
        signature: nullAlg(),
        issuer: issuer.cert.subject,
        thisUpdate: new pkijs.Time({ value: THIS_UPDATE }),
        nextUpdate: new pkijs.Time({ value: NEXT_UPDATE }),
        ...(revokedCertificates.length === 0 ? {} : { revokedCertificates }),
        ...(options.crlExtensions === undefined
            ? {}
            : {
                  crlExtensions: new pkijs.Extensions({
                      extensions: options.crlExtensions,
                  }),
              }),
        signatureAlgorithm: nullAlg(),
        signatureValue: new asn1js.BitString({ valueHex: new Uint8Array(256).buffer }),
    });
    const tbsBytes = new Uint8Array(
        (crl as unknown as { encodeTBS(): asn1js.Sequence }).encodeTBS().toBER(false)
    );
    const signature = await globalThis.crypto.subtle.sign(
        { name: "RSASSA-PKCS1-v1_5" },
        issuer.keys.privateKey,
        toArrayBuffer(tbsBytes)
    );
    crl.signatureValue = new asn1js.BitString({ valueHex: signature });
    return new Uint8Array(crl.toSchema(true).toBER(false));
}

function recordingFetcher(responses: {
    ocsp?: Uint8Array | ((request: Uint8Array) => Promise<Uint8Array>);
    crl?: Uint8Array | ((url: string) => Promise<Uint8Array>);
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
            if (typeof responses.ocsp === "function") return responses.ocsp(request);
            if (!responses.ocsp) return Promise.reject(new Error("no OCSP response"));
            return Promise.resolve(responses.ocsp);
        },
        fetchCRL: (url: string) => {
            fetcher.crlCalls += 1;
            if (typeof responses.crl === "function") return responses.crl(url);
            if (!responses.crl) return Promise.reject(new Error("no CRL response"));
            return Promise.resolve(responses.crl);
        },
    };
    return fetcher;
}

describe("CRL authentication (T07)", () => {
    let ca: TestCertificateAuthority;
    let leaf: TestLeaf;
    let bothLeaf: TestLeaf;
    let ecCA: TestCertificateAuthority;
    let ecLeaf: TestLeaf;
    let wrongCA: TestCertificateAuthority;
    let noCrlSignCA: TestCertificateAuthority;
    let crlSignCA: TestCertificateAuthority;
    let crlSignLeaf: TestLeaf;

    beforeAll(async () => {
        ca = await createTestCA("T07 Test CA", { serial: 1001, ski: new Uint8Array([0xaa, 0xbb]) });
        leaf = await createTestLeaf(ca, { serial: 2001, crlUrls: [CRL_URL] });
        bothLeaf = await createTestLeaf(ca, {
            commonName: "T07 Both Leaf",
            serial: 2003,
            ocspUrl: OCSP_URL,
            crlUrls: [CRL_URL],
        });
        ecCA = await createTestCA("T07 EC CA", { serial: 1011, keys: await generateECKeyPair() });
        ecLeaf = await createTestLeaf(ecCA, { serial: 2101, crlUrls: [CRL_URL] });
        wrongCA = await createTestCA("T07 Wrong CA", { serial: 9001 });
        // Key usage without the cRLSign bit (keyCertSign only).
        noCrlSignCA = await createTestCA("T07 No CRLSign CA", {
            serial: 1021,
            keyUsage: new Uint8Array([0x04]),
        });
        // Key usage with keyCertSign + cRLSign.
        crlSignCA = await createTestCA("T07 CRLSign CA", {
            serial: 1031,
            keyUsage: new Uint8Array([0x06]),
        });
        crlSignLeaf = await createTestLeaf(crlSignCA, { serial: 2301, crlUrls: [CRL_URL] });
    }, 60000);

    async function validateDirect(
        crlBytes: Uint8Array,
        options: {
            cert?: pkijs.Certificate;
            issuer?: pkijs.Certificate;
            checkDate?: Date;
            clockSkewMs?: number;
        } = {}
    ) {
        const validator = await expectValidator();
        return validator.validateCRLEvidence(crlBytes, {
            cert: options.cert ?? leaf.cert,
            issuer: options.issuer ?? ca.cert,
            checkDate: options.checkDate ?? CHECK_DATE,
            clockSkewMs: options.clockSkewMs ?? CLOCK_SKEW_MS,
        });
    }

    async function freshCRL(
        issuer: TestCertificateAuthority,
        options: Partial<SignedCRLOptions> = {}
    ): Promise<Uint8Array> {
        return createSignedCRL(issuer, {
            thisUpdate: THIS_UPDATE,
            nextUpdate: NEXT_UPDATE,
            ...options,
        });
    }

    describe("validateCRLEvidence positives", () => {
        it("reports revoked for a listed serial", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 2001 }] });
            const result = await validateDirect(crl);
            expect(result.status).toBe("revoked");
            expect(result.source).toBe("CRL");
            expect(result.errors).toEqual([]);
        });

        it("reports unknown for a listed serial with a future revocationDate (T09b)", async () => {
            // T09b closes the documented deferral: a matching revoked
            // entry now requires a finite revocationDate no later than
            // thisUpdate plus skew (MIGRATION "revocationDate is now
            // evaluated"). A 2027 revocation instant against a 2026
            // thisUpdate fails that bound.
            const crl = await freshCRL(ca, {
                entries: [{ serial: 2001, revocationDate: new Date("2027-01-01T00:00:00Z") }],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.source).toBe("CRL");
            expect(result.errors.join("\n")).toMatch(/revocationDate/);
        });

        it("reports good for an unlisted serial", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl);
            expect(result.status).toBe("good");
            expect(result.source).toBe("CRL");
            expect(result.errors).toEqual([]);
        });

        it("reports good for an empty revokedCertificates CRL", async () => {
            const crl = await freshCRL(ca, {});
            const result = await validateDirect(crl);
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts a v1 CRL without extensions", async () => {
            const listed = await freshCRL(ca, { version: 0, entries: [{ serial: 2001 }] });
            expect((await validateDirect(listed)).status).toBe("revoked");
            const unlisted = await freshCRL(ca, { version: 0, entries: [{ serial: 9999 }] });
            const result = await validateDirect(unlisted);
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts an ECDSA-signed CRL", async () => {
            const crl = await freshCRL(ecCA, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: ecLeaf.cert, issuer: ecCA.cert });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts recognized CRL extensions (number, AKI, empty IDP)", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [
                    crlNumberExtension(7),
                    akiExtension(new Uint8Array([0xaa, 0xbb])),
                    issuingDistributionPointExtension(new pkijs.IssuingDistributionPoint({})),
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("reports revoked with valid verdict-neutral entry extensions", async () => {
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [
                            reasonCodeExtension(1),
                            holdInstructionExtension("1.2.3.4.5"),
                            invalidityDateExtension(new Date("2026-03-01T00:00:00Z")),
                        ],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("revoked");
            expect(result.errors).toEqual([]);
        });

        it("reports revoked when the entry certificateIssuer names the issuer", async () => {
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [
                            certificateIssuerExtension([directoryNameGeneralName(ca.cert.subject)]),
                        ],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("revoked");
            expect(result.errors).toEqual([]);
        });

        it("accepts RSA signatures with explicit NULL parameters", async () => {
            const crl = await createRsaCrlWithNullParams(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl);
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });
    });

    describe("validateCRLEvidence signatures and issuer binding", () => {
        it("rejects a CRL signed by the wrong key", async () => {
            const crl = await freshCRL(ca, {
                signerKeys: wrongCA.keys,
                entries: [{ serial: 9999 }],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/signature/i);
        });

        it("rejects a CRL issued under the wrong issuer name", async () => {
            const crl = await freshCRL(wrongCA, {
                crlIssuerCert: wrongCA.cert,
                entries: [{ serial: 9999 }],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/issuer/i);
        });

        it("rejects a corrupted signature while the genuine twin validates", async () => {
            const genuine = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const forged = corruptCRLSignature(genuine);
            expect(forged).not.toEqual(genuine);
            const forgedResult = await validateDirect(forged);
            expect(forgedResult.status).toBe("unknown");
            expect(forgedResult.errors.join("\n")).toMatch(/signature/i);
            // Differential control: the same TBS with the genuine signature validates.
            const genuineResult = await validateDirect(genuine);
            expect(genuineResult.status).toBe("good");
        });

        it("rejects inconsistent inner/outer signature algorithms", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const relabelled = crlWithOuterSigAlgOid(crl, "1.2.840.10045.4.3.2");
            const result = await validateDirect(relabelled);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/consistent/i);
        });

        it("rejects a PSS algorithm label on an RSA-signed CRL", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const relabelled = crlWithOuterSigAlgOid(crl, "1.2.840.113549.1.1.10");
            const result = await validateDirect(relabelled);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/PSS|compatible|consistent/i);
        });

        it("rejects ECDSA signatures with NULL parameters", async () => {
            const crl = await freshCRL(ecCA, { entries: [{ serial: 9999 }] });
            // Splice a NULL into the outer ECDSA AlgorithmIdentifier.
            const outer = parseOuterCrl(crl);
            const outerAlg = outerChild(outer, 1);
            if (!(outerAlg instanceof asn1js.Sequence)) throw new Error("outer alg");
            outerAlg.valueBlock.value.push(new asn1js.Null());
            const freshAlg = new asn1js.Sequence({ value: [...outerAlg.valueBlock.value] });
            const mutated = rebuildOuterCrl(outerChild(outer, 0), freshAlg, outerChild(outer, 2));
            const result = await validateDirect(mutated, {
                cert: ecLeaf.cert,
                issuer: ecCA.cert,
            });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/parameter|consistent/i);
        });

        it("rejects non-octet-aligned signature BIT STRINGs", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const outer = parseOuterCrl(crl);
            const signatureValue = outerChild(outer, 2);
            if (!(signatureValue instanceof asn1js.BitString)) throw new Error("signature");
            const data = new Uint8Array(signatureValue.valueBlock.valueHexView);
            for (const unusedBits of [1, 7]) {
                const mutated = crlWithSignatureBits(crl, bitStringDer(unusedBits, data));
                const result = await validateDirect(mutated);
                expect(result.status).toBe("unknown");
                expect(result.errors.join("\n")).toMatch(/octet-aligned|BIT STRING/i);
            }
        });

        it("rejects an empty signature BIT STRING", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const mutated = crlWithSignatureBits(crl, new Uint8Array([0x03, 0x01, 0x00]));
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/empty|signature/i);
        });

        it("rejects a constructed signature BIT STRING", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const outer = parseOuterCrl(crl);
            const signatureValue = outerChild(outer, 2);
            if (!(signatureValue instanceof asn1js.BitString)) throw new Error("signature");
            const data = new Uint8Array(signatureValue.valueBlock.valueHexView);
            // Constructed BIT STRING wrapping one primitive segment.
            const segment = new asn1js.BitString({ valueHex: toArrayBuffer(data) });
            const constructed = new asn1js.Constructed({
                idBlock: { tagClass: 1, tagNumber: 3 },
                value: [segment],
            });
            const mutated = rebuildOuterCrl(
                outerChild(outer, 0),
                outerChild(outer, 1),
                constructed
            );
            const result = await validateDirect(mutated);
            // pkijs schema verification rejects the constructed BIT STRING
            // before the strict framing gate runs; either way unknown.
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/parse|primitive|BIT STRING/i);
        });

        it("rejects an ECDSA signature with trailing garbage", async () => {
            const crl = await freshCRL(ecCA, { entries: [{ serial: 9999 }] });
            const outer = parseOuterCrl(crl);
            const signatureValue = outerChild(outer, 2);
            if (!(signatureValue instanceof asn1js.BitString)) throw new Error("signature");
            const data = new Uint8Array(signatureValue.valueBlock.valueHexView);
            const garbage = concatBytes(data, new Uint8Array([0x05, 0x00]));
            const mutated = crlWithSignatureBits(crl, bitStringDer(0, garbage));
            const result = await validateDirect(mutated, {
                cert: ecLeaf.cert,
                issuer: ecCA.cert,
            });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/malformed|ECDSA|signature/i);
        });
    });

    describe("validateCRLEvidence freshness", () => {
        it("pins the thisUpdate future edge at 1 ms", async () => {
            // thisUpdate exactly at checkDate + skew is fresh; 1 ms later it is future.
            const thisUpdate = new Date(CHECK_DATE.getTime() + CLOCK_SKEW_MS);
            const crl = await createSignedCRL(ca, {
                thisUpdate,
                nextUpdate: new Date(thisUpdate.getTime() + 24 * 60 * 60 * 1000),
                entries: [{ serial: 9999 }],
            });
            const fresh = await validateDirect(crl);
            expect(fresh.status).toBe("good");
            const future = await validateDirect(crl, {
                checkDate: new Date(CHECK_DATE.getTime() - 1),
            });
            expect(future.status).toBe("unknown");
            expect(future.errors.join("\n")).toMatch(/after the check date/);
        });

        it("pins the nextUpdate staleness edge at 1 ms", async () => {
            // nextUpdate exactly at checkDate - skew is fresh; 1 ms earlier it is stale.
            const nextUpdate = new Date(CHECK_DATE.getTime() - CLOCK_SKEW_MS);
            const crl = await createSignedCRL(ca, {
                thisUpdate: new Date(nextUpdate.getTime() - 24 * 60 * 60 * 1000),
                nextUpdate,
                entries: [{ serial: 9999 }],
            });
            const fresh = await validateDirect(crl);
            expect(fresh.status).toBe("good");
            const stale = await validateDirect(crl, {
                checkDate: new Date(CHECK_DATE.getTime() + 1),
            });
            expect(stale.status).toBe("unknown");
            expect(stale.errors.join("\n")).toMatch(/stale/);
        });

        it("rejects an inverted freshness window (nextUpdate before thisUpdate)", async () => {
            // Shaped so the staleness gate alone would pass: the inversion
            // itself must fire (T06 F1 precedent).
            const crl = await createSignedCRL(ca, {
                thisUpdate: new Date("2026-05-01T11:58:00Z"),
                nextUpdate: new Date("2026-05-01T11:56:00Z"),
                entries: [{ serial: 9999 }],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/nextUpdate is before thisUpdate/);
        });

        it("rejects a CRL without nextUpdate (freshness unbounded)", async () => {
            const crl = await createSignedCRL(ca, {
                thisUpdate: THIS_UPDATE,
                entries: [{ serial: 9999 }],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/no nextUpdate/);
        });
    });

    describe("validateCRLEvidence issuer key usage", () => {
        it("accepts an issuer key usage with cRLSign", async () => {
            const crl = await freshCRL(crlSignCA, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, {
                cert: crlSignLeaf.cert,
                issuer: crlSignCA.cert,
            });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("rejects an issuer key usage without cRLSign", async () => {
            const noSignLeaf = await createTestLeaf(noCrlSignCA, {
                serial: 2201,
                crlUrls: [CRL_URL],
            });
            const crl = await freshCRL(noCrlSignCA, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, {
                cert: noSignLeaf.cert,
                issuer: noCrlSignCA.cert,
            });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/cRLSign/);
        });

        it("rejects a malformed issuer key usage", async () => {
            // Seven declared unused bits carrying nonzero padding.
            const badCA = await createTestCA("T07 Bad KU CA", { serial: 1041 });
            const badLeaf = await createTestLeaf(badCA, { serial: 2401, crlUrls: [CRL_URL] });
            const badIssuer = badCA.cert;
            const extensions = [...(badIssuer.extensions ?? [])];
            extensions.push(rawKeyUsageExtension(new Uint8Array([0x03, 0x02, 0x07, 0x06]).buffer));
            badIssuer.extensions = extensions;
            const crl = await freshCRL(badCA, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, {
                cert: badLeaf.cert,
                issuer: badIssuer,
            });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/cRLSign|key usage/i);
        });

        it("rejects a duplicate issuer key usage", async () => {
            const dupCA = await createTestCA("T07 Dup KU CA", {
                serial: 1051,
                keyUsage: new Uint8Array([0x06]),
            });
            const dupLeaf = await createTestLeaf(dupCA, { serial: 2501, crlUrls: [CRL_URL] });
            const dupIssuer = dupCA.cert;
            dupIssuer.extensions = [
                ...(dupIssuer.extensions ?? []),
                keyUsageExtension(new Uint8Array([0x06])),
            ];
            const crl = await freshCRL(dupCA, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, {
                cert: dupLeaf.cert,
                issuer: dupIssuer,
            });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/duplicate key usage/i);
        });
    });

    describe("validateCRLEvidence critical extensions", () => {
        it("rejects an unknown critical CRL extension", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [unknownExtension("1.2.3.4444", true)],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/unsupported critical extension/);
        });

        it("ignores an unknown non-critical CRL extension", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [unknownExtension("1.2.3.4444", false)],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("rejects an unknown critical extension on the matching entry", async () => {
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [unknownExtension("1.2.3.4444", true)],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/unsupported critical extension/);
        });

        it("ignores an unknown non-critical extension on the matching entry", async () => {
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [unknownExtension("1.2.3.4444", false)],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("revoked");
            expect(result.errors).toEqual([]);
        });

        it("rejects unknown critical extensions on non-matching entries", async () => {
            // RFC 5280 5.3: a CRL carrying a critical entry extension the
            // application cannot process MUST NOT be used for ANY
            // certificate -- non-matching entries gate the whole CRL
            // (T07 fix round 2 reverses the old ignore-the-rest rule).
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 9999,
                        entryExtensions: [unknownExtension("1.2.3.4444", true)],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/unsupported critical extension/);
        });

        it("rejects an empty extension OID at the CRL level", async () => {
            // pkijs decodes 06 00 as extnID ""; build the wire bytes directly.
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const mutated = await resignCrlTbs(
                crl,
                (tbsChildren) => {
                    // v1 CRL here (no extensions): insert version 1 first.
                    tbsChildren.unshift(new asn1js.Integer({ value: 1 }));
                    tbsChildren.push(extensionsWrapperWith(emptyOidExtensionNode()));
                },
                ca.keys
            );
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/empty extension OID/);
        });

        it("rejects an empty extension OID on the matching entry", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 2001 }] });
            const mutated = await resignCrlTbs(
                crl,
                (tbsChildren) => {
                    const revoked = revokedCertificatesNode(tbsChildren);
                    const entry = revoked.valueBlock.value[0];
                    if (!(entry instanceof asn1js.Sequence)) throw new Error("entry");
                    // Entry extensions are a BARE Extensions SEQUENCE (RFC
                    // 5280 5.1.2.6) -- no [0] tag, unlike CRL-level
                    // extensions. The [0]-wrapped twin is rejected outright.
                    entry.valueBlock.value.push(
                        new asn1js.Sequence({ value: [emptyOidExtensionNode()] })
                    );
                    tbsChildren.unshift(new asn1js.Integer({ value: 1 }));
                },
                ca.keys
            );
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/empty extension OID/);
        });
    });

    describe("validateCRLEvidence recognized CRL extensions", () => {
        function rawCrlNumberExtension(valueDer: number[], critical = false): pkijs.Extension {
            return new pkijs.Extension({
                extnID: "2.5.29.20",
                critical,
                extnValue: new Uint8Array(valueDer).slice().buffer,
            });
        }

        function rawAkiExtension(valueDer: number[], critical = false): pkijs.Extension {
            return new pkijs.Extension({
                extnID: "2.5.29.35",
                critical,
                extnValue: new Uint8Array(valueDer).slice().buffer,
            });
        }

        it("rejects a malformed CRL number", async () => {
            // INTEGER 7 with a trailing garbage octet inside extnValue.
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [rawCrlNumberExtension([0x02, 0x01, 0x07, 0x00])],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/CRL number/i);
        });

        it("rejects a negative CRL number", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [rawCrlNumberExtension([0x02, 0x01, 0xff])],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/CRL number/i);
        });

        it("rejects duplicate CRL numbers", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [crlNumberExtension(7), crlNumberExtension(8)],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/duplicate CRL number/i);
        });

        it("rejects an authority key identifier that mismatches the issuer", async () => {
            const mismatched = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [akiExtension(new Uint8Array([0xcc, 0xdd]))],
            });
            const result = await validateDirect(mismatched);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/authority key identifier/i);
        });

        it("rejects a malformed authority key identifier", async () => {
            // KeyIdentifier [0] OCTET STRING with trailing garbage.
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [rawAkiExtension([0x30, 0x07, 0x80, 0x02, 0xaa, 0xbb, 0x05, 0x00])],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/authority key identifier/i);
        });

        it("rejects a critical AKI with no processable key identifier", async () => {
            // Empty AKI SEQUENCE: parses, but binds nothing.
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [rawAkiExtension([0x30, 0x00], true)],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/authority key identifier/i);
        });

        it("ignores a non-critical AKI with no key identifier", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [rawAkiExtension([0x30, 0x00], false)],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts a critical AKI with a matching key identifier", async () => {
            const matched = akiExtension(new Uint8Array([0xaa, 0xbb]));
            matched.critical = true;
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [matched],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("rejects a critical AKI with unprocessed authorityCertSerialNumber", async () => {
            // The key identifier matches, but a critical AKI must be
            // recognized AND processed: the serial-number content is
            // not, so the CRL fails closed.
            const aki = new pkijs.AuthorityKeyIdentifier({
                keyIdentifier: new asn1js.OctetString({
                    valueHex: new Uint8Array([0xaa, 0xbb]).slice().buffer,
                }),
                authorityCertSerialNumber: new asn1js.Integer({ value: 1001 }),
            });
            const critical = new pkijs.Extension({
                extnID: "2.5.29.35",
                critical: true,
                extnValue: aki.toSchema().toBER(false),
            });
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [critical],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/unprocessed critical content/);
        });

        it("rejects duplicate authority key identifiers", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [
                    akiExtension(new Uint8Array([0xaa, 0xbb])),
                    akiExtension(new Uint8Array([0xaa, 0xbb])),
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/duplicate authority key identifier/i);
        });
    });

    describe("validateCRLEvidence scope binding", () => {
        it("rejects an indirect CRL", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [
                    issuingDistributionPointExtension(
                        new pkijs.IssuingDistributionPoint({ indirectCRL: true })
                    ),
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/indirect/i);
        });

        it("rejects partitioned CRLs (user-only, CA-only, reasons, name, attribute)", async () => {
            const partitioned = [
                new pkijs.IssuingDistributionPoint({ onlyContainsUserCerts: true }),
                new pkijs.IssuingDistributionPoint({ onlyContainsCACerts: true }),
                new pkijs.IssuingDistributionPoint({ onlySomeReasons: 4 }),
                new pkijs.IssuingDistributionPoint({
                    distributionPoint: [new pkijs.GeneralName({ type: 6, value: CRL_URL })],
                }),
                new pkijs.IssuingDistributionPoint({ onlyContainsAttributeCerts: true }),
            ];
            for (const idp of partitioned) {
                const crl = await freshCRL(ca, {
                    entries: [{ serial: 9999 }],
                    crlExtensions: [issuingDistributionPointExtension(idp)],
                });
                const result = await validateDirect(crl);
                expect(result.status).toBe("unknown");
                expect(result.errors.join("\n")).toMatch(/partition|scope|support/i);
            }
        });

        it("rejects a malformed issuing distribution point", async () => {
            // onlyContainsUserCerts TRUE with a trailing NULL member.
            const malformed = new pkijs.Extension({
                extnID: "2.5.29.28",
                critical: false,
                extnValue: new Uint8Array([0x30, 0x05, 0x81, 0x01, 0xff, 0x05, 0x00]).slice()
                    .buffer,
            });
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [malformed],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/issuing distribution point/i);
        });

        it("rejects an IDP with an explicitly encoded DEFAULT FALSE", async () => {
            // DER omits DEFAULT values: 81 01 00 is non-canonical.
            const nonCanonical = new pkijs.Extension({
                extnID: "2.5.29.28",
                critical: false,
                extnValue: new Uint8Array([0x30, 0x03, 0x81, 0x01, 0x00]).slice().buffer,
            });
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [nonCanonical],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/issuing distribution point/i);
        });

        it("rejects duplicate issuing distribution points", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [
                    issuingDistributionPointExtension(new pkijs.IssuingDistributionPoint({})),
                    issuingDistributionPointExtension(new pkijs.IssuingDistributionPoint({})),
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/duplicate issuing distribution point/i);
        });

        it("rejects a certificate whose distribution points all name another CRL issuer", async () => {
            const scopedLeaf = await createTestLeaf(ca, {
                commonName: "T07 Scoped Leaf",
                serial: 2601,
                crlDPExtension: crlDistributionPointsExtensionFromPoints([
                    new pkijs.DistributionPoint({
                        distributionPoint: [new pkijs.GeneralName({ type: 6, value: CRL_URL })],
                        cRLIssuer: [directoryNameGeneralName(wrongCA.cert.subject)],
                    }),
                ]),
            });
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: scopedLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/distribution point|scope/i);
        });

        it("rejects a distribution point whose cRLIssuer names the issuer", async () => {
            // RFC 5280 6.3.3(b)(1): a cRLIssuer-bearing point needs an
            // indirect CRL, which is outside the direct-only profile --
            // even when it names the verified issuer (conforming CAs
            // MUST omit that redundant field, RFC 5280 4.2.1.13; T07
            // fix round 2 reverses the old same-issuer acceptance).
            const scopedLeaf = await createTestLeaf(ca, {
                commonName: "T07 Scoped Leaf",
                serial: 2602,
                crlDPExtension: crlDistributionPointsExtensionFromPoints([
                    new pkijs.DistributionPoint({
                        distributionPoint: [new pkijs.GeneralName({ type: 6, value: CRL_URL })],
                        cRLIssuer: [directoryNameGeneralName(ca.cert.subject)],
                    }),
                ]),
            });
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: scopedLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/distribution point|scope/i);
        });

        it("accepts one in-scope distribution point after an out-of-scope one", async () => {
            const scopedLeaf = await createTestLeaf(ca, {
                commonName: "T07 Multi DP Leaf",
                serial: 2603,
                crlDPExtension: crlDistributionPointsExtensionFromPoints([
                    new pkijs.DistributionPoint({
                        distributionPoint: [new pkijs.GeneralName({ type: 6, value: CRL_URL_2 })],
                        cRLIssuer: [directoryNameGeneralName(wrongCA.cert.subject)],
                    }),
                    new pkijs.DistributionPoint({
                        distributionPoint: [new pkijs.GeneralName({ type: 6, value: CRL_URL })],
                    }),
                ]),
            });
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: scopedLeaf.cert });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("accepts distribution-point reasons against a full CRL", async () => {
            // The DP covers keyCompromise only; a full CRL covers every
            // reason, so the scope-subset relation holds.
            const scopedLeaf = await createTestLeaf(ca, {
                commonName: "T07 Reasons Leaf",
                serial: 2604,
                crlDPExtension: crlDistributionPointsExtensionFromPoints([
                    new pkijs.DistributionPoint({
                        distributionPoint: [new pkijs.GeneralName({ type: 6, value: CRL_URL })],
                        reasons: reasonFlagsBitString([1]),
                    }),
                ]),
            });
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: scopedLeaf.cert });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("rejects a relative-name distribution point", async () => {
            const relativeDP = new pkijs.DistributionPoint({
                distributionPoint: ca.cert.subject,
            });
            const scopedLeaf = await createTestLeaf(ca, {
                commonName: "T07 Relative Leaf",
                serial: 2605,
                crlDPExtension: crlDistributionPointsExtensionFromPoints([relativeDP]),
            });
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: scopedLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/distribution point|scope/i);
        });

        it("rejects a certificate with no distribution points", async () => {
            const bareLeaf = await createTestLeaf(ca, {
                commonName: "T07 Bare Leaf",
                serial: 2606,
            });
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: bareLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/distribution point/i);
        });

        it("caps the certificate distribution-point scan at 64", async () => {
            const points = (count: number): pkijs.DistributionPoint[] =>
                Array.from(
                    { length: count },
                    (_, index) =>
                        new pkijs.DistributionPoint({
                            distributionPoint: [
                                new pkijs.GeneralName({
                                    type: 6,
                                    value: `http://crl.example.com/${String(index)}.crl`,
                                }),
                            ],
                        })
                );
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const atLimit = await createTestLeaf(ca, {
                commonName: "T07 DP Cap Leaf",
                serial: 2607,
                crlDPExtension: crlDistributionPointsExtensionFromPoints(points(64)),
            });
            const atLimitResult = await validateDirect(crl, { cert: atLimit.cert });
            expect(atLimitResult.status).toBe("good");
            expect(atLimitResult.errors).toEqual([]);
            const overLimit = await createTestLeaf(ca, {
                commonName: "T07 DP Over Leaf",
                serial: 2608,
                crlDPExtension: crlDistributionPointsExtensionFromPoints(points(65)),
            });
            const result = await validateDirect(crl, { cert: overLimit.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/above the supported limit/);
        });

        it("caps the distribution-point GeneralName scan at 64", async () => {
            const pointWith = (count: number): pkijs.DistributionPoint[] => [
                new pkijs.DistributionPoint({
                    distributionPoint: Array.from(
                        { length: count },
                        (_, index) =>
                            new pkijs.GeneralName({
                                type: 6,
                                value: `http://crl.example.com/n${String(index)}.crl`,
                            })
                    ),
                }),
            ];
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const atLimit = await createTestLeaf(ca, {
                commonName: "T07 Names Cap Leaf",
                serial: 2609,
                crlDPExtension: crlDistributionPointsExtensionFromPoints(pointWith(64)),
            });
            const atLimitResult = await validateDirect(crl, { cert: atLimit.cert });
            expect(atLimitResult.status).toBe("good");
            expect(atLimitResult.errors).toEqual([]);
            const overLimit = await createTestLeaf(ca, {
                commonName: "T07 Names Over Leaf",
                serial: 2610,
                crlDPExtension: crlDistributionPointsExtensionFromPoints(pointWith(65)),
            });
            const result = await validateDirect(crl, { cert: overLimit.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/too many GeneralNames/);
        });

        it("rejects a certificate with a non-SEQUENCE distribution-points value", async () => {
            // Garbage extnValue (a NULL where the SEQUENCE OF lives):
            // the metadata reader throws and scope fails closed.
            const garbageLeaf = await createTestLeaf(ca, {
                commonName: "T07 Garbage CDP Leaf",
                serial: 2611,
                crlDPExtension: new pkijs.Extension({
                    extnID: "2.5.29.31",
                    critical: false,
                    extnValue: new asn1js.Null().toBER(false),
                }),
            });
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: garbageLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/must be a SEQUENCE/);
        });

        it("rejects a serial-matching entry issued for another CA", async () => {
            // Foreign entry-issuer scope fails the direct-only profile
            // (RFC 5280 5.3.3 inheritance would propagate it to
            // following entries without the extension, so per-entry
            // skips are unsound; T07 fix round 2 reverses the old skip).
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [
                            certificateIssuerExtension([
                                directoryNameGeneralName(wrongCA.cert.subject),
                            ]),
                        ],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/certificate issuer/i);
        });

        it("rejects a malformed entry certificate issuer", async () => {
            const malformed = new pkijs.Extension({
                extnID: "2.5.29.29",
                critical: true,
                extnValue: new Uint8Array([0x30, 0x03, 0x06, 0x01, 0x2a]).slice().buffer,
            });
            const crl = await freshCRL(ca, {
                entries: [{ serial: 2001, entryExtensions: [malformed] }],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/certificate issuer/i);
        });

        it("rejects a duplicate entry certificate issuer on the matching entry", async () => {
            // Two well-formed certificateIssuer extensions: the entry
            // scope gate fires before any scope verdict is attempted.
            const issuerScope = certificateIssuerExtension([
                directoryNameGeneralName(ca.cert.subject),
            ]);
            const crl = await freshCRL(ca, {
                entries: [{ serial: 2001, entryExtensions: [issuerScope, issuerScope] }],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/duplicate certificate issuer/i);
        });
    });

    describe("validateCRLEvidence delta deferral", () => {
        it("defers a delta CRL instead of treating it as complete", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [crlNumberExtension(7), deltaCrlIndicatorExtension(6)],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/delta CRL/);
        });

        it("defers a critical delta indicator", async () => {
            const indicator = deltaCrlIndicatorExtension(6);
            indicator.critical = true;
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [indicator],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/delta CRL/);
        });

        it("defers a delta CRL with a garbage indicator value", async () => {
            // OID-based detection fires before value parsing (T04 precedent).
            const garbage = new pkijs.Extension({
                extnID: "2.5.29.27",
                critical: false,
                extnValue: new Uint8Array([0x05, 0x00]).slice().buffer,
            });
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [garbage],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/delta CRL/);
        });

        it("never reports revoked from a delta CRL entry", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serial: 2001 }],
                crlExtensions: [crlNumberExtension(7), deltaCrlIndicatorExtension(6)],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/delta CRL/);
        });
    });

    describe("validateCRLEvidence entry extension grammar", () => {
        function rawEntryExtension(oid: string, valueDer: number[]): pkijs.Extension {
            return new pkijs.Extension({
                extnID: oid,
                critical: false,
                extnValue: new Uint8Array(valueDer).slice().buffer,
            });
        }

        it("rejects a malformed reason code on the matching entry", async () => {
            // ENUMERATED with trailing garbage.
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [rawEntryExtension("2.5.29.21", [0x0a, 0x01, 0x01, 0x00])],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/reason code/i);
        });

        it("rejects a malformed hold instruction on the matching entry", async () => {
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [rawEntryExtension("2.5.29.23", [0x05, 0x00])],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/hold instruction/i);
        });

        it("rejects a malformed invalidity date on the matching entry", async () => {
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [
                            rawEntryExtension(
                                "2.5.29.24",
                                [
                                    0x17, 0x0d, 0x32, 0x36, 0x30, 0x33, 0x30, 0x31, 0x30, 0x30,
                                    0x30, 0x30, 0x30, 0x30, 0x5a,
                                ]
                            ),
                        ],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/invalidity date/i);
        });

        it("rejects duplicate reason codes on the matching entry", async () => {
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [reasonCodeExtension(1), reasonCodeExtension(2)],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/duplicate reason code/i);
        });
    });

    describe("validateCRLEvidence entry framing", () => {
        it("rejects [0]-wrapped entry extensions (CRL-level shape at entry level)", async () => {
            // RFC 5280 5.1.2.6: crlEntryExtensions is a bare Extensions
            // SEQUENCE; the [0] EXPLICIT tag belongs to CRL-level
            // crlExtensions only. openssl emits the bare shape.
            const crl = await freshCRL(ca, { entries: [{ serial: 2001 }] });
            const reason = new pkijs.Extension({
                extnID: "2.5.29.21",
                critical: false,
                extnValue: new asn1js.Enumerated({ value: 1 }).toBER(false),
            });
            const mutated = await resignCrlTbs(
                crl,
                (tbsChildren) => {
                    const revoked = revokedCertificatesNode(tbsChildren);
                    const entry = revoked.valueBlock.value[0];
                    if (!(entry instanceof asn1js.Sequence)) throw new Error("entry");
                    entry.valueBlock.value.push(extensionsWrapperWith(reason.toSchema()));
                    tbsChildren.unshift(new asn1js.Integer({ value: 1 }));
                },
                ca.keys
            );
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/parse/i);
        });

        it("rejects an empty entry extension list on the matching entry", async () => {
            // Extensions is SIZE (1..MAX): present-but-empty is
            // malformed, not "no extensions". pkijs enforces the lower
            // bound during schema verification.
            const crl = await freshCRL(ca, { entries: [{ serial: 2001 }] });
            const mutated = await resignCrlTbs(
                crl,
                (tbsChildren) => {
                    const revoked = revokedCertificatesNode(tbsChildren);
                    const entry = revoked.valueBlock.value[0];
                    if (!(entry instanceof asn1js.Sequence)) throw new Error("entry");
                    entry.valueBlock.value.push(new asn1js.Sequence({ value: [] }));
                    tbsChildren.unshift(new asn1js.Integer({ value: 1 }));
                },
                ca.keys
            );
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/parse/i);
        });

        it("rejects an entry with a fourth member", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 2001 }] });
            const mutated = await resignCrlTbs(
                crl,
                (tbsChildren) => {
                    const revoked = revokedCertificatesNode(tbsChildren);
                    const entry = revoked.valueBlock.value[0];
                    if (!(entry instanceof asn1js.Sequence)) throw new Error("entry");
                    entry.valueBlock.value.push(new asn1js.Null());
                },
                ca.keys
            );
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/parse/i);
        });

        it("rejects an entry missing its revocation date", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 2001 }] });
            const mutated = await resignCrlTbs(
                crl,
                (tbsChildren) => {
                    const revoked = revokedCertificatesNode(tbsChildren);
                    const entry = revoked.valueBlock.value[0];
                    if (!(entry instanceof asn1js.Sequence)) throw new Error("entry");
                    entry.valueBlock.value.pop();
                },
                ca.keys
            );
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/parse/i);
        });
    });

    describe("validateCRLEvidence serial identity", () => {
        it("matches a high-bit serial on both sides (DER 00 pad)", async () => {
            const paddedLeaf = await createTestLeaf(ca, {
                commonName: "T07 Pad Leaf",
                serial: 128,
                crlUrls: [CRL_URL],
            });
            const crl = await freshCRL(ca, { entries: [{ serial: 128 }] });
            const result = await validateDirect(crl, { cert: paddedLeaf.cert });
            expect(result.status).toBe("revoked");
            expect(result.errors).toEqual([]);
        });

        it("never conflates serial -128 with serial 128", async () => {
            // The T04-ASTRA conflation: a leading-zero strip turns both
            // into 0x80. Exact numeric identity must not match them.
            const negativeLeaf = await createTestLeaf(ca, {
                commonName: "T07 Negative Leaf",
                serial: 2001,
                crlUrls: [CRL_URL],
            });
            negativeLeaf.cert.serialNumber = new asn1js.Integer({
                valueHex: new Uint8Array([0x80]).slice().buffer,
            });
            const crl = await freshCRL(ca, { entries: [{ serial: 128 }] });
            const result = await validateDirect(crl, { cert: negativeLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/serial/i);
        });

        it("rejects an empty certificate serial", async () => {
            const emptyLeaf = await createTestLeaf(ca, {
                commonName: "T07 Empty Serial Leaf",
                serial: 2001,
                crlUrls: [CRL_URL],
            });
            emptyLeaf.cert.serialNumber = new asn1js.Integer({
                valueHex: new Uint8Array(0).slice().buffer,
            });
            const crl = await freshCRL(ca, { entries: [{ serial: 2001 }] });
            const result = await validateDirect(crl, { cert: emptyLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/serial/i);
        });

        it("rejects a non-minimal certificate serial", async () => {
            const paddedLeaf = await createTestLeaf(ca, {
                commonName: "T07 Nonminimal Leaf",
                serial: 2001,
                crlUrls: [CRL_URL],
            });
            paddedLeaf.cert.serialNumber = new asn1js.Integer({
                valueHex: new Uint8Array([0x00, 0x07, 0xd1]).slice().buffer,
            });
            const crl = await freshCRL(ca, { entries: [{ serial: 2001 }] });
            const result = await validateDirect(crl, { cert: paddedLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/serial/i);
        });

        it("rejects a CRL entry with a negative serial", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serialValueHex: new Uint8Array([0x80]) }],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/serial/i);
        });

        it("matches serials beyond float precision exactly (no valueDec)", async () => {
            // 2^53 + 1: valueDec extracts it lossily, so decisions must
            // never use it (T04 F4).
            const bigSerial = new Uint8Array([0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
            const bigLeaf = await createTestLeaf(ca, {
                commonName: "T07 Big Serial Leaf",
                serial: 2001,
                crlUrls: [CRL_URL],
            });
            bigLeaf.cert.serialNumber = new asn1js.Integer({
                valueHex: bigSerial.slice().buffer,
            });
            const listed = await freshCRL(ca, { entries: [{ serialValueHex: bigSerial }] });
            expect((await validateDirect(listed, { cert: bigLeaf.cert })).status).toBe("revoked");
            const unlisted = await freshCRL(ca, {
                entries: [{ serialValueHex: new Uint8Array([0x01]) }],
            });
            const goodResult = await validateDirect(unlisted, { cert: bigLeaf.cert });
            expect(goodResult.status).toBe("good");
            expect(goodResult.errors).toEqual([]);
        });

        it("matches serial zero exactly", async () => {
            const zeroLeaf = await createTestLeaf(ca, {
                commonName: "T07 Zero Leaf",
                serial: 0,
                crlUrls: [CRL_URL],
            });
            const crl = await freshCRL(ca, { entries: [{ serial: 0 }] });
            const result = await validateDirect(crl, { cert: zeroLeaf.cert });
            expect(result.status).toBe("revoked");
            expect(result.errors).toEqual([]);
        });
    });

    describe("validateCRLEvidence versions", () => {
        it("rejects a v1 CRL carrying CRL extensions", async () => {
            const v2 = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [crlNumberExtension(7)],
            });
            // Downgrade to v1 by removing the version member, genuinely re-signed.
            const v1 = await resignCrlTbs(
                v2,
                (tbsChildren) => {
                    const version = tbsChildren[0];
                    if (!(version instanceof asn1js.Integer)) throw new Error("version member");
                    tbsChildren.shift();
                },
                ca.keys
            );
            const result = await validateDirect(v1);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/version/i);
        });

        it("rejects a v1 CRL carrying entry extensions", async () => {
            const v2 = await freshCRL(ca, {
                entries: [{ serial: 9999, entryExtensions: [reasonCodeExtension(1)] }],
            });
            const v1 = await resignCrlTbs(
                v2,
                (tbsChildren) => {
                    const version = tbsChildren[0];
                    if (!(version instanceof asn1js.Integer)) throw new Error("version member");
                    tbsChildren.shift();
                },
                ca.keys
            );
            const result = await validateDirect(v1);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/version/i);
        });

        it("rejects an explicit v1 (0x00) CRL carrying CRL extensions", async () => {
            // pkijs omits DEFAULT versions on emit, so version: 0 is
            // absence-equivalent; the explicit INTEGER 0x00 needs TBS
            // surgery (genuinely re-signed) to pin the
            // well-formed-v1-with-extensions branch.
            const v2 = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [crlNumberExtension(7)],
            });
            const v1 = await resignCrlTbs(
                v2,
                (tbsChildren) => {
                    const version = tbsChildren[0];
                    if (!(version instanceof asn1js.Integer)) throw new Error("version member");
                    tbsChildren[0] = new asn1js.Integer({ value: 0 });
                },
                ca.keys
            );
            const tbs = outerChild(parseOuterCrl(v1), 0);
            if (!(tbs instanceof asn1js.Sequence)) throw new Error("TBSCertList");
            const versionNode = tbs.valueBlock.value[0];
            if (!(versionNode instanceof asn1js.Integer)) {
                throw new Error("explicit version is not INTEGER");
            }
            expect(Array.from(new Uint8Array(versionNode.valueBlock.valueHexView))).toEqual([0x00]);
            const result = await validateDirect(v1);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/version 1 must not carry extensions/);
        });

        it("rejects an unsupported CRL version", async () => {
            const v2 = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [crlNumberExtension(7)],
            });
            const v3 = await resignCrlTbs(
                v2,
                (tbsChildren) => {
                    const version = tbsChildren[0];
                    if (!(version instanceof asn1js.Integer)) throw new Error("version member");
                    tbsChildren[0] = new asn1js.Integer({ value: 2 });
                },
                ca.keys
            );
            const result = await validateDirect(v3);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/version/i);
        });

        it("rejects a negative CRL version", async () => {
            // Version -1 slips past a greater-than-v2 gate; only
            // v1(0) and v2(1) are well-formed versions.
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const mutated = await resignCrlTbs(
                crl,
                (tbsChildren) => {
                    tbsChildren.unshift(new asn1js.Integer({ value: -1 }));
                },
                ca.keys
            );
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/version/i);
        });

        it("rejects an out-of-range CRL version", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const mutated = await resignCrlTbs(
                crl,
                (tbsChildren) => {
                    tbsChildren.unshift(
                        new asn1js.Integer({
                            valueHex: new Uint8Array([0x01, 0x00, 0x00, 0x00, 0x00]).slice().buffer,
                        })
                    );
                },
                ca.keys
            );
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/version/i);
        });
    });

    describe("validateCRLEvidence complete consumption", () => {
        it("rejects trailing garbage after the CRL", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(concatBytes(crl, new Uint8Array([0x00])));
            expect(result.status).toBe("unknown");
        });

        it("rejects concatenated CRLs", async () => {
            const first = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const second = await freshCRL(ca, { entries: [{ serial: 2001 }] });
            const result = await validateDirect(concatBytes(first, second));
            expect(result.status).toBe("unknown");
        });

        it("rejects malformed CRL bytes", async () => {
            const result = await validateDirect(new Uint8Array([0xff, 0xff, 0xff]));
            expect(result.status).toBe("unknown");
        });

        it("rejects a signed CRL with a malformed issuer name", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const mutated = await resignCrlTbs(
                crl,
                (tbsChildren) => {
                    const issuer = issuerNameNode(tbsChildren);
                    const rdn = issuer.valueBlock.value[0];
                    if (!(rdn instanceof asn1js.Set)) throw new Error("RDN");
                    const attribute = rdn.valueBlock.value[0];
                    if (!(attribute instanceof asn1js.Sequence)) throw new Error("ATV");
                    attribute.valueBlock.value.push(new asn1js.Null());
                },
                ca.keys
            );
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/name/i);
        });

        it("rejects a signed CRL with an empty issuer RDN", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const mutated = await resignCrlTbs(
                crl,
                (tbsChildren) => {
                    const issuer = issuerNameNode(tbsChildren);
                    issuer.valueBlock.value.push(new asn1js.Set({ value: [] }));
                },
                ca.keys
            );
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/name/i);
        });

        it("rejects a signed CRL extension with an extra member", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [crlNumberExtension(7)],
            });
            const mutated = await resignCrlTbs(
                crl,
                (tbsChildren) => {
                    const wrapper = crlExtensionsNode(tbsChildren);
                    const sequence = wrapper.valueBlock.value[0];
                    if (!(sequence instanceof asn1js.Sequence)) throw new Error("extensions");
                    const extension = sequence.valueBlock.value[0];
                    if (!(extension instanceof asn1js.Sequence)) throw new Error("extension");
                    extension.valueBlock.value.push(new asn1js.Null());
                },
                ca.keys
            );
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
        });

        it("rejects a CRL-level extension list that is present but empty", async () => {
            // Extensions is SIZE (1..MAX): [0] wrapping an empty
            // SEQUENCE is malformed, not "no extensions". pkijs
            // enforces the lower bound during schema verification.
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const mutated = await resignCrlTbs(
                crl,
                (tbsChildren) => {
                    tbsChildren.unshift(new asn1js.Integer({ value: 1 }));
                    tbsChildren.push(
                        new asn1js.Constructed({
                            idBlock: { tagClass: 3, tagNumber: 0 },
                            value: [new asn1js.Sequence({ value: [] })],
                        })
                    );
                },
                ca.keys
            );
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/parse/i);
        });

        it("rejects a constructed extnValue OCTET STRING", async () => {
            // DER strings are primitive (X.690 10.2): a constructed
            // OCTET STRING whose chunks concatenate to INTEGER 7 is
            // still malformed. Wire bytes pinned exactly. pkijs
            // Extension schema verification rejects the framing.
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const mutated = await resignCrlTbs(
                crl,
                (tbsChildren) => {
                    tbsChildren.unshift(new asn1js.Integer({ value: 1 }));
                    tbsChildren.push(
                        extensionsWrapperWith(
                            extensionNodeFromDer([
                                0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x14, 0x24, 0x06, 0x04, 0x01,
                                0x02, 0x04, 0x02, 0x01, 0x07,
                            ])
                        )
                    );
                },
                ca.keys
            );
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/parse/i);
        });

        it("rejects a trailing TBSCertList member", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const mutated = await resignCrlTbs(
                crl,
                (tbsChildren) => {
                    tbsChildren.push(new asn1js.Null());
                },
                ca.keys
            );
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/parse/i);
        });

        it("rejects reordered TBSCertList members", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const mutated = await resignCrlTbs(
                crl,
                (tbsChildren) => {
                    // Swap the issuer Name and thisUpdate positions.
                    const issuer = issuerNameNode(tbsChildren);
                    const index = tbsChildren.indexOf(issuer);
                    if (index < 0) throw new Error("CRL issuer position not found");
                    const next = tbsChildren[index + 1];
                    if (next === undefined) throw new Error("thisUpdate position not found");
                    tbsChildren[index] = next;
                    tbsChildren[index + 1] = issuer;
                },
                ca.keys
            );
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/parse/i);
        });
    });

    describe("validateCRLEvidence input validation", () => {
        it("throws INVALID_ARGUMENT for empty bytes and bad policy inputs", async () => {
            const validator = await expectValidator();
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            await expect(
                validator.validateCRLEvidence(new Uint8Array(0), {
                    cert: leaf.cert,
                    issuer: ca.cert,
                    checkDate: CHECK_DATE,
                    clockSkewMs: CLOCK_SKEW_MS,
                })
            ).rejects.toMatchObject({ code: TimestampErrorCode.INVALID_ARGUMENT });
            await expect(
                validator.validateCRLEvidence(crl, {
                    cert: leaf.cert,
                    issuer: ca.cert,
                    checkDate: new Date(Number.NaN),
                    clockSkewMs: CLOCK_SKEW_MS,
                })
            ).rejects.toMatchObject({ code: TimestampErrorCode.INVALID_ARGUMENT });
            await expect(
                validator.validateCRLEvidence(crl, {
                    cert: leaf.cert,
                    issuer: ca.cert,
                    checkDate: CHECK_DATE,
                    clockSkewMs: -1,
                })
            ).rejects.toMatchObject({ code: TimestampErrorCode.INVALID_ARGUMENT });
        });
    });

    describe("validateCRLEvidence resource caps", () => {
        it("caps the CRL extension scan at 64", async () => {
            const sixtyFour = Array.from({ length: 64 }, (_, index) =>
                unknownExtension(`1.2.3.${String(5000 + index)}`, false)
            );
            const atLimit = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: sixtyFour,
            });
            expect((await validateDirect(atLimit)).status).toBe("good");
            const overLimit = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [...sixtyFour, unknownExtension("1.2.3.9999", false)],
            });
            const result = await validateDirect(overLimit);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/above the supported limit/);
        });

        it("caps the matching-entry extension scan at 64", async () => {
            const sixtyFour = Array.from({ length: 64 }, (_, index) =>
                unknownExtension(`1.2.3.${String(6000 + index)}`, false)
            );
            // At-limit on the matching entry passes the cap gate and
            // reaches the revoked verdict the listing implies.
            const atLimit = await freshCRL(ca, {
                entries: [{ serial: 2001, entryExtensions: sixtyFour }],
            });
            const atLimitResult = await validateDirect(atLimit);
            expect(atLimitResult.status).toBe("revoked");
            expect(atLimitResult.errors).toEqual([]);
            const overLimit = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [...sixtyFour, unknownExtension("1.2.3.6999", false)],
                    },
                ],
            });
            const result = await validateDirect(overLimit);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/above the supported limit/);
        });

        it("caps the revoked-entry scan at 2000", async () => {
            const entries = (count: number): CrlEntrySpec[] =>
                Array.from({ length: count }, (_, index) => ({ serial: 100000 + index }));
            const atLimit = await freshCRL(ca, { entries: entries(2000) });
            expect((await validateDirect(atLimit)).status).toBe("good");
            const overLimit = await freshCRL(ca, { entries: entries(2001) });
            const result = await validateDirect(overLimit);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/above the supported limit/);
        }, 60000);

        it("caps the issuer-name walk (64 RDNs pass, 65 reject)", async () => {
            // Raw ASN.1 on the wire: pkijs packs every attribute into a
            // single RDN on re-emit, so multi-RDN names are spliced into
            // TBSCertList with surgery; the issuer certificate subject is
            // parsed from the same wire bytes so binding stays exact.
            function wireName(
                rdns: number,
                attributesPerRdn: number
            ): {
                der: Uint8Array;
                subject: pkijs.RelativeDistinguishedNames;
            } {
                const sets: asn1js.Set[] = [];
                for (let rdn = 0; rdn < rdns; rdn++) {
                    const attributes: asn1js.Sequence[] = [];
                    for (let attr = 0; attr < attributesPerRdn; attr++) {
                        attributes.push(
                            new asn1js.Sequence({
                                value: [
                                    new asn1js.ObjectIdentifier({ value: "2.5.4.3" }),
                                    new asn1js.PrintableString({
                                        value: `R${String(rdn)}A${String(attr)}`,
                                    }),
                                ],
                            })
                        );
                    }
                    sets.push(new asn1js.Set({ value: attributes }));
                }
                const der = new Uint8Array(new asn1js.Sequence({ value: sets }).toBER(false));
                const parsed = asn1js.fromBER(toArrayBuffer(der.slice()));
                if (parsed.offset === -1 || parsed.offset !== der.length) {
                    throw new Error("name fixture is not DER");
                }
                return {
                    der,
                    subject: new pkijs.RelativeDistinguishedNames({ schema: parsed.result }),
                };
            }
            function issuerWithSubject(
                subject: pkijs.RelativeDistinguishedNames
            ): pkijs.Certificate {
                // Clone the CA certificate object so the shared fixture
                // keeps its name; only the subject name differs.
                const certDer = new Uint8Array(ca.cert.toSchema(true).toBER(false));
                const parsed = asn1js.fromBER(toArrayBuffer(certDer));
                if (parsed.offset === -1) throw new Error("CA is not DER");
                const clone = new pkijs.Certificate({ schema: parsed.result });
                clone.subject = subject;
                return clone;
            }
            async function validateWithName(
                rdns: number,
                attributesPerRdn: number
            ): Promise<{ status: string; errors: string[] }> {
                const { der, subject } = wireName(rdns, attributesPerRdn);
                const issuerCert = issuerWithSubject(subject);
                const issuer: TestCertificateAuthority = { cert: issuerCert, keys: ca.keys };
                const base = await freshCRL(issuer, { entries: [{ serial: 9999 }] });
                const crl = await resignCrlTbs(
                    base,
                    (tbsChildren) => {
                        const current = issuerNameNode(tbsChildren);
                        const index = tbsChildren.indexOf(current);
                        if (index < 0) throw new Error("CRL issuer position not found");
                        const replacement = asn1js.fromBER(toArrayBuffer(der.slice()));
                        if (
                            replacement.offset === -1 ||
                            !(replacement.result instanceof asn1js.Sequence)
                        ) {
                            throw new Error("name fixture is not DER");
                        }
                        tbsChildren[index] = replacement.result;
                    },
                    ca.keys
                );
                const result = await validateDirect(crl, { issuer: issuerCert });
                return { status: result.status, errors: result.errors };
            }
            expect((await validateWithName(64, 1)).status).toBe("good");
            const overRdns = await validateWithName(65, 1);
            expect(overRdns.status).toBe("unknown");
            expect(overRdns.errors.join("\n")).toMatch(/name/i);
            expect((await validateWithName(1, 256)).status).toBe("good");
            const overAttributes = await validateWithName(1, 257);
            expect(overAttributes.status).toBe("unknown");
            expect(overAttributes.errors.join("\n")).toMatch(/name/i);
        });
    });

    describe("validateCRLEvidence openssl interop", () => {
        // Real openssl 3.5.5 bytes (base64 DER in fixtures): bare entry
        // extensions with a reasonCode, explicit NULL algorithm
        // parameters, a GeneralizedTime nextUpdate, and multi-byte CRL
        // numbers. The check date is fixed inside the CRL validity
        // window (deterministic until 2126).
        const OPENSSL_CHECK_DATE = new Date("2026-10-03T00:00:00Z");

        function parseInteropCertificate(base64: string): pkijs.Certificate {
            const parsed = asn1js.fromBER(toArrayBuffer(decodeInteropDer(base64).slice()));
            if (parsed.offset === -1) throw new Error("interop certificate is not DER");
            return new pkijs.Certificate({ schema: parsed.result });
        }

        async function validateInterop(crlBase64: string) {
            const validator = await expectValidator();
            return validator.validateCRLEvidence(decodeInteropDer(crlBase64), {
                cert: parseInteropCertificate(OPENSSL_INTEROP_LEAF_BASE64),
                issuer: parseInteropCertificate(OPENSSL_INTEROP_CA_BASE64),
                checkDate: OPENSSL_CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
            });
        }

        it("reports revoked for the openssl-listed leaf", async () => {
            const result = await validateInterop(OPENSSL_INTEROP_REVOKED_CRL_BASE64);
            expect(result.status).toBe("revoked");
            expect(result.source).toBe("CRL");
            expect(result.errors).toEqual([]);
        });

        it("reports good for the openssl CRL without the leaf", async () => {
            const result = await validateInterop(OPENSSL_INTEROP_EMPTY_CRL_BASE64);
            expect(result.status).toBe("good");
            expect(result.source).toBe("CRL");
            expect(result.errors).toEqual([]);
        });
    });

    describe("ValidationSession CRL evidence routing and fallback", () => {
        function sessionOptions(): {
            checkDate: Date;
            clockSkewMs: number;
            maxAgeWithoutNextUpdateMs: number;
        } {
            return {
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: 24 * 60 * 60 * 1000,
            };
        }

        /** OCSP responder that echoes the request nonce with a real signature. */
        function echoOcsp(
            status: "good" | "revoked",
            target: pkijs.Certificate = bothLeaf.cert
        ): (request: Uint8Array) => Promise<Uint8Array> {
            return async (request: Uint8Array) => {
                const inspected = inspectOCSPRequest(request);
                return createSignedOCSPResponse(ca.cert, {
                    signerKeys: ca.keys,
                    producedAt: THIS_UPDATE,
                    responses: [
                        {
                            cert: target,
                            issuer: ca.cert,
                            status,
                            thisUpdate: THIS_UPDATE,
                            nextUpdate: NEXT_UPDATE,
                        },
                    ],
                    nonceEcho: inspected.nonces[0],
                });
            };
        }

        it("falls back to an authenticated CRL after OCSP unknown", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const fetcher = recordingFetcher({
                ocsp: new Uint8Array([0xff, 0xff, 0xff]),
                crl,
            });
            const session = new ValidationSession({ fetcher, ...sessionOptions() });
            session.queueCertificate(bothLeaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("good");
            expect(result?.isValid).toBe(true);
            expect(result?.sources).toEqual(["OCSP", "CRL"]);
            expect(fetcher.ocspCalls).toBe(1);
            expect(fetcher.crlCalls).toBe(1);
        });

        it("falls back to an authenticated CRL after an OCSP error", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const fetcher = recordingFetcher({ crl });
            const session = new ValidationSession({ fetcher, ...sessionOptions() });
            session.queueCertificate(bothLeaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("good");
            expect(result?.isValid).toBe(true);
            expect(fetcher.ocspCalls).toBe(1);
            expect(fetcher.crlCalls).toBe(1);
        });

        it("rejects a CRL when cRLIssuer mixes the issuer DN with another name", async () => {
            // A cRLIssuer-bearing point needs an indirect CRL (RFC 5280
            // 6.3.3(b)(1)), and non-DN entries violate the cRLIssuer
            // DN-only rule (RFC 5280 4.2.1.13): malformed metadata, not
            // a bindable point (T07 fix round 2 reverses the old
            // scope-or acceptance).
            const mixedLeaf = await createTestLeaf(ca, {
                commonName: "T07 Mixed Issuer Leaf",
                serial: 2612,
                crlDPExtension: crlDistributionPointsExtensionFromPoints([
                    new pkijs.DistributionPoint({
                        distributionPoint: [new pkijs.GeneralName({ type: 6, value: CRL_URL })],
                        cRLIssuer: [
                            directoryNameGeneralName(ca.cert.subject),
                            new pkijs.GeneralName({ type: 1, value: "crl@example.com" }),
                        ],
                    }),
                ]),
            });
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const fetcher = recordingFetcher({ crl });
            const session = new ValidationSession({ fetcher, ...sessionOptions() });
            session.queueCertificate(mixedLeaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(result?.errors.join("\n")).toMatch(/cRLIssuer|distribution point/i);
            expect(fetcher.crlCalls).toBe(1);
        });

        it("accepts a CRL with 64 at-limit entry extensions through the session", async () => {
            // At-limit entry extensions on an unlisted entry: nothing
            // decisive to scan, so the good verdict holds end to end.
            const sixtyFour = Array.from({ length: 64 }, (_, index) =>
                unknownExtension(`1.2.3.${String(7000 + index)}`, false)
            );
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999, entryExtensions: sixtyFour }],
            });
            const fetcher = recordingFetcher({ crl });
            const session = new ValidationSession({ fetcher, ...sessionOptions() });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("good");
            expect(result?.isValid).toBe(true);
            expect(result?.errors).toEqual([]);
            expect(fetcher.crlCalls).toBe(1);
        });

        it("falls back to OCSP after a malformed CRL", async () => {
            // CRL first (malformed), then OCSP: the CRL attempt must not
            // block the fallback.
            const fetcher = recordingFetcher({
                ocsp: echoOcsp("good"),
                crl: new Uint8Array([0xff, 0xff, 0xff]),
            });
            const session = new ValidationSession({
                fetcher,
                preferOCSP: false,
                ...sessionOptions(),
            });
            session.queueCertificate(bothLeaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("good");
            expect(result?.isValid).toBe(true);
            expect(fetcher.crlCalls).toBe(1);
            expect(fetcher.ocspCalls).toBe(1);
        });

        it("yields unknown when both sources are unavailable", async () => {
            const fetcher = recordingFetcher({});
            const session = new ValidationSession({ fetcher, ...sessionOptions() });
            session.queueCertificate(bothLeaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(result?.sources).toEqual([]);
            expect(fetcher.ocspCalls).toBe(1);
            expect(fetcher.crlCalls).toBe(1);
        });

        it("never overwrites an authenticated OCSP revoked with a later CRL good", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const fetcher = recordingFetcher({ ocsp: echoOcsp("revoked"), crl });
            const session = new ValidationSession({ fetcher, ...sessionOptions() });
            session.queueCertificate(bothLeaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("revoked");
            expect(result?.isValid).toBe(false);
            // Stop-on-decisive: the CRL is never attempted.
            expect(fetcher.crlCalls).toBe(0);
        });

        it("never overwrites an authenticated CRL revoked with a later OCSP good", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 2003 }] });
            const fetcher = recordingFetcher({ ocsp: echoOcsp("good"), crl });
            const session = new ValidationSession({
                fetcher,
                preferOCSP: false,
                ...sessionOptions(),
            });
            session.queueCertificate(bothLeaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("revoked");
            expect(result?.isValid).toBe(false);
            // Stop-on-decisive: OCSP is never attempted.
            expect(fetcher.ocspCalls).toBe(0);
        });

        it("orders preferOCSP=false as CRL first, then OCSP (T06 M4)", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const fetcher = recordingFetcher({ ocsp: echoOcsp("good"), crl });
            const session = new ValidationSession({
                fetcher,
                preferOCSP: false,
                ...sessionOptions(),
            });
            session.queueCertificate(bothLeaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            // CRL first and decisive: OCSP never runs.
            expect(result?.revocationStatus).toBe("good");
            expect(result?.isValid).toBe(true);
            expect(result?.sources).toEqual(["CRL"]);
            expect(fetcher.crlCalls).toBe(1);
            expect(fetcher.ocspCalls).toBe(0);
        });

        it("tries OCSP second under preferOCSP=false after CRL unknown (T06 M4)", async () => {
            const fetcher = recordingFetcher({
                ocsp: echoOcsp("good"),
                crl: new Uint8Array([0xff, 0xff, 0xff]),
            });
            const session = new ValidationSession({
                fetcher,
                preferOCSP: false,
                ...sessionOptions(),
            });
            session.queueCertificate(bothLeaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("good");
            expect(result?.isValid).toBe(true);
            expect(result?.sources).toEqual(["CRL", "OCSP"]);
            expect(fetcher.crlCalls).toBe(1);
            expect(fetcher.ocspCalls).toBe(1);
        });

        it("tries an alternate CRL after unsupported evidence", async () => {
            const multiLeaf = await createTestLeaf(ca, {
                commonName: "T07 Multi CRL Leaf",
                serial: 2701,
                crlUrls: [CRL_URL, CRL_URL_2],
            });
            const delta = await freshCRL(ca, {
                entries: [{ serial: 9999 }],
                crlExtensions: [crlNumberExtension(7), deltaCrlIndicatorExtension(6)],
            });
            const full = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const fetcher = recordingFetcher({
                crl: (url: string) =>
                    url === CRL_URL ? Promise.resolve(delta) : Promise.resolve(full),
            });
            const session = new ValidationSession({ fetcher, ...sessionOptions() });
            session.queueCertificate(multiLeaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("good");
            expect(result?.isValid).toBe(true);
            expect(fetcher.crlCalls).toBe(2);
            expect(result?.errors.join("\n")).toMatch(/delta CRL/);
            expect(result?.crls).toHaveLength(2);
        });

        it("keeps per-URL diagnostics when every CRL fails", async () => {
            const multiLeaf = await createTestLeaf(ca, {
                commonName: "T07 Failing CRL Leaf",
                serial: 2702,
                crlUrls: [CRL_URL, CRL_URL_2],
            });
            const fetcher = recordingFetcher({});
            const session = new ValidationSession({ fetcher, ...sessionOptions() });
            session.queueCertificate(multiLeaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(result?.errors.join("\n")).toContain(`CRL from ${CRL_URL} failed:`);
            expect(result?.errors.join("\n")).toContain(`CRL from ${CRL_URL_2} failed:`);
            expect(result?.errors.join("\n")).not.toContain("No revocation endpoints attempted");
        });

        it("reports revoked through the session for a listed serial", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 2001 }] });
            const fetcher = new MockFetcher();
            fetcher.setCRLResponse(CRL_URL, crl);
            const session = new ValidationSession({ fetcher, ...sessionOptions() });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("revoked");
            expect(result?.isValid).toBe(false);
            expect(result?.sources).toEqual(["CRL"]);
            expect(result?.errors).toEqual([]);
        });

        it("does not refetch authentication-failed CRL bytes", async () => {
            // Structurally valid but signed by the wrong key: an auth
            // verdict, not cache corruption (T06 verdict-vs-corruption).
            const forged = await freshCRL(wrongCA, {
                crlIssuerCert: ca.cert,
                signerKeys: wrongCA.keys,
                entries: [{ serial: 9999 }],
            });
            const cache: ValidationCache = new InMemoryValidationCache();
            cache.setCRL(CRL_URL, forged);
            const fetcher = recordingFetcher({});
            const session = new ValidationSession({ fetcher, cache, ...sessionOptions() });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(fetcher.crlCalls).toBe(0);
        });

        it("refetches structurally poisoned cached CRL bytes once", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const cache: ValidationCache = new InMemoryValidationCache();
            cache.setCRL(CRL_URL, new Uint8Array([0xff, 0xff, 0xff]));
            const fetcher = recordingFetcher({ crl });
            const session = new ValidationSession({ fetcher, cache, ...sessionOptions() });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("good");
            expect(result?.isValid).toBe(true);
            expect(fetcher.crlCalls).toBe(1);
        });

        it("omits the no-endpoint diagnostic when only CRL endpoints exist (F3)", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const fetcher = new MockFetcher();
            fetcher.setCRLResponse(CRL_URL, crl);
            const session = new ValidationSession({ fetcher, ...sessionOptions() });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("good");
            expect(result?.errors.join("\n")).not.toContain("No revocation endpoints attempted");
        });

        it("omits the no-endpoint diagnostic when only OCSP endpoints exist (F3)", async () => {
            const ocspLeaf = await createTestLeaf(ca, {
                commonName: "T07 OCSP Leaf",
                serial: 2801,
                ocspUrl: OCSP_URL,
            });
            const fetcher = recordingFetcher({ ocsp: echoOcsp("good", ocspLeaf.cert) });
            const session = new ValidationSession({ fetcher, ...sessionOptions() });
            session.queueCertificate(ocspLeaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("good");
            expect(result?.errors.join("\n")).not.toContain("No revocation endpoints attempted");
        });

        it("keeps exactly one no-endpoint diagnostic when nothing is attempted (F3)", async () => {
            const bareLeaf = await createTestLeaf(ca, {
                commonName: "T07 Bare Leaf",
                serial: 2802,
            });
            const fetcher = recordingFetcher({});
            const session = new ValidationSession({ fetcher, ...sessionOptions() });
            session.queueCertificate(bareLeaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            const matches = (result?.errors ?? []).filter((error) =>
                error.includes("No revocation endpoints attempted")
            );
            expect(matches).toHaveLength(1);
        });

        it("preserves strict-unknown CRL material for embedding (C06 analogue)", async () => {
            const forged = await freshCRL(ca, {
                signerKeys: wrongCA.keys,
                entries: [{ serial: 9999 }],
            });
            const fetcher = new MockFetcher();
            fetcher.setCRLResponse(CRL_URL, forged);
            const session = new ValidationSession({ fetcher, ...sessionOptions() });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(result?.sources).toEqual(["CRL"]);
            expect(result?.crls).toHaveLength(1);
            expect(result?.crls?.[0]).toEqual(forged);
            expect(result?.errors.length).toBeGreaterThan(0);
            const ltv = session.exportLTVData();
            expect(ltv.crls).toHaveLength(1);
            expect(ltv.crls[0]).toEqual(forged);
        });

        it("fetches but cannot validate when the issuer is missing", async () => {
            const orphan = await createTestLeaf(ca, {
                commonName: "T07 Orphan Leaf",
                serial: 2901,
                crlUrls: [CRL_URL],
            });
            // Point the leaf at an absent issuer so no candidate verifies.
            orphan.cert.issuer = wrongCA.cert.subject;
            // Fetching needs only the distribution point, so the CRL is
            // fetched and preserved even though no issuer can validate
            // it (the T05 preservation contract); authentication still
            // needs the verified issuer, so the verdict stays unknown.
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const fetcher = recordingFetcher({ crl });
            const session = new ValidationSession({ fetcher, ...sessionOptions() });
            session.queueCertificate(orphan.cert);

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(result?.errors.join("\n")).toMatch(/issuer/i);
            expect(result?.sources).toEqual(["CRL"]);
            expect(result?.crls).toHaveLength(1);
            expect(fetcher.crlCalls).toBe(1);
            expect(fetcher.ocspCalls).toBe(0);
        });

        it("stops after the first CRL when the issuer is missing", async () => {
            const multiLeaf = await createTestLeaf(ca, {
                commonName: "T07 Orphan Multi Leaf",
                serial: 2903,
                crlUrls: [CRL_URL, CRL_URL_2],
            });
            multiLeaf.cert.issuer = wrongCA.cert.subject;
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const fetcher = recordingFetcher({ crl });
            const session = new ValidationSession({ fetcher, ...sessionOptions() });
            session.queueCertificate(multiLeaf.cert);

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            // Issuer resolution is URL-independent: one failure stops
            // the loop instead of fetching every remaining URL.
            expect(fetcher.crlCalls).toBe(1);
            expect(result?.crls).toHaveLength(1);
            expect(result?.errors.join("\n")).toMatch(/issuer/i);
        });

        it("yields unknown when the explicit issuer did not issue the leaf", async () => {
            const foreignLeaf = await createTestLeaf(wrongCA, {
                commonName: "T07 Foreign Leaf",
                serial: 2902,
                crlUrls: [CRL_URL],
            });
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const fetcher = recordingFetcher({ crl });
            const session = new ValidationSession({ fetcher, ...sessionOptions() });
            session.queueCertificate(foreignLeaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(result?.errors.join("\n")).toMatch(/did not issue/);
            expect(fetcher.crlCalls).toBe(1);
        });

        it("collects strict-unknown CRL material through completeLTVData", async () => {
            // Structural LTV collection keeps accepting bytes the strict
            // validator rejects: ordinary signing never depends on strict
            // CRL validation.
            const forged = await freshCRL(ca, {
                signerKeys: wrongCA.keys,
                entries: [{ serial: 9999 }],
            });
            const strict = await validateDirect(forged);
            expect(strict.status).toBe("unknown");

            const leafDer = new Uint8Array(leaf.cert.toSchema(true).toBER(false));
            const caDer = new Uint8Array(ca.cert.toSchema(true).toBER(false));
            const completed = await completeLTVData(
                { certificates: [leafDer, caDer], crls: [], ocspResponses: [] },
                {
                    fetchers: {
                        ocspFetcher: () => Promise.reject(new Error("no OCSP")),
                        crlFetcher: () => Promise.resolve(forged),
                        certFetcher: () => Promise.reject(new Error("no AIA")),
                    },
                }
            );
            expect(completed.data.crls).toHaveLength(1);
            expect(completed.data.crls[0]).toEqual(forged);
        });

        it("serves the supported CRL profile through both channels", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const strict = await validateDirect(crl);
            expect(strict.status).toBe("good");

            const leafDer = new Uint8Array(leaf.cert.toSchema(true).toBER(false));
            const caDer = new Uint8Array(ca.cert.toSchema(true).toBER(false));
            const completed = await completeLTVData(
                { certificates: [leafDer, caDer], crls: [], ocspResponses: [] },
                {
                    fetchers: {
                        ocspFetcher: () => Promise.reject(new Error("no OCSP")),
                        crlFetcher: () => Promise.resolve(crl),
                        certFetcher: () => Promise.reject(new Error("no AIA")),
                    },
                }
            );
            expect(completed.data.crls).toHaveLength(1);
        });
    });

    describe("operation budget elapsed boundaries (T08 fix round 4, F2)", () => {
        it("refuses usable cached CRL bytes once the elapsed budget is spent (F2a)", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const fetcher = recordingFetcher({});
            const cache: ValidationCache = {
                getOCSP: () => null,
                setOCSP: () => undefined,
                getCRL: () => crl,
                setCRL: () => undefined,
                clear: () => undefined,
            };
            const session = new ValidationSession({
                fetcher,
                cache,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                budget: { maxElapsedMs: 0 },
            });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });

            const [result] = await session.validateAll();

            // Elapsed exhaustion refuses even free cache hits: unknown
            // with a diagnostic, zero fetches. (Red run: good, no errors.)
            expect(fetcher.ocspCalls).toBe(0);
            expect(fetcher.crlCalls).toBe(0);
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect((result?.errors ?? []).join("\n")).toMatch(/operation budget exhausted/);
        });

        it("refuses authenticated CRL verdicts completing past the elapsed deadline (F2b)", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const fetcher = recordingFetcher({ crl });
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                budget: { maxElapsedMs: 20 },
            });
            session.queueCertificate(leaf.cert, { issuer: ca.cert });
            // Hold every real verification 50 ms: verdicts unchanged, only
            // late, so the 20 ms budget timer fires mid-validation.
            const subtle = crypto.subtle as unknown as {
                verify: (...args: never[]) => Promise<boolean>;
            };
            const originalVerify = subtle.verify.bind(subtle);
            subtle.verify = (async (...args: never[]) => {
                await new Promise((resolve) => setTimeout(resolve, 50));
                return originalVerify(...args);
            }) as (...args: never[]) => Promise<boolean>;
            try {
                const [result] = await session.validateAll();

                // The verdict completed past the deadline: unknown with a
                // diagnostic. (Red run: good, no errors, aborted signal.)
                expect(result?.revocationStatus).toBe("unknown");
                expect(result?.isValid).toBe(false);
                expect((result?.errors ?? []).join("\n")).toMatch(/operation budget exhausted/);
            } finally {
                subtle.verify = originalVerify;
            }
        });
    });

    describe("operation budget late-chunk byte accounting (T08 fix round 5, F1 residual)", () => {
        it("charges a chunk delivered past the attempt deadline, then refuses further fetches", async () => {
            // Sol re-review residual: a body chunk delivered past the
            // attempt deadline escaped byte accounting because onChunk ran
            // after the post-read deadline check, which threw first.
            // Rebuild of sol's standalone reproducer: a signed leaf with
            // two CRL URLs, DefaultFetcher maxRetries 3, budget { maxBytes:
            // 1024, maxAttempts: 10, maxElapsedMs: 10037 }, every first pull
            // blocking past the attempt timeout then delivering 4096 bytes.
            // Only retry backoffs (500/1000/2000) are accelerated; attempt
            // and operation deadlines stay real. The race window is scaled
            // 10x from sol's 15 ms / 40 ms to 150 ms / 200 ms: under
            // full-suite CPU oversubscription the OS preempts the fetch
            // continuation past a 15 ms attempt timeout (observed: pre-read
            // AttemptDeadlineExceededError at +15 ms, legitimately retried
            // with zero bytes delivered), which flakes the raw fetch count;
            // the scaled window keeps the chunk-always-late regime
            // identical while scheduling stalls stay far below it.
            const twoUrlLeaf = await createTestLeaf(ca, {
                serial: 2401,
                crlUrls: [CRL_URL, CRL_URL_2],
            });
            const calls: string[] = [];
            const counters = { pulls: 0, fulfilledBytes: 0, cancellations: 0 };
            const realFetch = globalThis.fetch;
            const realSetTimeout = globalThis.setTimeout;
            const backoffDelays = new Set([500, 1000, 2000]);
            globalThis.setTimeout = ((
                callback: (...args: never[]) => void,
                delay?: number,
                ...args: never[]
            ) =>
                realSetTimeout(
                    callback,
                    backoffDelays.has(delay ?? 0) ? 0 : delay,
                    ...args
                )) as unknown as typeof setTimeout;
            globalThis.fetch = (async (input: string) => {
                calls.push(input);
                let sent = false;
                const body = new ReadableStream<Uint8Array>(
                    {
                        pull(controller) {
                            counters.pulls++;
                            if (sent) return;
                            sent = true;
                            // Block the loop past the 150 ms attempt
                            // timeout: the chunk always fulfills late.
                            const start = Date.now();
                            while (Date.now() - start < 200) {
                                // Busy-wait: no timer callback interleaves.
                            }
                            controller.enqueue(new Uint8Array(4096));
                        },
                        cancel() {
                            counters.cancellations++;
                        },
                    },
                    { highWaterMark: 0 }
                );
                const savedGetReader = body.getReader.bind(body);
                body.getReader = (() => {
                    const reader = savedGetReader();
                    const savedRead = reader.read.bind(reader);
                    reader.read = async () => {
                        const chunk = await savedRead();
                        if (!chunk.done) counters.fulfilledBytes += chunk.value.byteLength;
                        return chunk;
                    };
                    return reader;
                }) as typeof body.getReader;
                return new Response(body);
            }) as typeof fetch;
            try {
                const nullCache: ValidationCache = {
                    getOCSP: () => null,
                    getCRL: () => null,
                    setOCSP: () => undefined,
                    setCRL: () => undefined,
                    clear: () => undefined,
                };
                const session = new ValidationSession({
                    fetcher: new DefaultFetcher({ timeout: 150, maxRetries: 3 }),
                    cache: nullCache,
                    preferOCSP: false,
                    checkDate: CHECK_DATE,
                    clockSkewMs: CLOCK_SKEW_MS,
                    budget: { maxBytes: 1024, maxAttempts: 10, maxElapsedMs: 10037 },
                });
                session.queueCertificate(twoUrlLeaf.cert, { issuer: ca.cert });

                const [result] = await session.validateAll();

                // The late 4096-byte chunk is charged, tipping the
                // 1024-byte budget: exactly one body is ever read, and no
                // fetch issues after the trip -- retries and the second URL
                // are refused. Zero-byte pre-read deadline retries (a
                // scheduling stall past the attempt timeout before any read
                // issues) deliver nothing, charge nothing, and are
                // legitimate, so the raw fetch count is not pinned; the
                // single pull plus the charged-bytes diagnostic pin the
                // invariant instead. (Red run: 8 fetches / 8 pulls / 32768
                // fulfilled bytes over both URLs, timeout errors, no
                // byte-limit diagnostic.)
                expect(new Set(calls)).toEqual(new Set([CRL_URL]));
                expect(counters.pulls).toBe(1);
                expect(counters.fulfilledBytes).toBe(4096);
                expect(counters.cancellations).toBe(calls.length);
                expect(result?.revocationStatus).toBe("unknown");
                expect((result?.errors ?? []).join("\n")).toMatch(
                    /byte limit \(1024\) exceeded after 4096 bytes/
                );
            } finally {
                globalThis.fetch = realFetch;
                globalThis.setTimeout = realSetTimeout;
            }
        });
    });

    describe("fix round 2: entry-issuer scope (sol P1-1)", () => {
        function rawCertificateIssuerExtension(
            valueDer: number[],
            critical = true
        ): pkijs.Extension {
            return new pkijs.Extension({
                extnID: "2.5.29.29",
                critical,
                extnValue: new Uint8Array(valueDer).slice().buffer,
            });
        }

        it("rejects an empty certificateIssuer payload on the matching entry", async () => {
            // 30 00: GeneralNames is SIZE (1..MAX); an empty payload
            // admits no scope and must fail closed, not skip to good.
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [rawCertificateIssuerExtension([0x30, 0x00])],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/certificate issuer/i);
        });

        it("rejects a certificateIssuer directoryName with an empty RDN", async () => {
            // [4]{SEQUENCE{SET{}}}: the Name grammar (RFC 5280 4.1.2.4)
            // requires a nonempty RDN SET; a malformed name cannot scope.
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [
                            rawCertificateIssuerExtension([
                                0x30, 0x06, 0xa4, 0x04, 0x30, 0x02, 0x31, 0x00,
                            ]),
                        ],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/certificate issuer/i);
        });

        it("rejects a matching issuer followed by an unbindable GeneralName", async () => {
            // The COMPLETE payload gates scope: one matching directoryName
            // does not excuse a trailing name the direct-only profile
            // cannot bind (early-return acceptance is the bug).
            const extras = [
                new pkijs.GeneralName({ type: 6, value: "http://evil.example.com/" }),
                directoryNameGeneralName(wrongCA.cert.subject),
            ];
            for (const extra of extras) {
                const crl = await freshCRL(ca, {
                    entries: [
                        {
                            serial: 2001,
                            entryExtensions: [
                                certificateIssuerExtension([
                                    directoryNameGeneralName(ca.cert.subject),
                                    extra,
                                ]),
                            ],
                        },
                    ],
                });
                const result = await validateDirect(crl);
                expect(result.status).toBe("unknown");
                expect(result.errors.join("\n")).toMatch(/certificate issuer/i);
            }
        });

        it("rejects inherited foreign scope on an entry without the extension", async () => {
            // RFC 5280 5.3.3: without the extension, an entry inherits
            // the preceding entry's issuer. The foreign scope on the
            // first entry therefore covers the target too, and foreign
            // scope is outside the direct-only profile.
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 9999,
                        entryExtensions: [
                            certificateIssuerExtension([
                                directoryNameGeneralName(wrongCA.cert.subject),
                            ]),
                        ],
                    },
                    { serial: 2001 },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/certificate issuer/i);
        });

        it("still scopes entries without the extension to the CRL issuer", async () => {
            // Control: no certificateIssuer anywhere keeps the direct
            // default, across several entries and both verdicts.
            const listed = await freshCRL(ca, {
                entries: [{ serial: 9998 }, { serial: 2001 }, { serial: 9999 }],
            });
            expect((await validateDirect(listed)).status).toBe("revoked");
            const unlisted = await freshCRL(ca, {
                entries: [{ serial: 9998 }, { serial: 9999 }],
            });
            const result = await validateDirect(unlisted);
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("still accepts same-issuer certificateIssuer on any entry", async () => {
            // Control + direct-only rule pin: a certificateIssuer naming
            // the verified issuer subject is scope-consistent with direct
            // issuance (it restates the default), on matching and
            // non-matching entries alike.
            const sameIssuer = (): pkijs.Extension =>
                certificateIssuerExtension([directoryNameGeneralName(ca.cert.subject)]);
            const crl = await freshCRL(ca, {
                entries: [
                    { serial: 9999, entryExtensions: [sameIssuer()] },
                    { serial: 2001, entryExtensions: [sameIssuer()] },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("revoked");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 2: distribution-point metadata (sol P1-2)", () => {
        async function leafWithPoints(points: pkijs.DistributionPoint[]): Promise<TestLeaf> {
            return createTestLeaf(ca, {
                commonName: "T07 R2 DP Leaf",
                serial: 3001,
                crlDPExtension: crlDistributionPointsExtensionFromPoints(points),
            });
        }

        function fullNamePoint(url: string): pkijs.DistributionPoint {
            return new pkijs.DistributionPoint({
                distributionPoint: [new pkijs.GeneralName({ type: 6, value: url })],
            });
        }

        function reasonsPoint(content: Uint8Array): pkijs.DistributionPoint {
            return new pkijs.DistributionPoint({
                distributionPoint: [new pkijs.GeneralName({ type: 6, value: CRL_URL })],
                reasons: rawReasonFlagsContent(content),
            });
        }

        it("pins the canonical implicit ReasonFlags wire bytes", async () => {
            // Fixture-repair pin: [1] IMPLICIT BIT STRING carries the
            // unused-bits count octet first (pkijs emits valueHex
            // verbatim, so the builder includes it).
            const cases: [number[], string][] = [
                [[1], "81020640"],
                [[1, 6], "81020142"],
                [[8], "8103070080"],
            ];
            for (const [bits, wire] of cases) {
                const point = new pkijs.DistributionPoint({
                    distributionPoint: [new pkijs.GeneralName({ type: 6, value: CRL_URL })],
                    reasons: reasonFlagsBitString(bits),
                });
                const schema = point.toSchema();
                const reasons = schema.valueBlock.value.find(
                    (member) => member.idBlock.tagClass === 3 && member.idBlock.tagNumber === 1
                );
                if (reasons === undefined) throw new Error("reasons member missing");
                expect(bytesToHex(new Uint8Array(reasons.toBER(false)))).toBe(wire);
            }
        });

        it("rejects an empty DistributionPoint even beside a foreign point", async () => {
            // RFC 5280 4.2.1.13: distributionPoint or cRLIssuer MUST be
            // present. The empty SEQUENCE must not supply a default scope.
            const scopedLeaf = await leafWithPoints([
                new pkijs.DistributionPoint({
                    distributionPoint: [new pkijs.GeneralName({ type: 6, value: CRL_URL_2 })],
                    cRLIssuer: [directoryNameGeneralName(wrongCA.cert.subject)],
                }),
                new pkijs.DistributionPoint({}),
            ]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: scopedLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/distribution point/i);
        });

        it("rejects a reasons-only DistributionPoint", async () => {
            // Same MUST: a point carrying only reasons is malformed
            // (canonical reasons isolate the presence rule itself).
            const scopedLeaf = await leafWithPoints([
                new pkijs.DistributionPoint({ reasons: reasonFlagsBitString([1]) }),
            ]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: scopedLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/distribution point/i);
        });

        it("rejects empty reasons content", async () => {
            // 81 00 (no content) and 81 01 00 (count only, no data).
            for (const content of [new Uint8Array(0), new Uint8Array([0x00])]) {
                const scopedLeaf = await leafWithPoints([reasonsPoint(content)]);
                const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
                const result = await validateDirect(crl, { cert: scopedLeaf.cert });
                expect(result.status).toBe("unknown");
                expect(result.errors.join("\n")).toMatch(/reason/i);
            }
        });

        it("rejects an invalid reasons unused-bits count", async () => {
            // The pre-repair fixture shape 81 01 40: 0x40 reads as a
            // count of 64, outside the valid 0-7 range.
            const scopedLeaf = await leafWithPoints([reasonsPoint(new Uint8Array([0x40]))]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: scopedLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/reason/i);
        });

        it("rejects nonzero reasons padding bits", async () => {
            // Unused count 6 with a padding bit set (0x41 & 0x3f != 0).
            const scopedLeaf = await leafWithPoints([reasonsPoint(new Uint8Array([0x06, 0x41]))]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: scopedLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/reason/i);
        });

        it("accepts multi-bit canonical reasons against a full CRL", async () => {
            // Repaired-fixture coverage: a full CRL covers every reason,
            // so any well-formed subset binds.
            const scopedLeaf = await leafWithPoints([
                new pkijs.DistributionPoint({
                    distributionPoint: [new pkijs.GeneralName({ type: 6, value: CRL_URL })],
                    reasons: reasonFlagsBitString([1, 6]),
                }),
            ]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: scopedLeaf.cert });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("rejects a non-directoryName cRLIssuer entry", async () => {
            // RFC 5280 4.2.1.13: cRLIssuer MUST only contain DNs. A URI
            // entry is malformed metadata even with a bindable sibling.
            const scopedLeaf = await leafWithPoints([
                new pkijs.DistributionPoint({
                    distributionPoint: [new pkijs.GeneralName({ type: 6, value: CRL_URL })],
                    cRLIssuer: [new pkijs.GeneralName({ type: 6, value: CRL_URL_2 })],
                }),
                fullNamePoint(CRL_URL),
            ]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: scopedLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/cRLIssuer|distribution point/i);
        });

        it("rejects an empty cRLIssuer GeneralNames", async () => {
            // GeneralNames is SIZE (1..MAX); malformed even with a sibling.
            const scopedLeaf = await leafWithPoints([
                new pkijs.DistributionPoint({
                    distributionPoint: [new pkijs.GeneralName({ type: 6, value: CRL_URL })],
                    cRLIssuer: [],
                }),
                fullNamePoint(CRL_URL),
            ]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: scopedLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/cRLIssuer|distribution point/i);
        });

        it("rejects an empty fullName GeneralNames", async () => {
            // GeneralNames is SIZE (1..MAX); malformed even with a sibling.
            const scopedLeaf = await leafWithPoints([
                new pkijs.DistributionPoint({ distributionPoint: [] }),
                fullNamePoint(CRL_URL),
            ]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: scopedLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/distribution point/i);
        });

        it("skips a well-formed cRLIssuer point but binds a sibling", async () => {
            // Direct-only rule pin (both sides): a DP carrying cRLIssuer
            // needs an indirect CRL (RFC 5280 6.3.3(b)(1)) and is out of
            // scope here even when it names the issuer -- but a sibling
            // in-scope point still binds.
            const scopedLeaf = await leafWithPoints([
                new pkijs.DistributionPoint({
                    distributionPoint: [new pkijs.GeneralName({ type: 6, value: CRL_URL_2 })],
                    cRLIssuer: [directoryNameGeneralName(ca.cert.subject)],
                }),
                fullNamePoint(CRL_URL),
            ]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: scopedLeaf.cert });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("rejects a cRLIssuer directoryName with an empty RDN", async () => {
            // The Name grammar gates directoryNames on the DP path too.
            // The CDP is hand-wired so the empty RDN survives verbatim.
            const uriName = new asn1js.IA5String({ value: CRL_URL });
            uriName.idBlock.tagClass = 3;
            uriName.idBlock.tagNumber = 6;
            const fullName = new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 0 },
                value: [uriName],
            });
            const dpName = new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 0 },
                value: [fullName],
            });
            const emptyRdnName = asn1js.fromBER(
                new Uint8Array([0x30, 0x02, 0x31, 0x00]).slice().buffer
            );
            if (emptyRdnName.offset === -1) throw new Error("name fixture is not DER");
            const dirName = new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 4 },
                value: [emptyRdnName.result],
            });
            const crlIssuer = new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 2 },
                value: [dirName],
            });
            const dp = new asn1js.Sequence({ value: [dpName, crlIssuer] });
            const cdp = new asn1js.Sequence({ value: [dp] });
            const rawLeaf = await createTestLeaf(ca, {
                commonName: "T07 R2 CDP Leaf",
                serial: 3002,
                crlDPExtension: new pkijs.Extension({
                    extnID: "2.5.29.31",
                    critical: false,
                    extnValue: cdp.toBER(false),
                }),
            });
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: rawLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/cRLIssuer|distribution point|malformed/i);
        });

        it("rejects an empty distribution-points SEQUENCE", async () => {
            // CRLDistributionPoints is SIZE (1..MAX).
            const emptyLeaf = await createTestLeaf(ca, {
                commonName: "T07 R2 Empty CDP Leaf",
                serial: 3003,
                crlDPExtension: new pkijs.Extension({
                    extnID: "2.5.29.31",
                    critical: false,
                    extnValue: new Uint8Array([0x30, 0x00]).slice().buffer,
                }),
            });
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: emptyLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/distribution point/i);
        });
    });

    describe("fix round 2: whole-CRL entry processing (sol P1-3)", () => {
        function rawEntryExtension(
            oid: string,
            valueDer: number[],
            critical: boolean
        ): pkijs.Extension {
            return new pkijs.Extension({
                extnID: oid,
                critical,
                extnValue: new Uint8Array(valueDer).slice().buffer,
            });
        }

        it("rejects duplicate serials with the benign entry first", async () => {
            const crl = await freshCRL(ca, {
                entries: [
                    { serial: 2001 },
                    {
                        serial: 2001,
                        entryExtensions: [unknownExtension("1.2.3.4444", true)],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/duplicate/i);
        });

        it("rejects duplicate serials with the critical entry first", async () => {
            // Both orders fail identically: no order-dependent first-match.
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [unknownExtension("1.2.3.4444", true)],
                    },
                    { serial: 2001 },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/duplicate/i);
        });

        it("rejects duplicate serials even when both are benign", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serial: 2001 }, { serial: 2001 }],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/duplicate/i);
        });

        it("rejects a non-matching entry above the extension cap", async () => {
            // Skipped entries count against the cap: every entry list is
            // scanned pre-selection, so the bypass-by-skip is closed.
            const sixtyFive = Array.from({ length: 65 }, (_, index) =>
                unknownExtension(`1.2.3.${String(8000 + index)}`, false)
            );
            const crl = await freshCRL(ca, {
                entries: [{ serial: 9999, entryExtensions: sixtyFive }],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/above the supported limit/);
        });

        it("rejects a critical recognized payload failure on a non-matching entry", async () => {
            // RFC 5280 5.3: a critical entry extension the application
            // cannot process poisons the whole CRL, whatever entry it is on.
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 9999,
                        entryExtensions: [
                            rawEntryExtension("2.5.29.21", [0x0a, 0x01, 0x01, 0x00], true),
                        ],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/reason code/i);
        });

        it("ignores a non-critical recognized payload failure on a non-matching entry", async () => {
            // Boundary pin: only critical payloads gate non-selected
            // entries (RFC 5280 5.3); non-critical reason grammar on an
            // entry that is not evidence stays verdict-neutral.
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 9999,
                        entryExtensions: [
                            rawEntryExtension("2.5.29.21", [0x0a, 0x01, 0x01, 0x00], false),
                        ],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("ignores non-critical unknown extensions on non-matching entries", async () => {
            // Control: RFC 5280 5.3 lets applications ignore unrecognized
            // non-critical entry extensions.
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 9999,
                        entryExtensions: [unknownExtension("1.2.3.4444", false)],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("rejects duplicate reason codes on a non-matching entry", async () => {
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 9999,
                        entryExtensions: [reasonCodeExtension(1), reasonCodeExtension(2)],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/duplicate reason code/i);
        });

        it("rejects an empty extension OID on a non-matching entry", async () => {
            // Twin of the matching-entry empty-OID probe, via TBS surgery.
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const mutated = await resignCrlTbs(
                crl,
                (tbsChildren) => {
                    const revoked = revokedCertificatesNode(tbsChildren);
                    const entry = revoked.valueBlock.value[0];
                    if (!(entry instanceof asn1js.Sequence)) throw new Error("entry");
                    entry.valueBlock.value.push(
                        new asn1js.Sequence({ value: [emptyOidExtensionNode()] })
                    );
                    tbsChildren.unshift(new asn1js.Integer({ value: 1 }));
                },
                ca.keys
            );
            const result = await validateDirect(mutated);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/empty extension OID/);
        });
    });

    describe("fix round 2: reason codes (sol P1-4)", () => {
        it.each([0, 1, 2, 3, 4, 5, 6, 7, 9, 10])(
            "reports revoked for listing reason %i",
            async (reason) => {
                // RFC 5280 5.3.1: every reason except removeFromCRL (8)
                // confirms the listing. certificateHold (6) does NOT
                // soften the verdict (hold semantics belong to T09b);
                // value 7 is unused by the RFC but carries no remove
                // semantics, so the complete-CRL profile treats it as
                // listing-confirming too.
                const crl = await freshCRL(ca, {
                    entries: [
                        {
                            serial: 2001,
                            entryExtensions: [reasonCodeExtension(reason)],
                        },
                    ],
                });
                const result = await validateDirect(crl);
                expect(result.status).toBe("revoked");
                expect(result.errors).toEqual([]);
            }
        );

        it("rejects removeFromCRL in a complete CRL", async () => {
            // RFC 5280 5.3.1: removeFromCRL (8) may only appear in delta
            // CRLs; here it must not read as revoked.
            for (const critical of [false, true]) {
                const crl = await freshCRL(ca, {
                    entries: [
                        {
                            serial: 2001,
                            entryExtensions: [reasonCodeExtension(8, critical)],
                        },
                    ],
                });
                const result = await validateDirect(crl);
                expect(result.status).toBe("unknown");
                expect(result.errors.join("\n")).toMatch(/removeFromCRL|delta/i);
            }
        });

        it("rejects negative and undefined reason values", async () => {
            for (const reason of [11, 99, 256]) {
                const crl = await freshCRL(ca, {
                    entries: [
                        {
                            serial: 2001,
                            entryExtensions: [reasonCodeExtension(reason)],
                        },
                    ],
                });
                const result = await validateDirect(crl);
                expect(result.status).toBe("unknown");
                expect(result.errors.join("\n")).toMatch(/reason code/i);
            }
            // -1: single-octet negative ENUMERATED (0a 01 ff).
            const negative = new pkijs.Extension({
                extnID: "2.5.29.21",
                critical: false,
                extnValue: new Uint8Array([0x0a, 0x01, 0xff]).slice().buffer,
            });
            const crl = await freshCRL(ca, {
                entries: [{ serial: 2001, entryExtensions: [negative] }],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/reason code/i);
        });

        it("ignores non-critical removeFromCRL on a non-matching entry", async () => {
            // Boundary pin: reason values gate wherever reason payloads
            // gate (the selected entry at any criticality, other
            // entries when critical). A non-critical removeFromCRL on
            // an entry that is not evidence stays verdict-neutral like
            // any other non-critical payload there.
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 9999,
                        entryExtensions: [reasonCodeExtension(8, false)],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 2: issuer public-key encoding (sol P2-5)", () => {
        function cloneCertificate(cert: pkijs.Certificate): pkijs.Certificate {
            // In-memory clone: the validator gates the caller-supplied
            // issuer object before its key executes in WebCrypto.
            const der = new Uint8Array(cert.toSchema(true).toBER(false));
            const parsed = asn1js.fromBER(toArrayBuffer(der));
            if (parsed.offset === -1) throw new Error("issuer is not DER");
            return new pkijs.Certificate({ schema: parsed.result });
        }

        function rsaIntegers(issuer: pkijs.Certificate): [asn1js.Integer, asn1js.Integer] {
            const raw = new Uint8Array(
                issuer.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView
            );
            const parsed = asn1js.fromBER(toArrayBuffer(raw));
            if (parsed.offset === -1 || !(parsed.result instanceof asn1js.Sequence)) {
                throw new Error("RSA payload is not a SEQUENCE");
            }
            const [n, e] = parsed.result.valueBlock.value;
            if (!(n instanceof asn1js.Integer) || !(e instanceof asn1js.Integer)) {
                throw new Error("RSA payload is not two INTEGERs");
            }
            return [n, e];
        }

        function withSpkiPayload(
            issuer: pkijs.Certificate,
            payload: Uint8Array,
            unusedBits = 0
        ): void {
            issuer.subjectPublicKeyInfo.subjectPublicKey = new asn1js.BitString({
                valueHex: toArrayBuffer(payload),
                unusedBits,
            });
        }

        it("rejects RSA issuer keys with non-octet-aligned framing", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const issuer = cloneCertificate(ca.cert);
            const raw = new Uint8Array(
                issuer.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView
            );
            withSpkiPayload(issuer, raw, 1);
            const result = await validateDirect(crl, { issuer });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/public key|octet-aligned/i);
        });

        it("rejects RSA issuer keys with trailing payload data", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const issuer = cloneCertificate(ca.cert);
            const raw = new Uint8Array(
                issuer.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView
            );
            withSpkiPayload(issuer, concatBytes(raw, new Uint8Array([0x05, 0x00])));
            const result = await validateDirect(crl, { issuer });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/public key/i);
        });

        it("rejects RSA issuer keys with a third INTEGER", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const issuer = cloneCertificate(ca.cert);
            const [n, e] = rsaIntegers(issuer);
            const evil = new asn1js.Sequence({
                value: [n, e, new asn1js.Integer({ value: 1 })],
            });
            withSpkiPayload(issuer, new Uint8Array(evil.toBER(false)));
            const result = await validateDirect(crl, { issuer });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/public key/i);
        });

        it("rejects RSA issuer keys with a negative modulus", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const issuer = cloneCertificate(ca.cert);
            const [n, e] = rsaIntegers(issuer);
            const nBytes = new Uint8Array(n.valueBlock.valueHexView);
            // A 2048-bit modulus always carries the 00 sign pad; the
            // setup assertion pins the premise, not the verdict.
            if (nBytes[0] !== 0x00) throw new Error("fixture modulus lacks a sign pad");
            const evil = new asn1js.Sequence({
                value: [new asn1js.Integer({ valueHex: toArrayBuffer(nBytes.subarray(1)) }), e],
            });
            withSpkiPayload(issuer, new Uint8Array(evil.toBER(false)));
            const result = await validateDirect(crl, { issuer });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/public key/i);
        });

        it("rejects RSA issuer keys with non-NULL parameters", async () => {
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const issuer = cloneCertificate(ca.cert);
            issuer.subjectPublicKeyInfo.algorithm.algorithmParams = new asn1js.Integer({
                value: 1,
            });
            const result = await validateDirect(crl, { issuer });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/parameter/i);
        });

        it("rejects EC issuer keys with non-octet-aligned framing", async () => {
            const crl = await freshCRL(ecCA, { entries: [{ serial: 2101 }] });
            const issuer = cloneCertificate(ecCA.cert);
            const raw = new Uint8Array(
                issuer.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView
            );
            withSpkiPayload(issuer, raw, 1);
            const result = await validateDirect(crl, { cert: ecLeaf.cert, issuer });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/public key|octet-aligned/i);
        });

        it("still verifies RSA issuers with NULL parameters", async () => {
            // Control: the fixture CA carries textbook NULL params.
            expect(ca.cert.subjectPublicKeyInfo.algorithm.algorithmParams).toBeInstanceOf(
                asn1js.Null
            );
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl);
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("still verifies RSA issuers with absent parameters", async () => {
            // Control: pkijs-built material omits the params entirely.
            const issuer = cloneCertificate(ca.cert);
            issuer.subjectPublicKeyInfo.algorithm.algorithmParams = undefined;
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { issuer });
            expect(result.status).toBe("good");
            expect(result.errors).toEqual([]);
        });

        it("still verifies EC issuers with named-curve parameters", async () => {
            // Control: named-curve OID params are the required EC form.
            expect(ecCA.cert.subjectPublicKeyInfo.algorithm.algorithmParams).toBeInstanceOf(
                asn1js.ObjectIdentifier
            );
            const crl = await freshCRL(ecCA, { entries: [{ serial: 2101 }] });
            const result = await validateDirect(crl, { cert: ecLeaf.cert, issuer: ecCA.cert });
            expect(result.status).toBe("revoked");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 2: invalidity dates (sol P2-6)", () => {
        function generalizedTimeValue(text: string): number[] {
            const bytes = [0x18, text.length];
            for (const char of text) bytes.push(char.charCodeAt(0));
            return bytes;
        }

        function invalidityDateRaw(text: string, critical: boolean): pkijs.Extension {
            return new pkijs.Extension({
                extnID: "2.5.29.24",
                critical,
                extnValue: new Uint8Array(generalizedTimeValue(text)).slice().buffer,
            });
        }

        it.each(["20260230000000Z", "20261301000000Z", "20260301000000+0000"])(
            "rejects malformed invalidity date %s",
            async (text) => {
                // asn1js parses all three as GeneralizedTime (silently
                // normalizing Feb-30, month 13, and the +0000 offset), so
                // the gate needs its own UTC-seconds + calendar grammar.
                for (const critical of [false, true]) {
                    const crl = await freshCRL(ca, {
                        entries: [
                            {
                                serial: 2001,
                                entryExtensions: [invalidityDateRaw(text, critical)],
                            },
                        ],
                    });
                    const result = await validateDirect(crl);
                    expect(result.status).toBe("unknown");
                    expect(result.errors.join("\n")).toMatch(/invalidity date/i);
                }
            }
        );

        it("accepts a leap-day invalidity date but rejects a non-leap Feb-29", async () => {
            const valid = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [invalidityDateRaw("20240229000000Z", false)],
                    },
                ],
            });
            expect((await validateDirect(valid)).status).toBe("revoked");
            const invalid = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [invalidityDateRaw("20230229000000Z", false)],
                    },
                ],
            });
            const result = await validateDirect(invalid);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/invalidity date/i);
        });

        it("rejects a 24:00 invalidity date (DER midnight is 00:00:00)", async () => {
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [invalidityDateRaw("20260301240000Z", false)],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/invalidity date/i);
        });

        it("still accepts a valid critical invalidity date as verdict-neutral", async () => {
            // Control: the date stays unevaluated (historical
            // interpretation belongs to T09b); only its grammar gates.
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [invalidityDateRaw("20260301000000Z", true)],
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("revoked");
            expect(result.errors).toEqual([]);
        });
    });

    describe("fix round 3: nested wrapper completeness (sol re-review)", () => {
        function contextNode(tag: number, children: asn1js.BaseBlock[]): asn1js.Constructed {
            return new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: tag },
                value: children,
            });
        }

        function directoryNameNode(
            subject: pkijs.RelativeDistinguishedNames,
            extras: asn1js.BaseBlock[] = []
        ): asn1js.Constructed {
            return contextNode(4, [subject.toSchema(), ...extras]);
        }

        function uriNode(url: string): asn1js.Primitive {
            return new asn1js.Primitive({
                idBlock: { tagClass: 3, tagNumber: 6 },
                valueHex: toArrayBuffer(new TextEncoder().encode(url)),
            });
        }

        function rawCertificateIssuer(nodes: asn1js.BaseBlock[], critical = true): pkijs.Extension {
            const sequence = new asn1js.Sequence({ value: nodes });
            return new pkijs.Extension({
                extnID: "2.5.29.29",
                critical,
                extnValue: sequence.toBER(false),
            });
        }

        function namePoint(url: string, nameExtras: asn1js.BaseBlock[] = []): asn1js.Sequence {
            return new asn1js.Sequence({
                value: [contextNode(0, [contextNode(0, [uriNode(url)]), ...nameExtras])],
            });
        }

        function crlIssuerOnlyPoint(subject: pkijs.RelativeDistinguishedNames): asn1js.Sequence {
            return new asn1js.Sequence({ value: [contextNode(2, [directoryNameNode(subject)])] });
        }

        async function leafWithRawPoints(points: asn1js.Sequence[]): Promise<TestLeaf> {
            const cdp = new asn1js.Sequence({ value: points });
            return createTestLeaf(ca, {
                commonName: "T07 R3 DP Leaf",
                serial: 3001,
                crlDPExtension: new pkijs.Extension({
                    extnID: "2.5.29.31",
                    critical: false,
                    extnValue: cdp.toBER(false),
                }),
            });
        }

        async function validateViaSession(cert: pkijs.Certificate, crl: Uint8Array) {
            const fetcher = recordingFetcher({ crl });
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: 24 * 60 * 60 * 1000,
            });
            session.queueCertificate(cert, { issuer: ca.cert });
            const [result] = await session.validateAll();
            return { result, fetcher };
        }

        it("rejects a matching entry whose directoryName wrapper carries a trailer", async () => {
            // [4]{issuer Name, NULL} and [4]{issuer Name, foreign
            // Name}: pkijs decodes the first Name and the scope walk
            // trusts it, so the wrapper must prove complete (exactly
            // one Name) before the decoded value is used.
            const trailers: asn1js.BaseBlock[] = [
                new asn1js.Null(),
                directoryNameNode(wrongCA.cert.subject),
            ];
            for (const trailer of trailers) {
                const crl = await freshCRL(ca, {
                    entries: [
                        {
                            serial: 2001,
                            entryExtensions: [
                                rawCertificateIssuer([
                                    directoryNameNode(ca.cert.subject, [trailer]),
                                ]),
                            ],
                        },
                    ],
                });
                const { result, fetcher } = await validateViaSession(leaf.cert, crl);
                expect(fetcher.crlCalls).toBe(1);
                expect(result?.revocationStatus).toBe("unknown");
                expect(result?.isValid).toBe(false);
                expect(result?.errors.join("\n")).toMatch(/certificate issuer/i);
            }
        });

        it("rejects a nonmatching entry whose directoryName wrapper carries a trailer", async () => {
            // Same malformed critical payload on an unlisted entry:
            // first-child scope acceptance would report good.
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 9999,
                        entryExtensions: [
                            rawCertificateIssuer([
                                directoryNameNode(ca.cert.subject, [new asn1js.Null()]),
                            ]),
                        ],
                    },
                ],
            });
            const { result, fetcher } = await validateViaSession(leaf.cert, crl);
            expect(fetcher.crlCalls).toBe(1);
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(result?.errors.join("\n")).toMatch(/certificate issuer/i);
        });

        it("rejects a distributionPoint wrapper with an ignored member", async () => {
            // [0]{fullName{URI}, NULL} and [0]{fullName{URI},
            // fullName{URI2}}: pkijs keeps the first choice and drops
            // the member, so the raw wrapper must carry exactly one
            // DistributionPointName choice.
            const points = [
                namePoint(CRL_URL, [new asn1js.Null()]),
                namePoint(CRL_URL, [contextNode(0, [uriNode(CRL_URL_2)])]),
            ];
            for (const point of points) {
                const scopedLeaf = await leafWithRawPoints([point]);
                const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
                const { result, fetcher } = await validateViaSession(scopedLeaf.cert, crl);
                expect(fetcher.crlCalls).toBe(1);
                expect(result?.revocationStatus).toBe("unknown");
                expect(result?.isValid).toBe(false);
                expect(result?.errors.join("\n")).toMatch(/distribution point/i);
            }
        });

        it("rejects a fullName directoryName wrapper with a trailing NULL", async () => {
            // fullName{URI, [4]{Name, NULL}}: the inner explicit
            // wrapper drops its trailer the same way entry
            // certificateIssuer does.
            const point = new asn1js.Sequence({
                value: [
                    contextNode(0, [
                        contextNode(0, [
                            uriNode(CRL_URL),
                            directoryNameNode(ca.cert.subject, [new asn1js.Null()]),
                        ]),
                    ]),
                ],
            });
            const scopedLeaf = await leafWithRawPoints([point]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const { result, fetcher } = await validateViaSession(scopedLeaf.cert, crl);
            expect(fetcher.crlCalls).toBe(1);
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(result?.errors.join("\n")).toMatch(/distribution point/i);
        });

        it("binds a direct sibling beside a cRLIssuer-only point", async () => {
            // RFC 5280 4.2.1.13: the name field may be absent when
            // cRLIssuer is present. The point validates normally,
            // stays out of direct scope, and the sibling binds.
            const scopedLeaf = await leafWithRawPoints([
                crlIssuerOnlyPoint(wrongCA.cert.subject),
                namePoint(CRL_URL),
            ]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const { result, fetcher } = await validateViaSession(scopedLeaf.cert, crl);
            expect(fetcher.crlCalls).toBe(1);
            expect(result?.revocationStatus).toBe("good");
            expect(result?.isValid).toBe(true);
            expect(result?.errors).toEqual([]);
        });

        it("reports no in-scope point for a lone cRLIssuer-only point", async () => {
            // The legal-but-indirect point excludes itself from direct
            // scope instead of throwing malformed.
            const scopedLeaf = await leafWithRawPoints([crlIssuerOnlyPoint(wrongCA.cert.subject)]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const result = await validateDirect(crl, { cert: scopedLeaf.cert });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/no in-scope/i);
        });

        it("rejects a relative-name wrapper with a trailing member", async () => {
            // [0]{[1]{RDN}, NULL} beside a direct sibling: pkijs drops
            // the trailer and the relative name excludes itself, so
            // the sibling would bind over malformed metadata.
            const nameSchema = ca.cert.subject.toSchema();
            const relative = contextNode(0, [
                contextNode(1, [...nameSchema.valueBlock.value]),
                new asn1js.Null(),
            ]);
            const scopedLeaf = await leafWithRawPoints([
                new asn1js.Sequence({ value: [relative] }),
                namePoint(CRL_URL),
            ]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const { result, fetcher } = await validateViaSession(scopedLeaf.cert, crl);
            expect(fetcher.crlCalls).toBe(1);
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(result?.errors.join("\n")).toMatch(/distribution point/i);
        });

        it("rejects a distributionPoint with a duplicated cRLIssuer field", async () => {
            // SEQ{[0]{fullName{URI}}, [2]{DN-A}, [2]{DN-B}} beside
            // a direct sibling: pkijs keeps the first [2] and drops
            // the second, so the sibling would bind over a silently
            // narrowed cRLIssuer.
            const issuerField = (subject: pkijs.RelativeDistinguishedNames) =>
                contextNode(2, [directoryNameNode(subject)]);
            const scopedLeaf = await leafWithRawPoints([
                new asn1js.Sequence({
                    value: [
                        contextNode(0, [contextNode(0, [uriNode(CRL_URL)])]),
                        issuerField(ca.cert.subject),
                        issuerField(wrongCA.cert.subject),
                    ],
                }),
                namePoint(CRL_URL),
            ]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const { result, fetcher } = await validateViaSession(scopedLeaf.cert, crl);
            expect(fetcher.crlCalls).toBe(1);
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(result?.errors.join("\n")).toMatch(/distribution point/i);
        });

        it("rejects a distributionPoint with unordered fields", async () => {
            // SEQ{[2]{DN}, [0]{fullName{URI}}} beside a direct
            // sibling: DER orders fields [0] < [1] < [2] but pkijs
            // accepts the swap while silently dropping the [0]
            // field (it decodes as cRLIssuer-only). The raw order
            // grammar must refuse the swap deliberately -- the
            // cRLIssuer-only relaxation below would otherwise let
            // the sibling bind over the dropped field.
            const scopedLeaf = await leafWithRawPoints([
                new asn1js.Sequence({
                    value: [
                        contextNode(2, [directoryNameNode(wrongCA.cert.subject)]),
                        contextNode(0, [contextNode(0, [uriNode(CRL_URL)])]),
                    ],
                }),
                namePoint(CRL_URL),
            ]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const { result, fetcher } = await validateViaSession(scopedLeaf.cert, crl);
            expect(fetcher.crlCalls).toBe(1);
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(result?.errors.join("\n")).toMatch(/distribution point/i);
        });

        it("rejects a cRLIssuer directoryName wrapper with a trailing NULL", async () => {
            // [2]{[4]{Name, NULL}} on a URI point beside a direct
            // sibling: pkijs binds the first Name and the point
            // excludes itself, so the sibling would bind over the
            // ignored trailer.
            const scopedLeaf = await leafWithRawPoints([
                new asn1js.Sequence({
                    value: [
                        contextNode(0, [contextNode(0, [uriNode(CRL_URL)])]),
                        contextNode(2, [
                            directoryNameNode(wrongCA.cert.subject, [new asn1js.Null()]),
                        ]),
                    ],
                }),
                namePoint(CRL_URL),
            ]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const { result, fetcher } = await validateViaSession(scopedLeaf.cert, crl);
            expect(fetcher.crlCalls).toBe(1);
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(result?.errors.join("\n")).toMatch(/cRLIssuer|distribution point/i);
        });

        it("rejects otherName and ediPartyName wrappers pkijs cannot fully consume", async () => {
            // pkijs parses [0]{OID, [0]{...}} and [5]{[1]{...}}
            // while dropping trailers, and fullName ignores the
            // decoded choice -- so a URI sibling would bind over
            // ignored bytes. The raw explicit wrapper must carry its
            // complete content.
            const otherName = (trailer: boolean): asn1js.Constructed => {
                const kids: asn1js.BaseBlock[] = [
                    new asn1js.ObjectIdentifier({ value: "1.2.3.4" }),
                    contextNode(0, [new asn1js.IA5String({ value: "other" })]),
                ];
                if (trailer) kids.push(new asn1js.Null());
                return contextNode(0, kids);
            };
            const ediPartyName = (trailer: boolean): asn1js.Constructed => {
                const kids: asn1js.BaseBlock[] = [
                    contextNode(1, [new asn1js.PrintableString({ value: "party" })]),
                ];
                if (trailer) kids.push(new asn1js.Null());
                return contextNode(5, kids);
            };
            const shapes: ((trailer: boolean) => asn1js.Constructed)[] = [otherName, ediPartyName];
            for (const shape of shapes) {
                for (const trailer of [true, false]) {
                    const names: asn1js.BaseBlock[] = [uriNode(CRL_URL), shape(trailer)];
                    const point = new asn1js.Sequence({
                        value: [contextNode(0, [contextNode(0, names)])],
                    });
                    const scopedLeaf = await leafWithRawPoints([point]);
                    const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
                    const { result, fetcher } = await validateViaSession(scopedLeaf.cert, crl);
                    expect(fetcher.crlCalls).toBe(1);
                    expect(result?.revocationStatus).toBe("unknown");
                    expect(result?.isValid).toBe(false);
                    expect(result?.errors.join("\n")).toMatch(/distribution point/i);
                }
            }
        });

        it("rejects even a well-formed x400Address beside a bound URI", async () => {
            // Fix round 4 reversal: pkijs matches only the leading
            // children of [3] against its ORAddress schema and drops
            // nested trailers (CountryName payloads, second country
            // strings, administration/private-domain trailers,
            // domain-defined and extension-attribute trailers), so no
            // framing rule can separate a complete value from one with
            // ignored members. x400Address joins otherName and
            // ediPartyName outside the direct-issuance profile: any
            // [3] wrapper fails the CRL instead of resolving to an
            // ignored choice (x400 DPs are vanishingly rare; unknown
            // is the safe direction).
            const orAddress = new asn1js.Sequence({
                value: [
                    new asn1js.Constructed({
                        idBlock: { tagClass: 2, tagNumber: 1 },
                        value: [new asn1js.PrintableString({ value: "US" })],
                    }),
                ],
            });
            const point = new asn1js.Sequence({
                value: [
                    contextNode(0, [
                        contextNode(0, [uriNode(CRL_URL), contextNode(3, [orAddress])]),
                    ]),
                ],
            });
            const scopedLeaf = await leafWithRawPoints([point]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const { result, fetcher } = await validateViaSession(scopedLeaf.cert, crl);
            expect(fetcher.crlCalls).toBe(1);
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.isValid).toBe(false);
            expect(result?.errors.join("\n")).toMatch(/distribution point/i);
        });

        it("still rejects non-directoryName certificateIssuer choices", async () => {
            // Sweep pin: otherName framing can only resolve to outside
            // the direct-only profile (or malformed), never decisive.
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        entryExtensions: [
                            rawCertificateIssuer([
                                contextNode(0, [
                                    new asn1js.ObjectIdentifier({ value: "1.2.3.4" }),
                                    contextNode(0, [new asn1js.IA5String({ value: "o" })]),
                                ]),
                            ]),
                        ],
                    },
                ],
            });
            const { result, fetcher } = await validateViaSession(leaf.cert, crl);
            expect(fetcher.crlCalls).toBe(1);
            expect(result?.revocationStatus).toBe("unknown");
            expect(result?.errors.join("\n")).toMatch(/certificate issuer/i);
        });

        it("accepts a raw-built canonical distributionPoint through the session", async () => {
            // Control: the raw framing walk must accept the canonical
            // [0]{fullName{URI}} shape it newly inspects.
            const scopedLeaf = await leafWithRawPoints([namePoint(CRL_URL)]);
            const crl = await freshCRL(ca, { entries: [{ serial: 9999 }] });
            const { result, fetcher } = await validateViaSession(scopedLeaf.cert, crl);
            expect(fetcher.crlCalls).toBe(1);
            expect(result?.revocationStatus).toBe("good");
            expect(result?.isValid).toBe(true);
            expect(result?.errors).toEqual([]);
        });
    });

    describe("fix round 4: x400Address deferral (sol re-review 2)", () => {
        function contextNode(tag: number, children: asn1js.BaseBlock[]): asn1js.Constructed {
            return new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: tag },
                value: children,
            });
        }

        function applicationNode(tag: number, children: asn1js.BaseBlock[]): asn1js.Constructed {
            return new asn1js.Constructed({
                idBlock: { tagClass: 2, tagNumber: tag },
                value: children,
            });
        }

        function uriNode(url: string): asn1js.Primitive {
            return new asn1js.Primitive({
                idBlock: { tagClass: 3, tagNumber: 6 },
                valueHex: toArrayBuffer(new TextEncoder().encode(url)),
            });
        }

        function hexToBytes(hex: string): Uint8Array {
            const out = new Uint8Array(hex.length / 2);
            for (let index = 0; index < out.length; index += 1) {
                out[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
            }
            return out;
        }

        /** Decodes exact reviewer bytes behind a complete-consumption gate. */
        function derNode(hex: string): asn1js.BaseBlock {
            const bytes = hexToBytes(hex);
            const parsed = asn1js.fromBER(toArrayBuffer(bytes.slice()));
            if (parsed.offset === -1 || parsed.offset !== bytes.length) {
                throw new Error("fixture DER is incomplete");
            }
            return parsed.result;
        }

        function x400Node(orAddressKids: asn1js.BaseBlock[]): asn1js.Constructed {
            return contextNode(3, [new asn1js.Sequence({ value: orAddressKids })]);
        }

        /**
         * [3] with direct children (pkijs models the ORAddress members
         * -- standard-attributes SEQUENCE, domain-defined SEQUENCE,
         * extension-attributes SET -- as immediate children of [3], not
         * nested in one ORAddress SEQUENCE).
         */
        function x400Direct(kids: asn1js.BaseBlock[]): asn1js.Constructed {
            return contextNode(3, kids);
        }

        function implicitPrimitive(tag: number, content: Uint8Array): asn1js.Primitive {
            return new asn1js.Primitive({
                idBlock: { tagClass: 3, tagNumber: tag },
                valueHex: toArrayBuffer(content.slice()),
            });
        }

        function printable(value: string): asn1js.PrintableString {
            return new asn1js.PrintableString({ value });
        }

        function countryName(...kids: asn1js.BaseBlock[]): asn1js.Constructed {
            return applicationNode(1, kids);
        }

        /**
         * The six [3] shapes: the reviewer's exact CountryName-trailer
         * bytes plus the five extra decisive shapes from the report
         * (second country string, administration-domain, private-domain,
         * domain-defined-attribute, and extension-attribute trailers).
         * Every shape sits beside a bound URI in one fullName; each must
         * fail closed whether the leaf serial is absent or listed.
         */
        function x400Shapes(): { label: string; node: asn1js.BaseBlock }[] {
            const wellFormedCountry = (): asn1js.Constructed => countryName(printable("US"));
            return [
                {
                    // [3]{SEQUENCE{[APPLICATION 1]{PrintableString("US"),
                    // NULL}}}: the tagged CountryName CHOICE carries an
                    // extra NULL pkijs drops.
                    label: "reviewer CountryName NULL trailer",
                    node: derNode("a30a30086106130255530500"),
                },
                {
                    label: "second country string",
                    node: x400Node([countryName(printable("US"), printable("GB"))]),
                },
                {
                    label: "administration-domain NULL trailer",
                    node: x400Node([applicationNode(2, [printable("ADM"), new asn1js.Null()])]),
                },
                {
                    // pkijs models private-domain-name as [2]{CHOICE}
                    // inside the standard-attributes SEQUENCE and drops
                    // the second member.
                    label: "private-domain NULL trailer",
                    node: x400Node([contextNode(2, [printable("PRV"), new asn1js.Null()])]),
                },
                {
                    // pkijs models one domain-defined attribute as a
                    // second [3] child SEQUENCE{type, value} and drops
                    // the trailer.
                    label: "domain-defined-attribute NULL trailer",
                    node: x400Direct([
                        new asn1js.Sequence({ value: [wellFormedCountry()] }),
                        new asn1js.Sequence({
                            value: [printable("TYPE"), printable("VAL"), new asn1js.Null()],
                        }),
                    ]),
                },
                {
                    // pkijs models extension-attributes as a trailing
                    // SET{[0], [1]{ANY}} child of [3] and drops the
                    // trailer.
                    label: "extension-attribute NULL trailer",
                    node: x400Direct([
                        new asn1js.Sequence({ value: [wellFormedCountry()] }),
                        new asn1js.Set({
                            value: [
                                implicitPrimitive(0, new Uint8Array([1])),
                                contextNode(1, [printable("V")]),
                                new asn1js.Null(),
                            ],
                        }),
                    ]),
                },
            ];
        }

        async function leafWithX400(x400: asn1js.BaseBlock): Promise<TestLeaf> {
            const point = new asn1js.Sequence({
                value: [contextNode(0, [contextNode(0, [uriNode(CRL_URL), x400])])],
            });
            const cdp = new asn1js.Sequence({ value: [point] });
            return createTestLeaf(ca, {
                commonName: "T07 R4 X400 Leaf",
                serial: 3001,
                crlDPExtension: new pkijs.Extension({
                    extnID: "2.5.29.31",
                    critical: false,
                    extnValue: cdp.toBER(false),
                }),
            });
        }

        async function validateViaSession(cert: pkijs.Certificate, crl: Uint8Array) {
            const fetcher = recordingFetcher({ crl });
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: 24 * 60 * 60 * 1000,
            });
            session.queueCertificate(cert, { issuer: ca.cert });
            const [result] = await session.validateAll();
            return { result, fetcher };
        }

        it.each(x400Shapes())(
            "fails closed direct and session, absent and listed: $label",
            async ({ node }) => {
                const scopedLeaf = await leafWithX400(node);
                for (const serial of [9999, 3001]) {
                    const crl = await freshCRL(ca, { entries: [{ serial }] });
                    const direct = await validateDirect(crl, { cert: scopedLeaf.cert });
                    expect(direct.status).toBe("unknown");
                    const { result, fetcher } = await validateViaSession(scopedLeaf.cert, crl);
                    expect(fetcher.crlCalls).toBe(1);
                    expect(result?.revocationStatus).toBe("unknown");
                    expect(result?.isValid).toBe(false);
                    expect(result?.errors.join("\n")).toMatch(/distribution point/i);
                }
            }
        );
    });

    describe("fix round 4: AKI framing (preemption sweep)", () => {
        function contextNode(tag: number, children: asn1js.BaseBlock[]): asn1js.Constructed {
            return new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: tag },
                value: children,
            });
        }

        function applicationNode(tag: number, children: asn1js.BaseBlock[]): asn1js.Constructed {
            return new asn1js.Constructed({
                idBlock: { tagClass: 2, tagNumber: tag },
                value: children,
            });
        }

        function implicitPrimitive(tag: number, content: Uint8Array): asn1js.Primitive {
            return new asn1js.Primitive({
                idBlock: { tagClass: 3, tagNumber: tag },
                valueHex: toArrayBuffer(content.slice()),
            });
        }

        function uriNode(url: string): asn1js.Primitive {
            return new asn1js.Primitive({
                idBlock: { tagClass: 3, tagNumber: 6 },
                valueHex: toArrayBuffer(new TextEncoder().encode(url)),
            });
        }

        /** Non-critical AKI extension from a raw SEQUENCE payload. */
        function akiExtension(payload: asn1js.Sequence): pkijs.Extension {
            return new pkijs.Extension({
                extnID: "2.5.29.35",
                critical: false,
                extnValue: payload.toBER(false),
            });
        }

        function keyId(): asn1js.Primitive {
            return implicitPrimitive(0, new Uint8Array([0xaa, 0xbb]));
        }

        function serialNumber(): asn1js.Primitive {
            return implicitPrimitive(2, new Uint8Array([0x07]));
        }

        /**
         * Malformed AKI payloads the sweep found decisive: pkijs
         * matches only leading SEQUENCE members (a trailer after the
         * last matched member is dropped) and only leading [1]
         * children (nested undecidable wrappers and split directory
         * names inside authorityCertIssuer are dropped while the
         * keyIdentifier still binds). An empty [1] violates
         * GeneralNames SIZE (1..MAX) and an empty RDN SET violates
         * RFC 5280 4.1.2.4; both decoded and stayed decisive.
         */
        function malformedAkiShapes(): { label: string; build: () => asn1js.Sequence }[] {
            const issuer = contextNode(1, [uriNode(CRL_URL)]);
            return [
                {
                    label: "trailer after serial-only [2]",
                    build: () =>
                        new asn1js.Sequence({
                            value: [serialNumber(), new asn1js.Null()],
                        }),
                },
                {
                    label: "trailer after full triple",
                    build: () =>
                        new asn1js.Sequence({
                            value: [keyId(), issuer, serialNumber(), new asn1js.Null()],
                        }),
                },
                {
                    // Already fail-closed pre-fix (pkijs rejects the
                    // mid-sequence trailer); pinned so the raw walk
                    // keeps rejecting it for the same reason.
                    label: "trailer after [1]",
                    build: () =>
                        new asn1js.Sequence({
                            value: [issuer, new asn1js.Null()],
                        }),
                },
                {
                    label: "[1] with x400Address trailer",
                    build: () =>
                        new asn1js.Sequence({
                            value: [
                                keyId(),
                                contextNode(1, [
                                    contextNode(3, [
                                        new asn1js.Sequence({
                                            value: [
                                                applicationNode(1, [
                                                    new asn1js.PrintableString({ value: "US" }),
                                                    new asn1js.Null(),
                                                ]),
                                            ],
                                        }),
                                    ]),
                                ]),
                            ],
                        }),
                },
                {
                    label: "[1] with split directoryName",
                    build: () =>
                        new asn1js.Sequence({
                            value: [
                                keyId(),
                                contextNode(1, [
                                    contextNode(4, [ca.cert.subject.toSchema(), new asn1js.Null()]),
                                ]),
                            ],
                        }),
                },
                {
                    label: "[1] with otherName trailer",
                    build: () =>
                        new asn1js.Sequence({
                            value: [
                                keyId(),
                                contextNode(1, [
                                    contextNode(0, [
                                        new asn1js.ObjectIdentifier({ value: "1.2.3.4" }),
                                        contextNode(0, [new asn1js.IA5String({ value: "o" })]),
                                        new asn1js.Null(),
                                    ]),
                                ]),
                            ],
                        }),
                },
                {
                    label: "empty [1]",
                    build: () => new asn1js.Sequence({ value: [keyId(), contextNode(1, [])] }),
                },
                {
                    label: "[1] with empty-RDN directoryName",
                    build: () =>
                        new asn1js.Sequence({
                            value: [
                                keyId(),
                                contextNode(1, [
                                    contextNode(4, [
                                        new asn1js.Sequence({
                                            value: [new asn1js.Set({ value: [] })],
                                        }),
                                    ]),
                                ]),
                            ],
                        }),
                },
            ];
        }

        /**
         * Well-formed non-critical AKI payloads whose [1]/[2] content
         * stays verdict-neutral (ignored): the framing fix must not
         * narrow the profile for complete values.
         */
        function wellFormedAkiShapes(): { label: string; build: () => asn1js.Sequence }[] {
            return [
                {
                    label: "full triple",
                    build: () =>
                        new asn1js.Sequence({
                            value: [keyId(), contextNode(1, [uriNode(CRL_URL)]), serialNumber()],
                        }),
                },
                {
                    label: "[1] with directoryName",
                    build: () =>
                        new asn1js.Sequence({
                            value: [
                                keyId(),
                                contextNode(1, [contextNode(4, [ca.cert.subject.toSchema()])]),
                            ],
                        }),
                },
            ];
        }

        async function validateViaSession(cert: pkijs.Certificate, crl: Uint8Array) {
            const fetcher = recordingFetcher({ crl });
            const session = new ValidationSession({
                fetcher,
                checkDate: CHECK_DATE,
                clockSkewMs: CLOCK_SKEW_MS,
                maxAgeWithoutNextUpdateMs: 24 * 60 * 60 * 1000,
            });
            session.queueCertificate(cert, { issuer: ca.cert });
            const [result] = await session.validateAll();
            return { result, fetcher };
        }

        it.each(malformedAkiShapes())(
            "fails closed direct and session, absent and listed: $label",
            async ({ build }) => {
                const payload = build();
                for (const serial of [9999, 2001]) {
                    const crl = await freshCRL(ca, {
                        entries: [{ serial }],
                        crlExtensions: [akiExtension(payload)],
                    });
                    const direct = await validateDirect(crl);
                    expect(direct.status).toBe("unknown");
                    const { result, fetcher } = await validateViaSession(leaf.cert, crl);
                    expect(fetcher.crlCalls).toBe(1);
                    expect(result?.revocationStatus).toBe("unknown");
                    expect(result?.isValid).toBe(false);
                    expect(result?.errors.join("\n")).toMatch(/authority key identifier/i);
                }
            }
        );

        it.each(wellFormedAkiShapes())(
            "still ignores well-formed non-critical content: $label",
            async ({ build }) => {
                const payload = build();
                for (const [serial, status, isValid] of [
                    [9999, "good", true],
                    [2001, "revoked", false],
                ] as const) {
                    const crl = await freshCRL(ca, {
                        entries: [{ serial }],
                        crlExtensions: [akiExtension(payload)],
                    });
                    const direct = await validateDirect(crl);
                    expect(direct.status).toBe(status);
                    const { result, fetcher } = await validateViaSession(leaf.cert, crl);
                    expect(fetcher.crlCalls).toBe(1);
                    expect(result?.revocationStatus).toBe(status);
                    expect(result?.isValid).toBe(isValid);
                    expect(result?.errors).toEqual([]);
                }
            }
        );
    });

    describe("T09b revocationDate evaluation (item 5)", () => {
        // RevocationDate rides UTCTime (whole seconds), so the +/-1 ms
        // boundary is pinned by shifting the skew knob against fixed
        // bytes instead of shifting the date (the T06 F6 technique).
        const REVOCATION_BOUNDARY = new Date(THIS_UPDATE.getTime() + CLOCK_SKEW_MS);

        it("reports revoked when revocationDate exactly equals thisUpdate plus skew", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serial: 2001, revocationDate: REVOCATION_BOUNDARY }],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("revoked");
            expect(result.errors).toEqual([]);
        });

        it("reports revoked when revocationDate predates thisUpdate plus skew", async () => {
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        revocationDate: new Date("2026-05-01T11:04:59Z"),
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("revoked");
            expect(result.errors).toEqual([]);
        });

        it("reports unknown when the skew shrinks one millisecond below the boundary", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serial: 2001, revocationDate: REVOCATION_BOUNDARY }],
            });
            const result = await validateDirect(crl, { clockSkewMs: CLOCK_SKEW_MS - 1 });
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/revocationDate/);
        });

        it("reports revoked when the skew grows one millisecond above the boundary", async () => {
            const crl = await freshCRL(ca, {
                entries: [{ serial: 2001, revocationDate: REVOCATION_BOUNDARY }],
            });
            const result = await validateDirect(crl, { clockSkewMs: CLOCK_SKEW_MS + 1 });
            expect(result.status).toBe("revoked");
            expect(result.errors).toEqual([]);
        });

        it("reports unknown when revocationDate is past thisUpdate plus skew", async () => {
            const crl = await freshCRL(ca, {
                entries: [
                    {
                        serial: 2001,
                        revocationDate: new Date("2026-05-01T11:05:01Z"),
                    },
                ],
            });
            const result = await validateDirect(crl);
            expect(result.status).toBe("unknown");
            expect(result.errors.join("\n")).toMatch(/revocationDate/);
        });

        it("treats non-finite and non-Date revocationDate as unknown (direct unit)", async () => {
            // Unreachable via DER (UTCTime garbage rolls over to a
            // finite instant or throws at parse; pkijs Time.value is
            // always a Date), pinned directly as defense-in-depth.
            const { checkRevocationDate } = await import("../../../core/src/pki/crl-validation.js");
            expect(
                checkRevocationDate(new Date(NaN), THIS_UPDATE.getTime(), CLOCK_SKEW_MS)
            ).toMatch(/non-finite revocationDate/);
            expect(
                checkRevocationDate("2026-05-01T11:00:00Z", THIS_UPDATE.getTime(), CLOCK_SKEW_MS)
            ).toMatch(/unsupported shape/);
            expect(checkRevocationDate(null, THIS_UPDATE.getTime(), CLOCK_SKEW_MS)).toMatch(
                /unsupported shape/
            );
            expect(
                checkRevocationDate(REVOCATION_BOUNDARY, THIS_UPDATE.getTime(), CLOCK_SKEW_MS)
            ).toBeNull();
        });
    });
});
