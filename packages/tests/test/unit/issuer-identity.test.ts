import { beforeAll, describe, expect, it } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { ValidationSession } from "../../../core/src/pki/validation-session.js";
import * as validationSessionModule from "../../../core/src/pki/validation-session.js";
import * as certUtils from "../../../core/src/pki/cert-utils.js";
import { createOCSPRequest } from "../../../core/src/pki/ocsp-utils.js";
import type { RevocationDataFetcher } from "../../../core/src/pki/validation-types.js";
import { bytesToHex, toArrayBuffer } from "../../../core/src/utils.js";
import { generateRSAKeyPair, importKeyForCertificate } from "../utils/crypto.js";
import { createCrlFixture, createOcspResponseCandidate } from "../fixtures/revocation-material.js";

// T05: issuers are verified, not name-matched. queueChain stores candidates;
// resolveVerifiedIssuer narrows by names/AKI/SKI and lets the target
// signature decide. Session lookup and LTV export use exact certificate
// bytes, never serial-only identity.

const OCSP_URL = "http://ocsp.example.com/";
const OTHER_OCSP_URL = "http://other-ocsp.example.com/";
const CRL_URL = "http://crl.example.com/ca.crl";
const OTHER_CRL_URL = "http://other-crl.example.com/ca.crl";

interface KeyPair {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
}

function roundTripCertificate(cert: pkijs.Certificate): pkijs.Certificate {
    const der = new Uint8Array(cert.toSchema(true).toBER(false));
    const asn1 = asn1js.fromBER(toArrayBuffer(der));
    if (asn1.offset === -1) throw new Error("test certificate is not DER");
    return new pkijs.Certificate({ schema: asn1.result });
}

function distinguishedName(commonName: string): pkijs.RelativeDistinguishedNames {
    const name = new pkijs.RelativeDistinguishedNames();
    name.typesAndValues.push(
        new pkijs.AttributeTypeAndValue({
            type: "2.5.4.3",
            value: new asn1js.PrintableString({ value: commonName }),
        })
    );
    return name;
}

function skiExtension(keyId: Uint8Array): pkijs.Extension {
    return new pkijs.Extension({
        extnID: "2.5.29.14",
        critical: false,
        extnValue: new asn1js.OctetString({ valueHex: new Uint8Array(keyId).buffer }).toBER(false),
    });
}

function akiExtension(keyId: Uint8Array): pkijs.Extension {
    const aki = new pkijs.AuthorityKeyIdentifier({
        keyIdentifier: new asn1js.OctetString({ valueHex: new Uint8Array(keyId).buffer }),
    });
    return new pkijs.Extension({
        extnID: "2.5.29.35",
        critical: false,
        extnValue: aki.toSchema().toBER(false),
    });
}

function endpointExtensions(options: { ocspUrl?: string; crlUrls?: string[] }): pkijs.Extension[] {
    const extensions: pkijs.Extension[] = [];
    if (options.ocspUrl) {
        const aia = new pkijs.InfoAccess({
            accessDescriptions: [
                new pkijs.AccessDescription({
                    accessMethod: "1.3.6.1.5.5.7.48.1",
                    accessLocation: new pkijs.GeneralName({ type: 6, value: options.ocspUrl }),
                }),
            ],
        });
        extensions.push(
            new pkijs.Extension({
                extnID: "1.3.6.1.5.5.7.1.1",
                critical: false,
                extnValue: aia.toSchema().toBER(false),
            })
        );
    }
    if (options.crlUrls && options.crlUrls.length > 0) {
        const cdp = new pkijs.CRLDistributionPoints({
            distributionPoints: options.crlUrls.map(
                (crlUrl) =>
                    new pkijs.DistributionPoint({
                        distributionPoint: [new pkijs.GeneralName({ type: 6, value: crlUrl })],
                    })
            ),
        });
        extensions.push(
            new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: cdp.toSchema().toBER(false),
            })
        );
    }
    return extensions;
}

async function createCertificate(options: {
    subject: string;
    issuerName: string;
    serial: number;
    keys: KeyPair;
    signerKeys: KeyPair;
    ski?: Uint8Array;
    aki?: Uint8Array;
    ocspUrl?: string;
    crlUrls?: string[];
}): Promise<pkijs.Certificate> {
    const cert = new pkijs.Certificate();
    cert.version = 2;
    cert.serialNumber = new asn1js.Integer({ value: options.serial });
    cert.subject = distinguishedName(options.subject);
    cert.issuer = distinguishedName(options.issuerName);
    cert.notBefore = new pkijs.Time({ value: new Date("2020-01-01T00:00:00Z") });
    cert.notAfter = new pkijs.Time({ value: new Date("2030-01-01T00:00:00Z") });
    cert.subjectPublicKeyInfo = await importKeyForCertificate(options.keys.publicKey);
    const extensions: pkijs.Extension[] = [];
    if (options.ski) extensions.push(skiExtension(options.ski));
    if (options.aki) extensions.push(akiExtension(options.aki));
    extensions.push(...endpointExtensions({ ocspUrl: options.ocspUrl, crlUrls: options.crlUrls }));
    if (extensions.length > 0) {
        cert.extensions = extensions;
    }
    await cert.sign(options.signerKeys.privateKey, "SHA-256");
    return roundTripCertificate(cert);
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

function certIdHashes(request: Uint8Array): { nameHash: string; keyHash: string; serial: string } {
    const asn1 = asn1js.fromBER(toArrayBuffer(request.slice()));
    if (asn1.offset === -1) throw new Error("captured OCSP request is not DER");
    const parsed = new pkijs.OCSPRequest({ schema: asn1.result });
    const first = parsed.tbsRequest.requestList[0];
    if (!first) throw new Error("captured OCSP request has no requests");
    return {
        nameHash: bytesToHex(first.reqCert.issuerNameHash.valueBlock.valueHexView),
        keyHash: bytesToHex(first.reqCert.issuerKeyHash.valueBlock.valueHexView),
        serial: bytesToHex(first.reqCert.serialNumber.valueBlock.valueHexView),
    };
}

describe("resolveVerifiedIssuer (T05)", () => {
    let caOldKeys: KeyPair;
    let caNewKeys: KeyPair;
    let plainKeys: KeyPair;
    let leafKeys: KeyPair;
    let caOld: pkijs.Certificate;
    let caNew: pkijs.Certificate;
    let caNewNoSki: pkijs.Certificate;
    let caPlain: pkijs.Certificate;
    let leaf: pkijs.Certificate;
    let leafNoAki: pkijs.Certificate;

    beforeAll(async () => {
        caOldKeys = await generateRSAKeyPair();
        caNewKeys = await generateRSAKeyPair();
        plainKeys = await generateRSAKeyPair();
        leafKeys = await generateRSAKeyPair();
        const oldSki = new Uint8Array(20).fill(0x11);
        const newSki = new Uint8Array(20).fill(0x22);
        caOld = await createCertificate({
            subject: "Identity CA",
            issuerName: "Identity CA",
            serial: 11,
            keys: caOldKeys,
            signerKeys: caOldKeys,
            ski: oldSki,
        });
        caNew = await createCertificate({
            subject: "Identity CA",
            issuerName: "Identity CA",
            serial: 22,
            keys: caNewKeys,
            signerKeys: caNewKeys,
            ski: newSki,
        });
        caNewNoSki = await createCertificate({
            subject: "Identity CA",
            issuerName: "Identity CA",
            serial: 66,
            keys: caNewKeys,
            signerKeys: caNewKeys,
        });
        caPlain = await createCertificate({
            subject: "Plain CA",
            issuerName: "Plain CA",
            serial: 44,
            keys: plainKeys,
            signerKeys: plainKeys,
        });
        leaf = await createCertificate({
            subject: "Identity Leaf",
            issuerName: "Identity CA",
            serial: 33,
            keys: leafKeys,
            signerKeys: caNewKeys,
            aki: newSki,
            ocspUrl: OCSP_URL,
        });
        leafNoAki = await createCertificate({
            subject: "Plain Leaf",
            issuerName: "Plain CA",
            serial: 55,
            keys: leafKeys,
            signerKeys: plainKeys,
        });
    });

    it("selects the AKI-indicated key among same-subject candidates", async () => {
        expect(typeof certUtils.resolveVerifiedIssuer).toBe("function");
        const verified = await certUtils.resolveVerifiedIssuer(leaf, [caOld, caNew]);
        expect(verified).toBe(caNew);
    });

    it("resolves by name and signature when AKI/SKI are missing", async () => {
        expect(typeof certUtils.resolveVerifiedIssuer).toBe("function");
        const verified = await certUtils.resolveVerifiedIssuer(leafNoAki, [caOld, caPlain]);
        expect(verified).toBe(caPlain);
    });

    it("resolves an AKI-set leaf via its SKI-less true issuer", async () => {
        expect(typeof certUtils.resolveVerifiedIssuer).toBe("function");
        const verified = await certUtils.resolveVerifiedIssuer(leaf, [caOld, caNewNoSki]);
        expect(verified).toBe(caNewNoSki);
    });

    it("returns undefined when no candidate issued the target", async () => {
        expect(typeof certUtils.resolveVerifiedIssuer).toBe("function");
        await expect(certUtils.resolveVerifiedIssuer(leaf, [caOld])).resolves.toBeUndefined();
        await expect(certUtils.resolveVerifiedIssuer(leaf, [caPlain])).resolves.toBeUndefined();
        await expect(certUtils.resolveVerifiedIssuer(leaf, [])).resolves.toBeUndefined();
    });

    it("never resolves the target to itself", async () => {
        expect(typeof certUtils.resolveVerifiedIssuer).toBe("function");
        await expect(certUtils.resolveVerifiedIssuer(leaf, [leaf, caOld])).resolves.toBeUndefined();
        await expect(certUtils.resolveVerifiedIssuer(caNew, [caNew])).resolves.toBeUndefined();
    });

    it("compares certificates by exact bytes, not serials", () => {
        expect(typeof certUtils.certificatesByteEqual).toBe("function");
        expect(certUtils.certificatesByteEqual(leaf, leaf)).toBe(true);
        expect(certUtils.certificatesByteEqual(leaf, caNew)).toBe(false);
        const twin = roundTripCertificate(leaf);
        expect(twin).not.toBe(leaf);
        expect(certUtils.certificatesByteEqual(leaf, twin)).toBe(true);
    });
});

describe("queueChain candidate storage (T05)", () => {
    let caOldKeys: KeyPair;
    let caNewKeys: KeyPair;
    let serialKeys: KeyPair;
    let leafKeys: KeyPair;
    let caOld: pkijs.Certificate;
    let caNew: pkijs.Certificate;
    let leaf: pkijs.Certificate;
    let serialCa: pkijs.Certificate;
    let serialLeaf: pkijs.Certificate;
    let lonelyLeaf: pkijs.Certificate;

    beforeAll(async () => {
        caOldKeys = await generateRSAKeyPair();
        caNewKeys = await generateRSAKeyPair();
        serialKeys = await generateRSAKeyPair();
        leafKeys = await generateRSAKeyPair();
        const oldSki = new Uint8Array(20).fill(0x11);
        const newSki = new Uint8Array(20).fill(0x22);
        caOld = await createCertificate({
            subject: "Chain CA",
            issuerName: "Chain CA",
            serial: 101,
            keys: caOldKeys,
            signerKeys: caOldKeys,
            ski: oldSki,
        });
        caNew = await createCertificate({
            subject: "Chain CA",
            issuerName: "Chain CA",
            serial: 102,
            keys: caNewKeys,
            signerKeys: caNewKeys,
            ski: newSki,
        });
        leaf = await createCertificate({
            subject: "Chain Leaf",
            issuerName: "Chain CA",
            serial: 103,
            keys: leafKeys,
            signerKeys: caNewKeys,
            aki: newSki,
            ocspUrl: OCSP_URL,
        });
        serialCa = await createCertificate({
            subject: "Serial CA",
            issuerName: "Serial CA",
            serial: 77,
            keys: serialKeys,
            signerKeys: serialKeys,
        });
        // Self-issued name (subject == issuer) but issued by serialCa: the
        // serial twin of its own issuer.
        serialLeaf = await createCertificate({
            subject: "Serial CA",
            issuerName: "Serial CA",
            serial: 77,
            keys: leafKeys,
            signerKeys: serialKeys,
            ocspUrl: OCSP_URL,
        });
        // Self-issued and alone: no queued certificate issued it.
        lonelyLeaf = await createCertificate({
            subject: "Lonely CA",
            issuerName: "Lonely CA",
            serial: 88,
            keys: leafKeys,
            signerKeys: leafKeys,
            ocspUrl: OCSP_URL,
        });
    });

    it("builds the OCSP request with the verified issuer, not the first name match", async () => {
        const fetcher = recordingFetcher({ ocsp: createOcspResponseCandidate("good") });
        const session = new ValidationSession({ fetcher });
        session.queueChain([leaf, caOld, caNew]);

        const [result] = await session.validateAll();
        expect(result?.revocationStatus).toBe("unknown");
        expect(fetcher.ocspCalls).toBe(1);
        const captured = fetcher.ocspRequests[0];
        if (!captured) throw new Error("expected the session to build an OCSP request");
        expect(certIdHashes(captured)).toEqual(
            certIdHashes(await createOCSPRequest(leaf, caNew, { includeNonce: false }))
        );
        expect(certIdHashes(captured)).not.toEqual(
            certIdHashes(await createOCSPRequest(leaf, caOld, { includeNonce: false }))
        );
    });

    it("rejects an explicit issuer that did not issue the target", async () => {
        const fetcher = recordingFetcher({ ocsp: createOcspResponseCandidate("good") });
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(leaf, { issuer: caOld });

        const [result] = await session.validateAll();
        expect(fetcher.ocspCalls).toBe(0);
        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.sources).toEqual([]);
        expect(result?.errors.join("\n")).toMatch(/did not issue/);
    });

    it("keeps a same-serial issuer as a candidate via byte identity", async () => {
        const fetcher = recordingFetcher({ ocsp: createOcspResponseCandidate("good") });
        const session = new ValidationSession({ fetcher });
        session.queueChain([serialLeaf, serialCa]);

        const [result] = await session.validateAll();
        expect(result?.revocationStatus).toBe("unknown");
        expect(fetcher.ocspCalls).toBe(1);
        const captured = fetcher.ocspRequests[0];
        if (!captured) throw new Error("expected the session to build an OCSP request");
        expect(certIdHashes(captured)).toEqual(
            certIdHashes(await createOCSPRequest(serialLeaf, serialCa, { includeNonce: false }))
        );
        expect(certIdHashes(captured)).not.toEqual(
            certIdHashes(await createOCSPRequest(serialLeaf, serialLeaf, { includeNonce: false }))
        );
    });

    it("yields unknown with an issuer diagnostic when no candidate verifies", async () => {
        const fetcher = recordingFetcher({ ocsp: createOcspResponseCandidate("good") });
        const session = new ValidationSession({ fetcher });
        session.queueChain([leaf]);

        const [result] = await session.validateAll();
        expect(fetcher.ocspCalls).toBe(0);
        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.sources).toEqual([]);
        expect(result?.errors.join("\n")).toMatch(/issuer/i);
    });

    it("does not resolve a self-issued leaf to itself for OCSP", async () => {
        const fetcher = recordingFetcher({ ocsp: createOcspResponseCandidate("good") });
        const session = new ValidationSession({ fetcher });
        session.queueChain([lonelyLeaf]);

        const [result] = await session.validateAll();
        expect(fetcher.ocspCalls).toBe(0);
        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.sources).toEqual([]);
        expect(result?.errors.join("\n")).toMatch(/issuer/i);
    });

    it("rejects an explicit same-object self-issuer without fetching", async () => {
        const fetcher = recordingFetcher({ ocsp: createOcspResponseCandidate("good") });
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(lonelyLeaf, { issuer: lonelyLeaf });

        const [result] = await session.validateAll();
        expect(fetcher.ocspCalls).toBe(0);
        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.sources).toEqual([]);
        expect(result?.errors.join("\n")).toMatch(/did not issue/);
    });

    it("rejects an explicit parsed-twin self-issuer without fetching", async () => {
        const fetcher = recordingFetcher({ ocsp: createOcspResponseCandidate("good") });
        const session = new ValidationSession({ fetcher });
        const twin = roundTripCertificate(lonelyLeaf);
        expect(twin).not.toBe(lonelyLeaf);
        session.queueCertificate(lonelyLeaf, { issuer: twin });

        const [result] = await session.validateAll();
        expect(fetcher.ocspCalls).toBe(0);
        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.sources).toEqual([]);
        expect(result?.errors.join("\n")).toMatch(/did not issue/);
    });
});

describe("getResultForCert byte identity (T05)", () => {
    let alphaKeys: KeyPair;
    let betaKeys: KeyPair;
    let leafKeys: KeyPair;
    let caAlpha: pkijs.Certificate;
    let caBeta: pkijs.Certificate;
    let certA: pkijs.Certificate;
    let certB: pkijs.Certificate;

    beforeAll(async () => {
        alphaKeys = await generateRSAKeyPair();
        betaKeys = await generateRSAKeyPair();
        leafKeys = await generateRSAKeyPair();
        caAlpha = await createCertificate({
            subject: "Issuer Alpha",
            issuerName: "Issuer Alpha",
            serial: 201,
            keys: alphaKeys,
            signerKeys: alphaKeys,
        });
        caBeta = await createCertificate({
            subject: "Issuer Beta",
            issuerName: "Issuer Beta",
            serial: 202,
            keys: betaKeys,
            signerKeys: betaKeys,
        });
        // Serial twins under different issuers.
        certA = await createCertificate({
            subject: "Twin A",
            issuerName: "Issuer Alpha",
            serial: 555,
            keys: leafKeys,
            signerKeys: alphaKeys,
            ocspUrl: OCSP_URL,
        });
        certB = await createCertificate({
            subject: "Twin B",
            issuerName: "Issuer Beta",
            serial: 555,
            keys: leafKeys,
            signerKeys: betaKeys,
            crlUrls: [CRL_URL],
        });
    });

    it("returns the result for the exact certificate, not a serial twin", async () => {
        const fetcher = recordingFetcher({
            ocsp: createOcspResponseCandidate("good"),
            crl: createCrlFixture({ crlNumber: 3 }),
        });
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(certA, { issuer: caAlpha });
        session.queueCertificate(certB, { issuer: caBeta });
        await session.validateAll();

        expect(session.getResultForCert(certA)?.sources).toEqual(["OCSP"]);
        expect(session.getResultForCert(certB)?.sources).toEqual(["CRL"]);
    });

    it("returns undefined for a certificate that was never queued", async () => {
        const fetcher = recordingFetcher({ ocsp: createOcspResponseCandidate("good") });
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(certA, { issuer: caAlpha });
        await session.validateAll();

        expect(session.getResultForCert(certB)).toBeUndefined();
    });
});

describe("exportLTVData exact-byte dedup (T05)", () => {
    let alphaKeys: KeyPair;
    let betaKeys: KeyPair;
    let leafKeys: KeyPair;
    let caAlpha: pkijs.Certificate;
    let caBeta: pkijs.Certificate;
    let twoCrlLeaf: pkijs.Certificate;
    let certO1: pkijs.Certificate;
    let certO2: pkijs.Certificate;

    beforeAll(async () => {
        alphaKeys = await generateRSAKeyPair();
        betaKeys = await generateRSAKeyPair();
        leafKeys = await generateRSAKeyPair();
        caAlpha = await createCertificate({
            subject: "Export Alpha",
            issuerName: "Export Alpha",
            serial: 301,
            keys: alphaKeys,
            signerKeys: alphaKeys,
        });
        caBeta = await createCertificate({
            subject: "Export Beta",
            issuerName: "Export Beta",
            serial: 302,
            keys: betaKeys,
            signerKeys: betaKeys,
        });
        twoCrlLeaf = await createCertificate({
            subject: "Two CRL Leaf",
            issuerName: "Export Alpha",
            serial: 303,
            keys: leafKeys,
            signerKeys: alphaKeys,
            crlUrls: [CRL_URL, OTHER_CRL_URL],
        });
        certO1 = await createCertificate({
            subject: "OCSP Leaf 1",
            issuerName: "Export Alpha",
            serial: 304,
            keys: leafKeys,
            signerKeys: alphaKeys,
            ocspUrl: OCSP_URL,
        });
        certO2 = await createCertificate({
            subject: "OCSP Leaf 2",
            issuerName: "Export Beta",
            serial: 305,
            keys: leafKeys,
            signerKeys: betaKeys,
            ocspUrl: OTHER_OCSP_URL,
        });
    });

    it("retains same-length same-prefix CRLs with different tails", async () => {
        const crlA = createCrlFixture({ crlNumber: 3 });
        expect(crlA.length).toBeGreaterThan(66);
        const crlB = new Uint8Array(crlA);
        const flipAt = crlB.length - 2;
        crlB[flipAt] = (crlB[flipAt] ?? 0) ^ 0xff;
        const fetcher: RevocationDataFetcher = {
            fetchOCSP: () => Promise.reject(new Error("no OCSP endpoint")),
            fetchCRL: (url: string) =>
                Promise.resolve(new Uint8Array(url === CRL_URL ? crlA : crlB)),
        };
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(twoCrlLeaf, { issuer: caAlpha });
        await session.validateAll();

        expect(session.exportLTVData().crls).toHaveLength(2);
    });

    it("retains same-length same-prefix OCSP responses with different tails", async () => {
        const ocspA = createOcspResponseCandidate("good");
        expect(ocspA.length).toBeGreaterThan(96);
        const ocspB = new Uint8Array(ocspA);
        ocspB[80] = (ocspB[80] ?? 0) ^ 0xff;
        const fetcher: RevocationDataFetcher = {
            fetchOCSP: (url: string) =>
                Promise.resolve(new Uint8Array(url === OCSP_URL ? ocspA : ocspB)),
            fetchCRL: () => Promise.reject(new Error("no CRL endpoint")),
        };
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(certO1, { issuer: caAlpha });
        session.queueCertificate(certO2, { issuer: caBeta });
        await session.validateAll();

        expect(session.exportLTVData().ocspResponses).toHaveLength(2);
    });
});

describe("certificate byte identity edge cases (T05 fix round 2)", () => {
    let caKeys: KeyPair;
    let leafKeys: KeyPair;
    let ca: pkijs.Certificate;
    let leaf: pkijs.Certificate;
    let alteredDer: Uint8Array;
    let altered: pkijs.Certificate;
    let inMemoryCa: pkijs.Certificate;
    let parsedTwin: pkijs.Certificate;

    function insertExplicitCriticalFalse(originalDer: Uint8Array): Uint8Array {
        const asn1 = asn1js.fromBER(toArrayBuffer(originalDer));
        if (asn1.offset === -1) throw new Error("test certificate is not DER");
        const certSeq = asn1.result as asn1js.Sequence;
        const tbs = certSeq.valueBlock.value[0];
        if (!(tbs instanceof asn1js.Sequence)) throw new Error("missing TBS");
        const extnConstructed = tbs.valueBlock.value.find(
            (v) =>
                v instanceof asn1js.Constructed &&
                v.idBlock.tagClass === 3 &&
                v.idBlock.tagNumber === 3
        );
        if (!(extnConstructed instanceof asn1js.Constructed)) throw new Error("missing extensions");
        const extnsSeq = extnConstructed.valueBlock.value[0];
        if (!(extnsSeq instanceof asn1js.Sequence)) throw new Error("missing extensions sequence");
        const firstExt = extnsSeq.valueBlock.value[0];
        if (!(firstExt instanceof asn1js.Sequence)) throw new Error("missing extension");
        if (firstExt.valueBlock.value.length !== 2)
            throw new Error("expected noncritical extension");
        const oid = firstExt.valueBlock.value[0];
        const oct = firstExt.valueBlock.value[1];
        if (!oid || !oct) throw new Error("missing extension parts");
        firstExt.valueBlock.value = [oid, new asn1js.Boolean({ value: false }), oct];
        return new Uint8Array(certSeq.toBER(false));
    }

    beforeAll(async () => {
        caKeys = await generateRSAKeyPair();
        leafKeys = await generateRSAKeyPair();
        ca = await createCertificate({
            subject: "P2 CA",
            issuerName: "P2 CA",
            serial: 901,
            keys: caKeys,
            signerKeys: caKeys,
        });
        leaf = await createCertificate({
            subject: "P2 Leaf",
            issuerName: "P2 CA",
            serial: 902,
            keys: leafKeys,
            signerKeys: caKeys,
            ocspUrl: OCSP_URL,
        });
        const originalDer = new Uint8Array(leaf.toSchema(true).toBER(false));
        alteredDer = insertExplicitCriticalFalse(originalDer);
        const alteredAsn1 = asn1js.fromBER(toArrayBuffer(alteredDer));
        if (alteredAsn1.offset === -1) throw new Error("altered certificate is not DER");
        altered = new pkijs.Certificate({ schema: alteredAsn1.result });

        inMemoryCa = new pkijs.Certificate();
        inMemoryCa.version = 2;
        inMemoryCa.serialNumber = new asn1js.Integer({ value: 903 });
        inMemoryCa.subject = distinguishedName("P2 InMemory CA");
        inMemoryCa.issuer = distinguishedName("P2 InMemory CA");
        inMemoryCa.subjectPublicKeyInfo = await importKeyForCertificate(caKeys.publicKey);
        await inMemoryCa.sign(caKeys.privateKey, "SHA-256");
        parsedTwin = roundTripCertificate(inMemoryCa);
    });

    it("distinguishes explicit critical=FALSE from omitted default", async () => {
        const originalDer = new Uint8Array(leaf.toSchema(true).toBER(false));
        expect(alteredDer.length).toBe(originalDer.length + 3);
        expect(altered.extensions?.[0]?.critical).toBe(false);
        expect(await certUtils.verifyIssuance(leaf, ca)).toBe(true);
        expect(await certUtils.verifyIssuance(altered, ca)).toBe(false);
        expect(certUtils.certificatesByteEqual(leaf, altered)).toBe(false);
    });

    it("does not confuse altered bytes with the queued result", async () => {
        const fetcher = recordingFetcher({ ocsp: createOcspResponseCandidate("good") });
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(leaf, { issuer: ca });
        await session.validateAll();
        expect(session.getResultForCert(leaf)?.sources).toEqual(["OCSP"]);
        expect(session.getResultForCert(altered)).toBeUndefined();
    });

    it("treats an in-memory cert and its parse as identical", () => {
        expect(parsedTwin).not.toBe(inMemoryCa);
        expect(certUtils.certificatesByteEqual(inMemoryCa, parsedTwin)).toBe(true);
    });

    it("excludes a parsed twin from self-issuance", async () => {
        await expect(
            certUtils.resolveVerifiedIssuer(inMemoryCa, [parsedTwin])
        ).resolves.toBeUndefined();
        await expect(
            certUtils.resolveVerifiedIssuer(parsedTwin, [inMemoryCa])
        ).resolves.toBeUndefined();
    });
});

describe("export dedup exactness (T05 fix round 2)", () => {
    it("deduplicates by exact bytes without hex strings", () => {
        expect(typeof validationSessionModule.deduplicateByteArtifacts).toBe("function");
        const dedupe = validationSessionModule.deduplicateByteArtifacts;
        const a = new Uint8Array(64).fill(0x30);
        const b = new Uint8Array(a);
        b[63] = 0x31;
        const aCopy = new Uint8Array(a);
        expect(dedupe([])).toEqual([]);
        expect(dedupe([a, aCopy])).toHaveLength(1);
        expect(dedupe([a, b])).toHaveLength(2);
        const short = new Uint8Array([1, 2, 3]);
        const long = new Uint8Array([1, 2, 3, 4]);
        expect(dedupe([short, long])).toHaveLength(2);
        expect(dedupe([a, b, aCopy])).toHaveLength(2);
    });
});

describe("certificate identity empty-TBS transitivity (T05 fix round 3)", () => {
    let caKeys: KeyPair;
    let leafKeys: KeyPair;
    let ca: pkijs.Certificate;
    let certA: pkijs.Certificate;
    let certB: pkijs.Certificate;
    let certC: pkijs.Certificate;
    let certCFromB: pkijs.Certificate;

    function insertExplicitCriticalFalse(originalDer: Uint8Array): Uint8Array {
        const asn1 = asn1js.fromBER(toArrayBuffer(originalDer));
        if (asn1.offset === -1) throw new Error("test certificate is not DER");
        const certSeq = asn1.result as asn1js.Sequence;
        const tbs = certSeq.valueBlock.value[0];
        if (!(tbs instanceof asn1js.Sequence)) throw new Error("missing TBS");
        const extnConstructed = tbs.valueBlock.value.find(
            (v) =>
                v instanceof asn1js.Constructed &&
                v.idBlock.tagClass === 3 &&
                v.idBlock.tagNumber === 3
        );
        if (!(extnConstructed instanceof asn1js.Constructed)) throw new Error("missing extensions");
        const extnsSeq = extnConstructed.valueBlock.value[0];
        if (!(extnsSeq instanceof asn1js.Sequence)) throw new Error("missing extensions sequence");
        const firstExt = extnsSeq.valueBlock.value[0];
        if (!(firstExt instanceof asn1js.Sequence)) throw new Error("missing extension");
        if (firstExt.valueBlock.value.length !== 2)
            throw new Error("expected noncritical extension");
        const oid = firstExt.valueBlock.value[0];
        const oct = firstExt.valueBlock.value[1];
        if (!oid || !oct) throw new Error("missing extension parts");
        firstExt.valueBlock.value = [oid, new asn1js.Boolean({ value: false }), oct];
        return new Uint8Array(certSeq.toBER(false));
    }

    beforeAll(async () => {
        caKeys = await generateRSAKeyPair();
        leafKeys = await generateRSAKeyPair();
        ca = await createCertificate({
            subject: "R3 CA",
            issuerName: "R3 CA",
            serial: 921,
            keys: caKeys,
            signerKeys: caKeys,
        });
        certA = await createCertificate({
            subject: "R3 Leaf",
            issuerName: "R3 CA",
            serial: 922,
            keys: leafKeys,
            signerKeys: caKeys,
            ocspUrl: OCSP_URL,
        });
        const originalDer = new Uint8Array(certA.toSchema(true).toBER(false));
        const alteredDer = insertExplicitCriticalFalse(originalDer);
        const alteredAsn1 = asn1js.fromBER(toArrayBuffer(alteredDer));
        if (alteredAsn1.offset === -1) throw new Error("altered certificate is not DER");
        certB = new pkijs.Certificate({ schema: alteredAsn1.result });
        // eslint-disable-next-line @typescript-eslint/no-misused-spread -- Astra triple: fresh object, empty tbsView
        certC = new pkijs.Certificate({ ...certA });
        // eslint-disable-next-line @typescript-eslint/no-misused-spread -- Astra triple: fresh object, empty tbsView
        certCFromB = new pkijs.Certificate({ ...certB });
    });

    it("pins Astra's construction: spread copies keep fields but no retained TBS", () => {
        expect(certA.tbsView.length).toBeGreaterThan(0);
        expect(certB.tbsView.length).toBeGreaterThan(0);
        expect(certC.tbsView.length).toBe(0);
        expect(certCFromB.tbsView.length).toBe(0);
    });

    it("compares the A/B/C triple transitively in both argument orders", () => {
        expect(certUtils.certificatesByteEqual(certA, certB)).toBe(false);
        expect(certUtils.certificatesByteEqual(certB, certA)).toBe(false);
        expect(certUtils.certificatesByteEqual(certA, certC)).toBe(true);
        expect(certUtils.certificatesByteEqual(certC, certA)).toBe(true);
        expect(certUtils.certificatesByteEqual(certB, certC)).toBe(false);
        expect(certUtils.certificatesByteEqual(certC, certB)).toBe(false);
    });

    it("does not return B's queued result for C", async () => {
        const fetcher = recordingFetcher({ ocsp: createOcspResponseCandidate("good") });
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(certB, { issuer: ca });
        await session.validateAll();
        expect(session.getResultForCert(certB)).toBeDefined();
        expect(session.getResultForCert(certC)).toBeUndefined();
    });

    it("treats B-field reconstruction exactly like A-field reconstruction", () => {
        // certCFromB's fields equal certA's fields (explicit FALSE parses to
        // the same value as the omitted default), so its reconstructed TBS
        // is byte-identical to certC's. Any byte-based comparison must treat
        // both alike: unequal to retained noncanonical B, equal to canonical
        // A. Expecting equal(B, C-from-B) would require re-encoding B, which
        // is the aliasing bug this round fixes.
        expect(certUtils.certificatesByteEqual(certB, certCFromB)).toBe(false);
        expect(certUtils.certificatesByteEqual(certCFromB, certB)).toBe(false);
        expect(certUtils.certificatesByteEqual(certA, certCFromB)).toBe(true);
        expect(certUtils.certificatesByteEqual(certCFromB, certA)).toBe(true);
    });
});

describe("export large-artifact memory (T05 fix round 2)", () => {
    it("exports an 8 MiB CRL under a 128 MiB heap", async () => {
        const heapCaKeys = await generateRSAKeyPair();
        const heapLeafKeys = await generateRSAKeyPair();
        const heapCa = await createCertificate({
            subject: "Heap CA",
            issuerName: "Heap CA",
            serial: 1001,
            keys: heapCaKeys,
            signerKeys: heapCaKeys,
        });
        const heapLeaf = await createCertificate({
            subject: "Heap Leaf",
            issuerName: "Heap CA",
            serial: 1002,
            keys: heapLeafKeys,
            signerKeys: heapCaKeys,
            crlUrls: [CRL_URL],
        });
        const leafDer = new Uint8Array(heapLeaf.toSchema(true).toBER(false));
        const caDer = new Uint8Array(heapCa.toSchema(true).toBER(false));

        const testDir = dirname(fileURLToPath(import.meta.url));
        const moduleRequire = createRequire(import.meta.url);
        const distPath = join(testDir, "../../../core/dist/advanced.js");
        const distUrl = pathToFileURL(distPath).href;
        const pkijsUrl = pathToFileURL(moduleRequire.resolve("pkijs")).href;
        const asn1jsUrl = pathToFileURL(moduleRequire.resolve("asn1js")).href;

        const probeCode = `import { readFileSync } from "node:fs";
const distUrl = process.argv[2];
const pkijsUrl = process.argv[3];
const asn1jsUrl = process.argv[4];
const leafPath = process.argv[5];
const caPath = process.argv[6];
const { ValidationSession } = await import(distUrl);
const pkijs = await import(pkijsUrl);
const asn1js = await import(asn1jsUrl);
function parseCert(path) {
    const fileBytes = readFileSync(path);
    const copy = new Uint8Array(fileBytes);
    const asn1 = asn1js.fromBER(copy.buffer);
    if (asn1.offset === -1) throw new Error("parse fail");
    return new pkijs.Certificate({ schema: asn1.result });
}
const leaf = parseCert(leafPath);
const ca = parseCert(caPath);
const largeCrl = new Uint8Array(8 * 1024 * 1024);
largeCrl.fill(0x41);
const fetcher = {
    fetchOCSP: () => Promise.reject(new Error("no OCSP")),
    fetchCRL: () => Promise.resolve(largeCrl),
};
const session = new ValidationSession({ fetcher });
session.queueCertificate(leaf, { issuer: ca });
await session.validateAll();
const exported = session.exportLTVData();
if (exported.crls.length !== 1) throw new Error("expected 1 CRL");
if (exported.crls[0].length !== largeCrl.length) throw new Error("length mismatch");
`;

        const tempDir = mkdtempSync(join(tmpdir(), "pdf-rfc3161-export-heap-"));
        try {
            const leafPath = join(tempDir, "leaf.der");
            const caPath = join(tempDir, "ca.der");
            const probePath = join(tempDir, "probe.mjs");
            writeFileSync(leafPath, leafDer);
            writeFileSync(caPath, caDer);
            writeFileSync(probePath, probeCode);
            const result = spawnSync(
                process.execPath,
                [
                    "--max-old-space-size=128",
                    probePath,
                    distUrl,
                    pkijsUrl,
                    asn1jsUrl,
                    leafPath,
                    caPath,
                ],
                { encoding: "utf8", timeout: 60000 }
            );
            const output = [result.stdout, result.stderr]
                .filter((v) => typeof v === "string" && v.length > 0)
                .join("\n");
            expect(result.status, `export probe failed: ${output}`).toBe(0);
        } finally {
            rmSync(tempDir, { force: true, recursive: true });
        }
    }, 60000);
});
