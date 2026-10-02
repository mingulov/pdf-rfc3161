/* eslint-disable @typescript-eslint/no-deprecated -- compatibility coverage */
import { describe, it, expect, beforeAll } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { ValidationSession } from "../../../core/src/pki/validation-session.js";
import * as validationSessionModule from "../../../core/src/pki/validation-session.js";
import { MockFetcher } from "../../../core/src/pki/fetchers/mock-fetcher.js";
import type { RevocationDataFetcher } from "../../../core/src/pki/validation-types.js";
import { createOcspResponseCandidate, createCrlFixture } from "../fixtures/revocation-material.js";
import { generateRSAKeyPair, importKeyForCertificate } from "../utils/crypto.js";

// T04: unauthenticated revocation verdicts are contained. Every case below
// must yield revocationStatus "unknown" with isValid false until the
// authenticated OCSP/CRL evaluators exist (T06/T07). Evidence bytes are
// real serialized fixtures; no verdict parser is mocked in this file.

const OCSP_URL = "http://ocsp.example.com/";
const CRL_URL = "http://crl.example.com/ca.crl";
const LEAF_SERIAL = 4242;

function roundTripCertificate(cert: pkijs.Certificate): pkijs.Certificate {
    const der = new Uint8Array(cert.toSchema(true).toBER(false));
    const asn1 = asn1js.fromBER(der.slice().buffer);
    if (asn1.offset === -1) throw new Error("test certificate is not DER");
    return new pkijs.Certificate({ schema: asn1.result });
}

async function createLeafCertificate(options: {
    serial?: number;
    ocspUrl?: string;
    crlUrl?: string;
    issuer?: pkijs.Certificate;
    issuerName?: string;
    signedBy?: { issuer: pkijs.Certificate; privateKey: CryptoKey };
}): Promise<pkijs.Certificate> {
    const cert = new pkijs.Certificate();
    cert.version = 2;
    cert.serialNumber = new asn1js.Integer({ value: options.serial ?? LEAF_SERIAL });
    cert.subject.typesAndValues.push(
        new pkijs.AttributeTypeAndValue({
            type: "2.5.4.3",
            value: new asn1js.PrintableString({ value: "Evidence leaf" }),
        })
    );
    if (options.issuer) {
        cert.issuer = options.issuer.subject;
    } else if (options.issuerName) {
        cert.issuer.typesAndValues.push(
            new pkijs.AttributeTypeAndValue({
                type: "2.5.4.3",
                value: new asn1js.PrintableString({ value: options.issuerName }),
            })
        );
    } else {
        cert.issuer = cert.subject;
    }
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
    if (options.crlUrl) {
        const cdp = new pkijs.CRLDistributionPoints({
            distributionPoints: [
                new pkijs.DistributionPoint({
                    distributionPoint: [new pkijs.GeneralName({ type: 6, value: options.crlUrl })],
                }),
            ],
        });
        extensions.push(
            new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: cdp.toSchema().toBER(false),
            })
        );
    }
    if (extensions.length > 0) {
        cert.extensions = extensions;
    }
    if (options.signedBy) {
        // T05: the session verifies that the issuer actually issued the
        // target, so evidence leaves paired with an explicit issuer are
        // really signed by it.
        cert.issuer = options.signedBy.issuer.subject;
        await cert.sign(options.signedBy.privateKey, "SHA-256");
    }
    // Round-trip so AIA/CDP extensions go through real DER parsing.
    return roundTripCertificate(cert);
}

async function createIssuerCertificate(publicKey: CryptoKey): Promise<pkijs.Certificate> {
    const issuer = new pkijs.Certificate();
    issuer.version = 2;
    issuer.serialNumber = new asn1js.Integer({ value: 9001 });
    issuer.subject.typesAndValues.push(
        new pkijs.AttributeTypeAndValue({
            type: "2.5.4.3",
            value: new asn1js.PrintableString({ value: "Evidence Test CA" }),
        })
    );
    issuer.issuer = issuer.subject;
    issuer.subjectPublicKeyInfo = await importKeyForCertificate(publicKey);
    return issuer;
}

function throwingFetcher(): RevocationDataFetcher {
    return {
        fetchOCSP: () => Promise.reject(new Error("ocsp unreachable")),
        fetchCRL: () => Promise.reject(new Error("crl unreachable")),
    };
}

function recordingFetcher(responses: {
    ocsp?: Uint8Array;
    crl?: Uint8Array;
}): RevocationDataFetcher & { calls: string[] } {
    const calls: string[] = [];
    return {
        calls,
        fetchOCSP: (url: string) => {
            calls.push(`OCSP:${url}`);
            if (!responses.ocsp) return Promise.reject(new Error("no OCSP response"));
            return Promise.resolve(responses.ocsp);
        },
        fetchCRL: (url: string) => {
            calls.push(`CRL:${url}`);
            if (!responses.crl) return Promise.reject(new Error("no CRL response"));
            return Promise.resolve(responses.crl);
        },
    };
}

describe("ValidationSession revocation evidence containment (T04)", () => {
    let issuer: pkijs.Certificate;
    let issuerKeys: { publicKey: CryptoKey; privateKey: CryptoKey };

    function signedByIssuer(): { issuer: pkijs.Certificate; privateKey: CryptoKey } {
        return { issuer, privateKey: issuerKeys.privateKey };
    }

    beforeAll(async () => {
        issuerKeys = await generateRSAKeyPair();
        issuer = await createIssuerCertificate(issuerKeys.publicKey);
    });

    it("yields unknown when the certificate carries no revocation endpoints", async () => {
        const leaf = await createLeafCertificate({ signedBy: signedByIssuer() });
        const fetcher = recordingFetcher({});
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(leaf, { issuer });

        const [result] = await session.validateAll();
        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.isValid).toBe(false);
        expect(result?.sources).toEqual([]);
        expect(fetcher.calls).toEqual([]);
    });

    it("yields unknown when the issuer is missing", async () => {
        // Issuer name matches no queued certificate: no OCSP request can be built.
        const leaf = await createLeafCertificate({ ocspUrl: OCSP_URL, issuerName: "Absent CA" });
        const session = new ValidationSession({ fetcher: new MockFetcher() });
        session.queueCertificate(leaf);

        const [result] = await session.validateAll();
        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.isValid).toBe(false);
        expect(result?.errors.join("\n")).toContain("issuer");
    });

    it("yields unknown on total outage", async () => {
        const leaf = await createLeafCertificate({
            ocspUrl: OCSP_URL,
            crlUrl: CRL_URL,
            signedBy: signedByIssuer(),
        });
        const session = new ValidationSession({ fetcher: throwingFetcher() });
        session.queueCertificate(leaf, { issuer });

        const [result] = await session.validateAll();
        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.isValid).toBe(false);
        expect(result?.sources).toEqual([]);
        expect(result?.errors.length).toBeGreaterThan(0);
    });

    it("yields unknown for a malformed OCSP response", async () => {
        const leaf = await createLeafCertificate({ ocspUrl: OCSP_URL, signedBy: signedByIssuer() });
        const fetcher = new MockFetcher();
        fetcher.setOCSPResponse(OCSP_URL, new Uint8Array([0xff, 0xff, 0xff]));
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(leaf, { issuer });

        const [result] = await session.validateAll();
        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.isValid).toBe(false);
    });

    it("yields unknown for a malformed CRL", async () => {
        const leaf = await createLeafCertificate({ crlUrl: CRL_URL, signedBy: signedByIssuer() });
        const fetcher = new MockFetcher();
        fetcher.setCRLResponse(CRL_URL, new Uint8Array([0xff, 0xff, 0xff]));
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(leaf, { issuer });

        const [result] = await session.validateAll();
        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.isValid).toBe(false);
    });

    it("yields unknown for a forged GOOD OCSP response", async () => {
        const leaf = await createLeafCertificate({ ocspUrl: OCSP_URL, signedBy: signedByIssuer() });
        const forged = createOcspResponseCandidate("good");
        const fetcher = new MockFetcher();
        fetcher.setOCSPResponse(OCSP_URL, forged);
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(leaf, { issuer });

        const [result] = await session.validateAll();
        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.isValid).toBe(false);
        // Raw collection is preserved even though no verdict is produced.
        expect(result?.sources).toEqual(["OCSP"]);
        expect(result?.ocspResponses).toHaveLength(1);
    });

    it("yields unknown, never revoked, for a forged REVOKED OCSP response", async () => {
        const leaf = await createLeafCertificate({ ocspUrl: OCSP_URL, signedBy: signedByIssuer() });
        const forged = createOcspResponseCandidate("revoked");
        const fetcher = new MockFetcher();
        fetcher.setOCSPResponse(OCSP_URL, forged);
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(leaf, { issuer });

        const [result] = await session.validateAll();
        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.isValid).toBe(false);
    });

    it("yields unknown, never revoked, for a forged CRL listing the serial", async () => {
        const leaf = await createLeafCertificate({ crlUrl: CRL_URL, signedBy: signedByIssuer() });
        const forged = createCrlFixture({ crlNumber: 7, revokedSerials: [LEAF_SERIAL] });
        const fetcher = new MockFetcher();
        fetcher.setCRLResponse(CRL_URL, forged);
        // The fixture CRL is dated January 2024; check inside its window
        // so the verdict exercises issuer binding, not staleness.
        const session = new ValidationSession({
            fetcher,
            checkDate: new Date("2024-01-15T00:00:00Z"),
        });
        session.queueCertificate(leaf, { issuer });

        const [result] = await session.validateAll();
        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.isValid).toBe(false);
        expect(result?.sources).toEqual(["CRL"]);
        // T07: the structural entry is visible, but the forged CRL is not
        // issued by the verified issuer, so it yields no verdict.
        expect(result?.errors.join("\n")).toContain("CRL issuer does not match");
    });

    it("does not treat a delta CRL as a complete revocation source", async () => {
        const leaf = await createLeafCertificate({ crlUrl: CRL_URL, signedBy: signedByIssuer() });
        const delta = createCrlFixture({ crlNumber: 7, deltaBaseNumber: 6 });
        const fetcher = new MockFetcher();
        fetcher.setCRLResponse(CRL_URL, delta);
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(leaf, { issuer });

        const [result] = await session.validateAll();
        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.isValid).toBe(false);
        expect(result?.errors.join("\n")).toContain("delta CRL");
    });

    it("orders attempts by preferOCSP: OCSP first by default, CRL first when false", async () => {
        const ocsp = createOcspResponseCandidate("good");
        const crl = createCrlFixture({ crlNumber: 3 });

        const leafDefault = await createLeafCertificate({
            ocspUrl: OCSP_URL,
            crlUrl: CRL_URL,
            issuer,
            signedBy: signedByIssuer(),
        });
        const fetcherDefault = recordingFetcher({ ocsp, crl });
        const sessionDefault = new ValidationSession({ fetcher: fetcherDefault });
        sessionDefault.queueCertificate(leafDefault, { issuer });
        const [resultDefault] = await sessionDefault.validateAll();
        expect(resultDefault?.revocationStatus).toBe("unknown");
        expect(fetcherDefault.calls).toEqual([`OCSP:${OCSP_URL}`, `CRL:${CRL_URL}`]);

        const leafCrlFirst = await createLeafCertificate({
            ocspUrl: OCSP_URL,
            crlUrl: CRL_URL,
            issuer,
            signedBy: signedByIssuer(),
        });
        const fetcherCrlFirst = recordingFetcher({ ocsp, crl });
        const sessionCrlFirst = new ValidationSession({
            fetcher: fetcherCrlFirst,
            preferOCSP: false,
        });
        sessionCrlFirst.queueCertificate(leafCrlFirst, { issuer });
        const [resultCrlFirst] = await sessionCrlFirst.validateAll();
        expect(resultCrlFirst?.revocationStatus).toBe("unknown");
        expect(fetcherCrlFirst.calls).toEqual([`CRL:${CRL_URL}`, `OCSP:${OCSP_URL}`]);
    });

    it("keeps isValid as an alias of revocationStatus === good", async () => {
        const leaf = await createLeafCertificate({ ocspUrl: OCSP_URL, signedBy: signedByIssuer() });
        const fetcher = new MockFetcher();
        fetcher.setOCSPResponse(OCSP_URL, createOcspResponseCandidate("good"));
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(leaf, { issuer });

        const [result] = await session.validateAll();
        expect(result?.isValid).toBe(result?.revocationStatus === "good");
    });

    it("still collects raw evidence bytes for exportLTVData", async () => {
        const leaf = await createLeafCertificate({
            ocspUrl: OCSP_URL,
            crlUrl: CRL_URL,
            signedBy: signedByIssuer(),
        });
        const ocsp = createOcspResponseCandidate("good");
        const crl = createCrlFixture({ crlNumber: 3 });
        const fetcher = new MockFetcher();
        fetcher.setOCSPResponse(OCSP_URL, ocsp);
        fetcher.setCRLResponse(CRL_URL, crl);
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(leaf, { issuer });
        await session.validateAll();

        const ltv = session.exportLTVData();
        expect(ltv.ocspResponses).toHaveLength(1);
        expect(ltv.ocspResponses[0]).toEqual(ocsp);
        expect(ltv.crls).toHaveLength(1);
        expect(ltv.crls[0]).toEqual(crl);
    });
});

describe("crlContainsSerial structural scan (T04)", () => {
    it("finds a serial listed in revokedCertificates", async () => {
        expect(typeof validationSessionModule.crlContainsSerial).toBe("function");
        const leaf = await createLeafCertificate({ serial: LEAF_SERIAL });
        const crl = createCrlFixture({ crlNumber: 7, revokedSerials: [LEAF_SERIAL] });
        expect(validationSessionModule.crlContainsSerial(crl, leaf)).toBe(true);
    });

    it("tolerates DER leading-zero padding on high-bit serials", async () => {
        expect(typeof validationSessionModule.crlContainsSerial).toBe("function");
        // Serial 128 has the high bit set, so its minimal DER encoding is
        // 02 02 00 80 and the parsed CRL entry carries the 00 pad. The
        // leaf side uses the same minimal form so the comparison matches
        // on exact numeric identity.
        const leaf = await createLeafCertificate({ serial: 128 });
        leaf.serialNumber = new asn1js.Integer({
            valueHex: Uint8Array.of(0x00, 0x80).buffer,
        });
        const crl = createCrlFixture({ crlNumber: 7, revokedSerials: [128] });
        expect(validationSessionModule.crlContainsSerial(crl, leaf)).toBe(true);
        // No confusion with serial 0 after stripping the pad byte.
        const zeroLeaf = await createLeafCertificate({ serial: 0 });
        expect(validationSessionModule.crlContainsSerial(crl, zeroLeaf)).toBe(false);
    });

    it("never conflates serial -128 with serial 128 (T07 exact identity)", async () => {
        expect(typeof validationSessionModule.crlContainsSerial).toBe("function");
        // The bare byte 0x80 is the minimal encoding of -128, not an
        // unpadded 128: exact identity must not match it against the
        // CRL entry for 128.
        const negativeLeaf = await createLeafCertificate({ serial: 128 });
        negativeLeaf.serialNumber = new asn1js.Integer({
            valueHex: Uint8Array.of(0x80).buffer,
        });
        const crl = createCrlFixture({ crlNumber: 7, revokedSerials: [128] });
        expect(validationSessionModule.crlContainsSerial(crl, negativeLeaf)).toBe(false);
        // Empty and non-minimal serials never match either.
        const emptyLeaf = await createLeafCertificate({ serial: 4242 });
        emptyLeaf.serialNumber = new asn1js.Integer({ valueHex: new Uint8Array(0).buffer });
        const listed = createCrlFixture({ crlNumber: 7, revokedSerials: [4242] });
        expect(validationSessionModule.crlContainsSerial(listed, emptyLeaf)).toBe(false);
    });

    it("returns false when the serial is absent", async () => {
        expect(typeof validationSessionModule.crlContainsSerial).toBe("function");
        const leaf = await createLeafCertificate({ serial: LEAF_SERIAL });
        const crl = createCrlFixture({ crlNumber: 7, revokedSerials: [9999] });
        expect(validationSessionModule.crlContainsSerial(crl, leaf)).toBe(false);
    });

    it("returns false for malformed input", async () => {
        expect(typeof validationSessionModule.crlContainsSerial).toBe("function");
        const leaf = await createLeafCertificate({ serial: LEAF_SERIAL });
        expect(validationSessionModule.crlContainsSerial(new Uint8Array([0xff, 0xff]), leaf)).toBe(
            false
        );
    });
});
