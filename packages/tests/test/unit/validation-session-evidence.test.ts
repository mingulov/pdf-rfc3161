/* eslint-disable @typescript-eslint/no-deprecated -- compatibility coverage */
import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { ValidationSession } from "../../../core/src/pki/validation-session.js";
import * as validationSessionModule from "../../../core/src/pki/validation-session.js";
import { DefaultFetcher } from "../../../core/src/pki/fetchers/default-fetcher.js";
import { MockFetcher } from "../../../core/src/pki/fetchers/mock-fetcher.js";
import { InMemoryValidationCache } from "../../../core/src/pki/fetchers/memory-cache.js";
import { resetOCSPCircuits } from "../../../core/src/pki/ocsp-client.js";
import { resetCRLCircuits } from "../../../core/src/pki/crl-client.js";
import type { OperationBudgetLimits } from "../../../core/src/utils/operation-budget.js";
import type {
    RevocationDataFetcher,
    RevocationFetchContext,
    ValidationSessionOptions,
} from "../../../core/src/pki/validation-types.js";
import { createOcspResponseCandidate, createCrlFixture } from "../fixtures/revocation-material.js";
import { generateRSAKeyPair, importKeyForCertificate } from "../utils/crypto.js";

// T04: unauthenticated revocation verdicts are contained. Every case below
// must yield revocationStatus "unknown" with isValid false until the
// authenticated OCSP/CRL evaluators exist (T06/T07). Evidence bytes are
// real serialized fixtures; no verdict parser is mocked in this file.

const OCSP_URL = "http://ocsp.example.com/";
const CRL_URL = "http://crl.example.com/ca.crl";
const LEAF_SERIAL = 4242;

// Real setTimeout, captured before any fake timers: yields genuine
// event-loop turns while the fake clock stays frozen.
const realSetTimeout: typeof setTimeout = globalThis.setTimeout;

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

describe("ValidationSession operation budget (T08)", () => {
    let issuer: pkijs.Certificate;
    let issuerKeys: { publicKey: CryptoKey; privateKey: CryptoKey };

    function signedByIssuer(): { issuer: pkijs.Certificate; privateKey: CryptoKey } {
        return { issuer, privateKey: issuerKeys.privateKey };
    }

    beforeAll(async () => {
        issuerKeys = await generateRSAKeyPair();
        issuer = await createIssuerCertificate(issuerKeys.publicKey);
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    function makeBudget(limits: OperationBudgetLimits): OperationBudgetLimits {
        return { ...limits };
    }

    function withBudget(
        options: ValidationSessionOptions,
        limits: OperationBudgetLimits
    ): ValidationSessionOptions {
        return { ...options, budget: makeBudget(limits) } as ValidationSessionOptions;
    }

    async function runToSettled<T>(pending: Promise<T>, isDispatched: () => boolean): Promise<T> {
        const state = { settled: false };
        const watched = pending.then(
            (value: T) => {
                state.settled = true;
                return value;
            },
            (error: unknown) => {
                state.settled = true;
                throw error;
            }
        );
        // Real loop turns until dispatch: crypto setup completes while the
        // fake clock stays frozen, so short elapsed budgets cannot fire.
        for (let step = 0; step < 500 && !state.settled && !isDispatched(); step++) {
            await new Promise((resolve) => realSetTimeout(resolve, 0));
        }
        expect(isDispatched()).toBe(true);
        for (let step = 0; step < 300 && !state.settled; step++) {
            await vi.advanceTimersByTimeAsync(1000);
        }
        expect(state.settled).toBe(true);
        return watched;
    }

    it("cancels cooperative custom fetchers once the elapsed budget expires", async () => {
        const leaf = await createLeafCertificate({ ocspUrl: OCSP_URL, signedBy: signedByIssuer() });
        let captured: AbortSignal | undefined;
        const fetcher: RevocationDataFetcher = {
            fetchOCSP: async (
                _url: string,
                _request: Uint8Array,
                context?: RevocationFetchContext
            ): Promise<Uint8Array> => {
                captured = context?.signal;
                if (context?.signal === undefined) {
                    return createOcspResponseCandidate("good");
                }
                return new Promise<Uint8Array>((_resolve, reject) => {
                    context.signal?.addEventListener("abort", () => {
                        reject(new Error("custom OCSP cancelled"));
                    });
                });
            },
            fetchCRL: () => Promise.reject(new Error("no CRL response")),
        };
        const session = new ValidationSession(withBudget({ fetcher }, { maxElapsedMs: 4000 }));
        session.queueCertificate(leaf, { issuer });
        vi.useFakeTimers();

        const [result] = await runToSettled(session.validateAll(), () => captured !== undefined);

        expect(result?.revocationStatus).toBe("unknown");
        expect(captured?.aborted).toBe(true);
        expect((result?.errors ?? []).join("\n")).toMatch(/custom OCSP cancelled/);
    });

    it("discards late custom-fetcher returns instead of using them", async () => {
        const leaf = await createLeafCertificate({ ocspUrl: OCSP_URL, signedBy: signedByIssuer() });
        const cache = new InMemoryValidationCache();
        let requestBytes: Uint8Array | undefined;
        let fetchCalled = false;
        const fetcher: RevocationDataFetcher = {
            fetchOCSP: async (_url: string, request: Uint8Array): Promise<Uint8Array> => {
                requestBytes = request;
                fetchCalled = true;
                // Legacy behavior: ignores the abort context entirely, and
                // resolves long after the elapsed budget expires.
                await new Promise((resolve) => setTimeout(resolve, 50000));
                return createOcspResponseCandidate("good");
            },
            fetchCRL: () => Promise.reject(new Error("no CRL response")),
        };
        const session = new ValidationSession(
            withBudget({ fetcher, cache }, { maxElapsedMs: 4000 })
        );
        session.queueCertificate(leaf, { issuer });
        vi.useFakeTimers();

        const [result] = await runToSettled(session.validateAll(), () => fetchCalled);

        expect(result?.sources).toEqual([]);
        expect(requestBytes ? cache.getOCSP(OCSP_URL, requestBytes) : null).toBeNull();
        expect((result?.errors ?? []).join("\n")).toMatch(/operation budget exhausted/);
    });

    it("rejects over-cap custom-fetcher bytes", async () => {
        const leaf = await createLeafCertificate({ ocspUrl: OCSP_URL, signedBy: signedByIssuer() });
        const fetcher: RevocationDataFetcher = {
            fetchOCSP: async (): Promise<Uint8Array> => new Uint8Array(60 * 1024).fill(0xcd),
            fetchCRL: () => Promise.reject(new Error("no CRL response")),
        };
        const session = new ValidationSession(withBudget({ fetcher }, {}));
        session.queueCertificate(leaf, { issuer });

        const [result] = await session.validateAll();

        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.sources).toEqual([]);
        expect((result?.errors ?? []).join("\n")).toMatch(/exceed/);
    });

    it("refuses cache-refetch once the attempt budget is spent", async () => {
        const cache = new InMemoryValidationCache();
        const leaf = await createLeafCertificate({ ocspUrl: OCSP_URL, signedBy: signedByIssuer() });
        const poison = new Uint8Array([0xff, 0xff]);
        // First session (unbudgeted) plants the poisoned cache entry. The
        // nonce is off so both sessions build byte-identical requests.
        const planter = new ValidationSession({
            fetcher: {
                fetchOCSP: async (): Promise<Uint8Array> => poison,
                fetchCRL: () => Promise.reject(new Error("no CRL response")),
            },
            cache,
            includeOCSPNonce: false,
        });
        planter.queueCertificate(leaf, { issuer });
        await planter.validateAll();

        let calls = 0;
        const session = new ValidationSession(
            withBudget(
                {
                    fetcher: {
                        fetchOCSP: async (): Promise<Uint8Array> => {
                            calls++;
                            return poison;
                        },
                        fetchCRL: () => Promise.reject(new Error("no CRL response")),
                    },
                    cache,
                    includeOCSPNonce: false,
                },
                { maxAttempts: 0 }
            )
        );
        session.queueCertificate(leaf, { issuer });

        const [result] = await session.validateAll();

        expect(calls).toBe(0);
        expect(result?.revocationStatus).toBe("unknown");
        expect((result?.errors ?? []).join("\n")).toMatch(/operation budget exhausted/);
    });

    it("hands custom fetchers a signal-only context with no budget handle (R19)", async () => {
        const leaf = await createLeafCertificate({ ocspUrl: OCSP_URL, signedBy: signedByIssuer() });
        let captured: RevocationFetchContext | undefined;
        const fetcher: RevocationDataFetcher = {
            fetchOCSP: async (
                _url: string,
                _request: Uint8Array,
                context?: RevocationFetchContext
            ): Promise<Uint8Array> => {
                captured = context;
                return createOcspResponseCandidate("good");
            },
            fetchCRL: () => Promise.reject(new Error("no CRL response")),
        };
        const session = new ValidationSession(withBudget({ fetcher }, {}));
        session.queueCertificate(leaf, { issuer });

        await session.validateAll();

        expect(captured?.signal).toBeInstanceOf(AbortSignal);
        // R19: the public fetcher context is signal-only. The live
        // budget must never be observable from caller fetchers, not
        // even as an own property on the handed object.
        expect(captured === undefined ? [] : Object.keys(captured)).toEqual(["signal"]);
        expect(captured !== undefined && "budget" in captured).toBe(false);
    });

    it("hands DefaultFetcher subclasses a signal-only context too (R19/M1)", async () => {
        const leaf = await createLeafCertificate({ ocspUrl: OCSP_URL, signedBy: signedByIssuer() });
        let captured: RevocationFetchContext | undefined;
        class CaptureFetcher extends DefaultFetcher {
            async fetchOCSP(
                _url: string,
                _request: Uint8Array,
                context?: RevocationFetchContext
            ): Promise<Uint8Array> {
                captured = context;
                return createOcspResponseCandidate("good");
            }
        }
        const session = new ValidationSession(withBudget({ fetcher: new CaptureFetcher() }, {}));
        session.queueCertificate(leaf, { issuer });

        await session.validateAll();

        // A subclass override is caller code: it must observe the same
        // signal-only context as any other custom fetcher.
        expect(captured?.signal).toBeInstanceOf(AbortSignal);
        expect(captured === undefined ? [] : Object.keys(captured)).toEqual(["signal"]);
        expect(captured !== undefined && "budget" in captured).toBe(false);
    });

    it("yields unknown with diagnostics for certificates past the cap", async () => {
        const leaves = await Promise.all(
            [5001, 5002, 5003].map((serial) =>
                createLeafCertificate({ serial, ocspUrl: OCSP_URL, signedBy: signedByIssuer() })
            )
        );
        let calls = 0;
        const fetcher: RevocationDataFetcher = {
            fetchOCSP: async (): Promise<Uint8Array> => {
                calls++;
                return new Uint8Array([0xff, 0xff]);
            },
            fetchCRL: () => Promise.reject(new Error("no CRL response")),
        };
        const session = new ValidationSession(withBudget({ fetcher }, { maxCertificates: 1 }));
        for (const leaf of leaves) {
            session.queueCertificate(leaf, { issuer });
        }

        const results = await session.validateAll();

        // One result per queued certificate, even past the cap.
        expect(results).toHaveLength(3);
        expect(calls).toBe(1);
        expect(results[1]?.revocationStatus).toBe("unknown");
        expect((results[1]?.errors ?? []).join("\n")).toMatch(/operation budget exhausted/);
    });

    describe("built-in fetcher budget accounting (fix round 3)", () => {
        const mockFetch = vi.fn();
        let originalFetch: typeof globalThis.fetch;

        beforeEach(() => {
            originalFetch = globalThis.fetch;
            globalThis.fetch = mockFetch;
            vi.clearAllMocks();
            mockFetch.mockReset();
            resetOCSPCircuits();
            resetCRLCircuits();
        });

        afterEach(() => {
            globalThis.fetch = originalFetch;
        });

        function failTwiceThenSucceed(body: Uint8Array): void {
            let calls = 0;
            mockFetch.mockImplementation(async () => {
                calls++;
                if (calls <= 2) return new Response("error-body", { status: 500 });
                return new Response(body as BodyInit, { status: 200 });
            });
        }

        function subclassFetcher(counter: { calls: number }): RevocationDataFetcher {
            class SubclassFetcher extends DefaultFetcher {
                async fetchOCSP(): Promise<Uint8Array> {
                    counter.calls++;
                    return createOcspResponseCandidate("good");
                }
            }
            return new SubclassFetcher();
        }

        it("counts every physical OCSP attempt of the built-in fetcher, retries included", async () => {
            const leaf = await createLeafCertificate({
                ocspUrl: OCSP_URL,
                signedBy: signedByIssuer(),
            });
            failTwiceThenSucceed(createOcspResponseCandidate("good"));
            const session = new ValidationSession(
                withBudget({ fetcher: new DefaultFetcher() }, { maxAttempts: 1 })
            );
            session.queueCertificate(leaf, { issuer });

            const [result] = await session.validateAll();

            // One physical attempt spends the budget; the retries are
            // refused, never issued. (Red run: one counted attempt covers
            // all three physical fetches, so the call succeeds.)
            expect(mockFetch).toHaveBeenCalledTimes(1);
            expect(result?.revocationStatus).toBe("unknown");
            expect((result?.errors ?? []).join("\n")).toMatch(/operation budget exhausted/);
        });

        it("admits built-in OCSP retries that fit the attempt budget", async () => {
            const leaf = await createLeafCertificate({
                ocspUrl: OCSP_URL,
                signedBy: signedByIssuer(),
            });
            failTwiceThenSucceed(createOcspResponseCandidate("good"));
            const session = new ValidationSession(
                withBudget({ fetcher: new DefaultFetcher() }, { maxAttempts: 3 })
            );
            session.queueCertificate(leaf, { issuer });
            vi.useFakeTimers();

            const [result] = await runToSettled(
                session.validateAll(),
                () => mockFetch.mock.calls.length > 0
            );

            // Control: exactly three physical attempts are claimed, so a
            // budget of three admits the fail-twice-then-succeed exchange.
            // (Green before and after; proves the responder setup works.)
            expect(mockFetch).toHaveBeenCalledTimes(3);
            expect(result?.sources).toEqual(["OCSP"]);
            expect(result?.revocationStatus).toBe("unknown");
        });

        it("counts built-in failed-attempt bytes even when the body is rejected", async () => {
            const leaf = await createLeafCertificate({
                ocspUrl: OCSP_URL,
                crlUrl: CRL_URL,
                signedBy: signedByIssuer(),
            });
            mockFetch.mockImplementation(async (url: string) => {
                if (url === OCSP_URL) {
                    return new Response(new Uint8Array(60 * 1024).fill(0xcd) as BodyInit, {
                        status: 200,
                    });
                }
                return new Response(new Uint8Array([0x30, 0x00]) as BodyInit, { status: 200 });
            });
            const session = new ValidationSession(
                withBudget({ fetcher: new DefaultFetcher() }, { maxBytes: 150 })
            );
            session.queueCertificate(leaf, { issuer });

            const [result] = await session.validateAll();

            const crlCalls = mockFetch.mock.calls.filter((call) => (call[0] as string) === CRL_URL);
            // The 60 KiB rejected OCSP body tips the byte budget, so the CRL
            // fallback is refused without issuing a fetch. (Red run: the
            // rejected body counts nothing, so the CRL fetch goes out.)
            expect(crlCalls).toHaveLength(0);
            expect((result?.errors ?? []).join("\n")).toMatch(/operation budget exhausted/);
        });

        it("counts physical attempts for explicit-timeout built-in fetchers", async () => {
            const leaf = await createLeafCertificate({
                ocspUrl: OCSP_URL,
                signedBy: signedByIssuer(),
            });
            failTwiceThenSucceed(createOcspResponseCandidate("good"));
            const session = new ValidationSession(
                withBudget({ fetcher: new DefaultFetcher({ timeout: 5000 }) }, { maxAttempts: 1 })
            );
            session.queueCertificate(leaf, { issuer });

            const [result] = await session.validateAll();

            // Same per-physical-attempt accounting through the
            // explicit-policy direct-shell branch. (Red run: succeeds; the
            // in-shell retries are free.)
            expect(mockFetch).toHaveBeenCalledTimes(1);
            expect((result?.errors ?? []).join("\n")).toMatch(/operation budget exhausted/);
        });

        it("admits explicit-timeout built-in retries that fit the attempt budget", async () => {
            const leaf = await createLeafCertificate({
                ocspUrl: OCSP_URL,
                signedBy: signedByIssuer(),
            });
            failTwiceThenSucceed(createOcspResponseCandidate("good"));
            const session = new ValidationSession(
                withBudget({ fetcher: new DefaultFetcher({ timeout: 5000 }) }, { maxAttempts: 3 })
            );
            session.queueCertificate(leaf, { issuer });
            vi.useFakeTimers();

            const [result] = await runToSettled(
                session.validateAll(),
                () => mockFetch.mock.calls.length > 0
            );

            // Control for the explicit branch: three physical attempts fit
            // a budget of three. (Green before and after.)
            expect(mockFetch).toHaveBeenCalledTimes(3);
            expect(result?.sources).toEqual(["OCSP"]);
            expect(result?.revocationStatus).toBe("unknown");
        });

        it("routes DefaultFetcher subclasses through the custom path: override invoked, one attempt", async () => {
            const leaves = await Promise.all(
                [5001, 5002].map((serial) =>
                    createLeafCertificate({ serial, ocspUrl: OCSP_URL, signedBy: signedByIssuer() })
                )
            );
            const counter = { calls: 0 };
            const session = new ValidationSession(
                withBudget({ fetcher: subclassFetcher(counter) }, { maxAttempts: 1 })
            );
            for (const leaf of leaves) {
                session.queueCertificate(leaf, { issuer });
            }

            const results = await session.validateAll();

            // The override is caller I/O: invoked (not bypassed by an
            // internal built-in method) and counted as one custom attempt,
            // so the second certificate is refused without a fetch.
            expect(counter.calls).toBe(1);
            expect(results[0]?.sources).toEqual(["OCSP"]);
            expect((results[1]?.errors ?? []).join("\n")).toMatch(/operation budget exhausted/);
        });

        it("counts DefaultFetcher-subclass return bytes as custom-fetch bytes", async () => {
            const leaves = await Promise.all(
                [5001, 5002].map((serial) =>
                    createLeafCertificate({ serial, ocspUrl: OCSP_URL, signedBy: signedByIssuer() })
                )
            );
            const counter = { calls: 0 };
            const session = new ValidationSession(
                withBudget({ fetcher: subclassFetcher(counter) }, { maxBytes: 10 })
            );
            for (const leaf of leaves) {
                session.queueCertificate(leaf, { issuer });
            }

            const results = await session.validateAll();

            // The canned OCSP return (far over 10 bytes) tips the byte
            // budget, so the second certificate is refused without a fetch.
            expect(counter.calls).toBe(1);
            expect(results[0]?.sources).toEqual(["OCSP"]);
            expect((results[1]?.errors ?? []).join("\n")).toMatch(/operation budget exhausted/);
        });

        it("routes non-overriding DefaultFetcher subclasses through the budgeted path (fix round 4, F3)", async () => {
            // F3 mechanism pin: a cross-format genuine instance (CJS
            // fetcher + ESM session) shares no constructor identity, so
            // dispatch is capability + same-realm override self-check, not
            // exact-constructor. A subclass overriding nothing is genuine
            // built-in I/O with per-physical-attempt accounting.
            class PlainSubclass extends DefaultFetcher {}
            const leaf = await createLeafCertificate({
                ocspUrl: OCSP_URL,
                signedBy: signedByIssuer(),
            });
            failTwiceThenSucceed(createOcspResponseCandidate("good"));
            const session = new ValidationSession(
                withBudget({ fetcher: new PlainSubclass() }, { maxAttempts: 1 })
            );
            session.queueCertificate(leaf, { issuer });

            const [result] = await session.validateAll();

            // Every physical attempt is claimed, so the retries are
            // refused, never issued. (Red run: 3 fetches via the custom
            // path with free in-shell retries.)
            expect(mockFetch).toHaveBeenCalledTimes(1);
            expect(result?.revocationStatus).toBe("unknown");
            expect((result?.errors ?? []).join("\n")).toMatch(/operation budget exhausted/);
        });

        it("aborts in-flight built-in session I/O once the elapsed budget expires", async () => {
            const leaf = await createLeafCertificate({
                ocspUrl: OCSP_URL,
                signedBy: signedByIssuer(),
            });
            mockFetch.mockImplementation(
                (_url: string, init?: { signal?: AbortSignal }) =>
                    new Promise<never>((_resolve, reject) => {
                        const signal = init?.signal;
                        if (signal?.aborted === true) {
                            reject(new Error("Aborted"));
                            return;
                        }
                        signal?.addEventListener("abort", () => {
                            const error = new Error("Aborted");
                            error.name = "AbortError";
                            reject(error);
                        });
                    })
            );
            const session = new ValidationSession(
                withBudget({ fetcher: new DefaultFetcher() }, { maxElapsedMs: 4000 })
            );
            session.queueCertificate(leaf, { issuer });
            vi.useFakeTimers();

            const [result] = await runToSettled(
                session.validateAll(),
                () => mockFetch.mock.calls.length > 0
            );

            // The budget signal stays wired into built-in I/O as real
            // cancellation. (Green before and after; guards the signal half
            // of the internal budgeted path.)
            expect(mockFetch).toHaveBeenCalledTimes(1);
            const firstInit = mockFetch.mock.calls[0]?.[1] as { signal?: AbortSignal } | undefined;
            expect(firstInit?.signal?.aborted).toBe(true);
            expect((result?.errors ?? []).join("\n")).toMatch(/operation budget exhausted/);
        });
    });
});

describe("ValidationSession CRL diagnostic URL redaction (T12 I1)", () => {
    const CREDENTIALED_CRL_URL = "https://user:pass@crl.example.test/x?token=MARKER";
    const REDACTED_CRL_URL = "https://crl.example.test/x";

    let issuer: pkijs.Certificate;
    let issuerKeys: { publicKey: CryptoKey; privateKey: CryptoKey };

    function signedByIssuer(): { issuer: pkijs.Certificate; privateKey: CryptoKey } {
        return { issuer, privateKey: issuerKeys.privateKey };
    }

    beforeAll(async () => {
        issuerKeys = await generateRSAKeyPair();
        issuer = await createIssuerCertificate(issuerKeys.publicKey);
    });

    it("redacts credential-bearing CRL URLs in fetch-failure diagnostics", async () => {
        const leaf = await createLeafCertificate({ crlUrl: CREDENTIALED_CRL_URL });
        const session = new ValidationSession({ fetcher: throwingFetcher() });
        session.queueCertificate(leaf);

        const [result] = await session.validateAll();
        const joined = (result?.errors ?? []).join("\n");
        expect(joined).toMatch(/failed/i);
        expect(joined).toContain(REDACTED_CRL_URL);
        expect(joined).not.toContain("user:pass@");
        expect(joined).not.toContain("MARKER");
    });

    it("redacts credential-bearing CRL URLs in validation-failure diagnostics", async () => {
        const leaf = await createLeafCertificate({
            crlUrl: CREDENTIALED_CRL_URL,
            signedBy: signedByIssuer(),
        });
        const fetcher = new MockFetcher();
        fetcher.setCRLResponse(CREDENTIALED_CRL_URL, new Uint8Array([0xff, 0xff, 0xff]));
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(leaf, { issuer });

        const [result] = await session.validateAll();
        const joined = (result?.errors ?? []).join("\n");
        expect(joined).toContain(REDACTED_CRL_URL);
        expect(joined).not.toContain("user:pass@");
        expect(joined).not.toContain("MARKER");
    });

    it("redacts credential-bearing CRL URLs in unknown-evidence diagnostics", async () => {
        const leaf = await createLeafCertificate({
            crlUrl: CREDENTIALED_CRL_URL,
            signedBy: signedByIssuer(),
        });
        const fetcher = new MockFetcher();
        fetcher.setCRLResponse(
            CREDENTIALED_CRL_URL,
            createCrlFixture({ crlNumber: 7, deltaBaseNumber: 6 })
        );
        const session = new ValidationSession({ fetcher });
        session.queueCertificate(leaf, { issuer });

        const [result] = await session.validateAll();
        const joined = (result?.errors ?? []).join("\n");
        expect(joined).toMatch(/delta CRL/);
        expect(joined).toContain(REDACTED_CRL_URL);
        expect(joined).not.toContain("user:pass@");
        expect(joined).not.toContain("MARKER");
    });
});
