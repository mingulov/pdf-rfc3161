// test/unit/ltv-resource-budget.test.ts - T08 aggregate operation-budget regressions.
//
// One OperationBudget per completion bounds every collection path: built-in
// fetch/retry calls, custom fetchers, repeated AIA URLs, and cache-refetch
// paths all consume attempts / bytes / certificates / elapsed from it.
// Exhaustion aborts built-in I/O, issues no further fetches, and degrades
// honestly (partial LTV + diagnostics; strict validation yields unknown).
import { createHash } from "node:crypto";
import { beforeEach, afterEach, describe, expect, it, vi, type Mock } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { completeLTVData, type LTVData, type LTVSettings } from "../../../core/src/pdf/ltv.js";
import type { OperationBudgetLimits } from "../../../core/src/utils/operation-budget.js";
import type { RevocationFetchContext } from "../../../core/src/pki/validation-types.js";
import { getOCSPURI } from "../../../core/src/pki/ocsp-utils.js";
import { getCRLDistributionPoints } from "../../../core/src/pki/crl-utils.js";
import { getCaIssuers } from "../../../core/src/pki/cert-utils.js";
import { resetOCSPCircuits } from "../../../core/src/pki/ocsp-client.js";
import { resetCRLCircuits } from "../../../core/src/pki/crl-client.js";
import { resetCertCircuits } from "../../../core/src/pki/cert-client.js";
import {
    createTestCA,
    createTestLeaf,
    type TestCertificateAuthority,
} from "../fixtures/signed-revocation-material.js";
import { createCrlFixture, createOcspResponseCandidate } from "../fixtures/revocation-material.js";
import { createRFC3161TokenFixture } from "../fixtures/rfc3161-token.js";

vi.mock(
    "../../../core/src/pki/ocsp-utils.js",
    async (importOriginal: <T = unknown>() => Promise<T>) => ({
        ...(await importOriginal<typeof import("../../../core/src/pki/ocsp-utils.js")>()),
        getOCSPURI: vi.fn(),
    })
);

vi.mock(
    "../../../core/src/pki/crl-utils.js",
    async (importOriginal: <T = unknown>() => Promise<T>) => ({
        ...(await importOriginal<typeof import("../../../core/src/pki/crl-utils.js")>()),
        getCRLDistributionPoints: vi.fn(),
    })
);

vi.mock(
    "../../../core/src/pki/cert-utils.js",
    async (importOriginal: <T = unknown>() => Promise<T>) => ({
        ...(await importOriginal<typeof import("../../../core/src/pki/cert-utils.js")>()),
        getCaIssuers: vi.fn(),
    })
);

const mockGetOCSPURI = getOCSPURI as unknown as Mock<
    (cert: pkijs.Certificate) => string | undefined
>;
const mockGetCRLDistributionPoints = getCRLDistributionPoints as unknown as Mock<
    (cert: pkijs.Certificate) => string[]
>;
const mockGetCaIssuers = getCaIssuers as unknown as Mock<(cert: pkijs.Certificate) => string[]>;

const OCSP_URL = "http://ocsp.t08-budget.example.com/";
const CRL_URL = "http://crl.t08-budget.example.com/ca.crl";
const AIA_URL = "http://aia.t08-budget.example.com/ca.cer";

function makeBudget(limits: OperationBudgetLimits): OperationBudgetLimits {
    return { ...limits };
}

function settingsWithBudget(settings: LTVSettings, limits: OperationBudgetLimits): LTVSettings {
    return { ...settings, budget: makeBudget(limits) } as LTVSettings;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    return bytes.slice().buffer;
}

function sha256Hex(bytes: Uint8Array): string {
    return createHash("sha256").update(bytes).digest("hex");
}

/** Signer/issuer DER pair with the signer issued by the decoy (existing pattern). */
async function certificatePair(): Promise<Uint8Array[]> {
    const fixture = await createRFC3161TokenFixture({ certificates: "decoyFirst" });
    const signerAsn1 = asn1js.fromBER(toArrayBuffer(fixture.signerCertificate));
    const issuerAsn1 = asn1js.fromBER(toArrayBuffer(fixture.decoyCertificate));
    if (
        signerAsn1.offset !== fixture.signerCertificate.length ||
        issuerAsn1.offset !== fixture.decoyCertificate.length
    ) {
        throw new Error("fixture certificates must be complete DER");
    }
    const signer = new pkijs.Certificate({ schema: signerAsn1.result });
    const issuer = new pkijs.Certificate({ schema: issuerAsn1.result });
    signer.issuer = issuer.subject;
    return [
        new Uint8Array(signer.toSchema(true).toBER(false)),
        new Uint8Array(issuer.toSchema().toBER(false)),
    ];
}

function derOf(cert: pkijs.Certificate): Uint8Array {
    return new Uint8Array(cert.toSchema().toBER(false));
}

/** Real-signed leaf -> mid -> root chain; every name link resolves. */
async function certificateChain(): Promise<{
    ca: TestCertificateAuthority;
    leafDer: Uint8Array;
    midDer: Uint8Array;
    rootDer: Uint8Array;
}> {
    const ca = await createTestCA("T08 Root", { serial: 8001 });
    const mid = await createTestLeaf(ca, { commonName: "T08 Mid", serial: 8002 });
    const leaf = await createTestLeaf(mid, { commonName: "T08 Leaf", serial: 8003 });
    return { ca, leafDer: derOf(leaf.cert), midDer: derOf(mid.cert), rootDer: derOf(ca.cert) };
}

function garbageBytes(length: number): Uint8Array {
    return new Uint8Array(length).fill(0xab);
}

const mockFetch = vi.fn();

function hangUntilAbort(): void {
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
}

/**
 * Real setTimeout, captured before any fake timers: yields genuine
 * event-loop turns while the fake clock stays frozen.
 */
const realSetTimeout: typeof setTimeout = globalThis.setTimeout;

/**
 * Waits for the first fetch dispatch on real loop turns (crypto setup
 * completes while the fake clock stays frozen, so elapsed budgets cannot
 * fire before dispatch), then pumps fake time until the completion
 * settles. Fake-timer tests use this; a bare runAllTimersAsync would
 * return early with an empty queue and freeze the clock.
 */
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

describe("LTV operation budget (T08)", () => {
    let originalFetch: typeof globalThis.fetch;

    beforeEach(() => {
        originalFetch = globalThis.fetch;
        globalThis.fetch = mockFetch;
        vi.clearAllMocks();
        mockFetch.mockReset();
        resetOCSPCircuits();
        resetCRLCircuits();
        resetCertCircuits();
        mockGetOCSPURI.mockReturnValue(undefined);
        mockGetCRLDistributionPoints.mockReturnValue([]);
        mockGetCaIssuers.mockReturnValue([]);
    });

    afterEach(() => {
        vi.useRealTimers();
        globalThis.fetch = originalFetch;
    });

    describe("AIA URL bounds (R13)", () => {
        it("fetches a repeated AIA URL only once per certificate", async () => {
            const [signer] = await certificatePair();
            if (signer === undefined) throw new Error("pair fixture must hold a signer");
            mockGetCaIssuers.mockReturnValue([AIA_URL, AIA_URL]);
            const certFetcher = vi.fn(async (_url: string) => garbageBytes(10));

            await completeLTVData(
                { certificates: [signer], crls: [], ocspResponses: [] },
                settingsWithBudget({ fetchers: { certFetcher } }, {})
            );

            expect(certFetcher).toHaveBeenCalledTimes(1);
        });

        it("stops after 8 unique AIA URLs per certificate", async () => {
            const [signer] = await certificatePair();
            if (signer === undefined) throw new Error("pair fixture must hold a signer");
            const urls = Array.from(
                { length: 10 },
                (_unused, index) => `http://aia.t08-budget.example.com/${index.toString()}.cer`
            );
            mockGetCaIssuers.mockReturnValue(urls);
            const certFetcher = vi.fn(async (_url: string) => garbageBytes(10));

            const result = await completeLTVData(
                { certificates: [signer], crls: [], ocspResponses: [] },
                settingsWithBudget({ fetchers: { certFetcher } }, {})
            );

            expect(certFetcher).toHaveBeenCalledTimes(8);
            expect(result.errors.join("\n")).toMatch(/operation budget exhausted/);
            expect(result.errors.join("\n")).toMatch(/URL/);
        });
    });

    describe("certificate bounds", () => {
        it("admits only maxCertificates certificates for revocation collection", async () => {
            const chain = await certificateChain();
            mockGetOCSPURI.mockReturnValue(OCSP_URL);
            const ocspFetcher = vi.fn(async (_url: string, _request: Uint8Array) =>
                createOcspResponseCandidate("good")
            );

            const result = await completeLTVData(
                {
                    certificates: [chain.leafDer, chain.midDer, chain.rootDer],
                    crls: [],
                    ocspResponses: [],
                },
                settingsWithBudget({ fetchers: { ocspFetcher } }, { maxCertificates: 2 })
            );

            // Leaf and mid admitted, root refused; only the leaf keeps a
            // resolvable issuer, so exactly one OCSP fetch is issued.
            expect(ocspFetcher).toHaveBeenCalledTimes(1);
            expect(result.data.ocspResponses).toHaveLength(1);
            expect(result.errors.join("\n")).toMatch(/operation budget exhausted/);
            expect(result.errors.join("\n")).toMatch(/certificate/);
        });
    });

    describe("byte accounting", () => {
        it("counts bytes from invalid returned issuers against the budget", async () => {
            // Leaf keeps a resolvable issuer (mid) for OCSP; mid misses its
            // issuer (root) so AIA triggers for it. The returned candidate
            // is well-formed but issued under another root, so the name
            // check inside verifyIssuance fails deterministically.
            const chain = await certificateChain();
            const wrongCA = await createTestCA("T08 Wrong Root", { serial: 8011 });
            const wrongMid = await createTestLeaf(wrongCA, {
                commonName: "T08 Wrong Mid",
                serial: 8012,
            });
            const wrongIssuer = derOf(wrongMid.cert);
            mockGetOCSPURI.mockReturnValue(OCSP_URL);
            mockGetCaIssuers.mockReturnValue([AIA_URL]);
            const certFetcher = vi.fn(async (_url: string) => wrongIssuer);
            const ocspFetcher = vi.fn(async (_url: string, _request: Uint8Array) =>
                createOcspResponseCandidate("good")
            );

            const result = await completeLTVData(
                { certificates: [chain.leafDer, chain.midDer], crls: [], ocspResponses: [] },
                settingsWithBudget(
                    { fetchers: { certFetcher, ocspFetcher } },
                    { maxBytes: wrongIssuer.length - 1 }
                )
            );

            // The rejected issuer bytes tipped the budget over, so the OCSP
            // fetch that follows must never be issued.
            expect(ocspFetcher).not.toHaveBeenCalled();
            expect(result.errors.join("\n")).toMatch(/did not issue/);
            expect(result.errors.join("\n")).toMatch(/operation budget exhausted/);
        });

        it("counts failed bodies and stops issuing fetches once bytes tip over", async () => {
            const chain = await certificateChain();
            mockGetOCSPURI.mockReturnValue(OCSP_URL);
            mockGetCRLDistributionPoints.mockReturnValue([CRL_URL]);
            const ocspFetcher = vi.fn(async (_url: string, _request: Uint8Array) =>
                garbageBytes(100)
            );
            const crlFetcher = vi.fn(async (_url: string) => garbageBytes(100));

            const result = await completeLTVData(
                {
                    certificates: [chain.leafDer, chain.midDer, chain.rootDer],
                    crls: [],
                    ocspResponses: [],
                },
                settingsWithBudget({ fetchers: { ocspFetcher, crlFetcher } }, { maxBytes: 150 })
            );

            // Leaf OCSP (100) + leaf CRL fallback (100, tipping over at 200)
            // are consumed; the mid OCSP fetch must never be issued.
            expect(ocspFetcher).toHaveBeenCalledTimes(1);
            expect(crlFetcher).toHaveBeenCalledTimes(1);
            expect(result.errors.join("\n")).toMatch(/operation budget exhausted/);
        });
    });

    describe("attempt accounting over built-in transport", () => {
        it("counts unsuccessful attempts including retries and stops at the cap", async () => {
            const pair = await certificatePair();
            const signer = pair[0];
            const issuer = pair[1];
            if (signer === undefined || issuer === undefined) {
                throw new Error("pair fixture must hold two certificates");
            }
            vi.useFakeTimers();
            mockGetOCSPURI.mockReturnValue(OCSP_URL);
            mockGetCRLDistributionPoints.mockReturnValue([CRL_URL]);
            mockFetch.mockImplementation(async () => new Response("error-body", { status: 500 }));

            // Elapsed is parked far away: this test counts attempts only,
            // and crypto setup must never race a fake deadline.
            const result = await runToSettled(
                completeLTVData(
                    { certificates: [signer, issuer], crls: [], ocspResponses: [] },
                    settingsWithBudget({}, { maxAttempts: 4, maxElapsedMs: 600000 })
                ),
                () => mockFetch.mock.calls.length > 0
            );

            // One exhausted OCSP call (1 + 3 retries) spends the whole
            // budget; the CRL fallback must never be issued.
            expect(mockFetch).toHaveBeenCalledTimes(4);
            expect(result.errors.join("\n")).toMatch(/operation budget exhausted/);
        });

        it("aborts in-flight built-in I/O once the elapsed budget expires", async () => {
            const pair = await certificatePair();
            const signer = pair[0];
            const issuer = pair[1];
            if (signer === undefined || issuer === undefined) {
                throw new Error("pair fixture must hold two certificates");
            }
            vi.useFakeTimers();
            mockGetOCSPURI.mockReturnValue(OCSP_URL);
            mockGetCRLDistributionPoints.mockReturnValue([CRL_URL]);
            hangUntilAbort();

            // Below the 5 s built-in attempt timeout (so the budget wins
            // the race mid-flight) but far above crypto setup (50 ms
            // dispatch polling cannot overshoot it).
            const result = await runToSettled(
                completeLTVData(
                    { certificates: [signer, issuer], crls: [], ocspResponses: [] },
                    settingsWithBudget({}, { maxElapsedMs: 4000 })
                ),
                () => mockFetch.mock.calls.length > 0
            );

            expect(mockFetch).toHaveBeenCalledTimes(1);
            const firstInit = mockFetch.mock.calls[0]?.[1] as { signal?: AbortSignal } | undefined;
            expect(firstInit?.signal?.aborted).toBe(true);
            expect(result.errors.join("\n")).toMatch(/operation budget exhausted/);
        });
    });

    describe("post-exhaustion diagnostic silence (fix round 1)", () => {
        it("stops the AIA URL loop once the budget is spent", async () => {
            // P2-3: like the CRL loop, the AIA loop must break on
            // exhaustion instead of pushing one diagnostic per URL.
            const [signer] = await certificatePair();
            if (signer === undefined) throw new Error("pair fixture must hold a signer");
            const urls = Array.from(
                { length: 5 },
                (_unused, index) => `http://aia.t08-budget.example.com/${index.toString()}.cer`
            );
            mockGetCaIssuers.mockReturnValue(urls);
            // Garbage parses as nothing (silent continue), spending the
            // single attempt; every later URL is refused identically.
            const certFetcher = vi.fn(async (_url: string) => garbageBytes(10));

            const result = await completeLTVData(
                { certificates: [signer], crls: [], ocspResponses: [] },
                settingsWithBudget({ fetchers: { certFetcher } }, { maxAttempts: 1 })
            );

            expect(certFetcher).toHaveBeenCalledTimes(1);
            expect(result.errors).toHaveLength(1);
            expect(result.errors.join("\n")).toMatch(/operation budget exhausted/);
        });

        it("stops the per-certificate OCSP loop once the budget is spent", async () => {
            const chain = await certificateChain();
            mockGetOCSPURI.mockReturnValue(OCSP_URL);
            mockGetCRLDistributionPoints.mockReturnValue([CRL_URL]);
            const ocspFetcher = vi.fn(async (_url: string, _request: Uint8Array) =>
                garbageBytes(100)
            );
            const crlFetcher = vi.fn(async (_url: string) => garbageBytes(100));

            const result = await completeLTVData(
                {
                    certificates: [chain.leafDer, chain.midDer, chain.rootDer],
                    crls: [],
                    ocspResponses: [],
                },
                settingsWithBudget({ fetchers: { ocspFetcher, crlFetcher } }, { maxAttempts: 0 })
            );

            // The causative certificate keeps its OCSP + CRL fallback
            // refusal diagnostics; the remaining certificates are skipped
            // silently instead of spamming identical refusals.
            expect(ocspFetcher).not.toHaveBeenCalled();
            expect(crlFetcher).not.toHaveBeenCalled();
            expect(result.errors).toHaveLength(2);
            expect(result.errors.join("\n")).toMatch(/operation budget exhausted/);
        });
    });

    describe("custom-fetcher contract (S17)", () => {
        it("passes an abort context to custom fetchers without breaking legacy ones", async () => {
            const pair = await certificatePair();
            const signer = pair[0];
            const issuer = pair[1];
            if (signer === undefined || issuer === undefined) {
                throw new Error("pair fixture must hold two certificates");
            }
            mockGetOCSPURI.mockReturnValue(OCSP_URL);
            let receivedArgs = 0;
            let receivedSignal: unknown;
            const ocspFetcher = async (
                ...args: [string, Uint8Array, unknown?]
            ): Promise<Uint8Array> => {
                receivedArgs = args.length;
                receivedSignal = (args[2] as RevocationFetchContext | undefined)?.signal;
                return createOcspResponseCandidate("good");
            };

            const result = await completeLTVData(
                { certificates: [signer, issuer], crls: [], ocspResponses: [] },
                settingsWithBudget({ fetchers: { ocspFetcher } }, {})
            );

            expect(receivedArgs).toBe(3);
            expect(receivedSignal).toBeInstanceOf(AbortSignal);
            // The legacy two-parameter shape keeps working: ignoring the
            // context still collects the candidate.
            expect(result.data.ocspResponses).toHaveLength(1);
        });

        it("hands custom fetchers a signal-only context with no budget handle (R19)", async () => {
            const pair = await certificatePair();
            const signer = pair[0];
            const issuer = pair[1];
            if (signer === undefined || issuer === undefined) {
                throw new Error("pair fixture must hold two certificates");
            }
            mockGetOCSPURI.mockReturnValue(OCSP_URL);
            let captured: RevocationFetchContext | undefined;
            const ocspFetcher = async (
                ...args: [string, Uint8Array, unknown?]
            ): Promise<Uint8Array> => {
                captured = args[2] as RevocationFetchContext | undefined;
                return createOcspResponseCandidate("good");
            };

            await completeLTVData(
                { certificates: [signer, issuer], crls: [], ocspResponses: [] },
                settingsWithBudget({ fetchers: { ocspFetcher } }, {})
            );

            expect(captured?.signal).toBeInstanceOf(AbortSignal);
            // R19: the public fetcher context is signal-only. The live
            // budget must never be observable from caller fetchers, not
            // even as an own property on the handed object.
            expect(captured === undefined ? [] : Object.keys(captured)).toEqual(["signal"]);
            expect(captured !== undefined && "budget" in captured).toBe(false);
        });
    });

    describe("exhaustion honesty (C03/C06)", () => {
        it("retains existing artifacts and returns partial LTV plus diagnostics", async () => {
            const pair = await certificatePair();
            const signer = pair[0];
            const issuer = pair[1];
            if (signer === undefined || issuer === undefined) {
                throw new Error("pair fixture must hold two certificates");
            }
            mockGetOCSPURI.mockReturnValue(OCSP_URL);
            mockGetCRLDistributionPoints.mockReturnValue([CRL_URL]);
            mockGetCaIssuers.mockReturnValue([AIA_URL]);
            const existingCrl = createCrlFixture({ crlNumber: 1 });
            const existingOcsp = createOcspResponseCandidate("good");
            const addedCrl = createCrlFixture({ crlNumber: 2 });
            const ocspFetcher = vi.fn(async (_url: string, _request: Uint8Array) =>
                garbageBytes(100)
            );
            const crlFetcher = vi.fn(async (_url: string) => addedCrl);
            const certFetcher = vi.fn(async (_url: string) => garbageBytes(10));

            const input: LTVData = {
                certificates: [signer, issuer],
                crls: [existingCrl],
                ocspResponses: [existingOcsp],
            };
            const result = await completeLTVData(
                input,
                settingsWithBudget(
                    { fetchers: { ocspFetcher, crlFetcher, certFetcher } },
                    { maxAttempts: 0 }
                )
            );

            // Nothing may be issued and nothing pre-existing may be lost.
            expect(ocspFetcher).not.toHaveBeenCalled();
            expect(crlFetcher).not.toHaveBeenCalled();
            expect(certFetcher).not.toHaveBeenCalled();
            expect(result.data.crls).toHaveLength(1);
            expect(result.data.crls[0]).toEqual(existingCrl);
            expect(result.data.ocspResponses).toHaveLength(1);
            expect(result.data.ocspResponses[0]).toEqual(existingOcsp);
            expect(result.data.certificates).toHaveLength(2);
            expect(result.errors.join("\n")).toMatch(/operation budget exhausted/);
        });

        it("pins the byte-identical success path (behavior-preservation control)", async () => {
            const pair = await certificatePair();
            const signer = pair[0];
            const issuer = pair[1];
            if (signer === undefined || issuer === undefined) {
                throw new Error("pair fixture must hold two certificates");
            }
            mockGetOCSPURI.mockReturnValue(OCSP_URL);
            const candidate = createOcspResponseCandidate("good");
            const ocspFetcher = vi.fn(async (_url: string, _request: Uint8Array) => candidate);

            const result = await completeLTVData(
                { certificates: [signer, issuer], crls: [], ocspResponses: [] },
                { fetchers: { ocspFetcher } }
            );

            expect(result.errors).toEqual([]);
            expect(result.data.certificates).toHaveLength(2);
            expect(result.data.ocspResponses).toHaveLength(1);
            const collected = result.data.ocspResponses[0];
            if (collected === undefined) throw new Error("expected one OCSP candidate");
            // Pinned on BASE: the default budget must not perturb ordinary
            // success paths.
            expect(sha256Hex(collected)).toBe(
                "8fa3dbefafc806517827dc00ccb37112292b0d663ad0a71269979db8c6d9f767"
            );
        });
    });
});
