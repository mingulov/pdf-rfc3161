import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
    fetchCRL,
    parseCRLInfo,
    getCRLCircuitState,
    resetCRLCircuits,
} from "../../../core/src/pki/crl-client.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";
import { CircuitState } from "../../../core/src/utils/circuit-breaker.js";
import { createCrlFixture } from "../fixtures/revocation-material.js";

// Global fetch mock
const fetchMock = vi.fn();
global.fetch = fetchMock;

// Mock Logger
const warnSpy = vi.fn();
vi.mock(
    "../../../core/src/utils/logger.js",
    async (importOriginal: <T = unknown>() => Promise<T>) => {
        const mod = await importOriginal<typeof import("../../../core/src/utils/logger.js")>();
        return {
            ...mod,
            getLogger: () => ({
                debug: vi.fn(),
                info: vi.fn(),
                warn: warnSpy,
                error: vi.fn(),
            }),
        };
    }
);

async function expectRejected<T>(promise: Promise<T>): Promise<unknown> {
    const captured = promise.catch((e: unknown) => e);
    await vi.runAllTimersAsync();
    return captured;
}

function okResponse(bytes: Uint8Array): Response {
    return new Response(bytes as BodyInit, { status: 200 });
}

describe("CRL Client", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        resetCRLCircuits();
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    describe("parseCRLInfo", () => {
        it("should return false for non-delta CRL", () => {
            const randomBytes = new Uint8Array([0x30, 0x00]);
            const info = parseCRLInfo(randomBytes);
            expect(info.isDelta).toBe(false);
        });

        it("should return default info when CRL parsing throws", () => {
            const malformedBytes = new Uint8Array([0x02, 0x01, 0x01]);
            const info = parseCRLInfo(malformedBytes);
            expect(info.crl).toEqual(malformedBytes);
            expect(info.isDelta).toBe(false);
        });

        it("should return default info when ASN.1 parsing fails completely", () => {
            const invalidAsn1 = new Uint8Array([0xff, 0xff, 0xff]);
            const info = parseCRLInfo(invalidAsn1);
            expect(info.crl).toEqual(invalidAsn1);
            expect(info.isDelta).toBe(false);
        });
    });

    describe("parseCRLInfo with serialized CRLs (T04)", () => {
        it("should parse a complete CRL with number and revoked entries", () => {
            const crl = createCrlFixture({ crlNumber: 7, revokedSerials: [4242] });
            const info = parseCRLInfo(crl);
            expect(info.crl).toEqual(crl);
            expect(info.parsed).toBe(true);
            expect(info.isDelta).toBe(false);
            expect(info.crlNumber).toBe(7);
            expect(info.deltaCrlNumber).toBeUndefined();
        });

        it("should detect a delta CRL via the DeltaCRLIndicator extension", () => {
            const crl = createCrlFixture({ crlNumber: 7, deltaBaseNumber: 6 });
            const info = parseCRLInfo(crl);
            expect(info.parsed).toBe(true);
            expect(info.isDelta).toBe(true);
            expect(info.crlNumber).toBe(7);
            expect(info.deltaCrlNumber).toBe(6);
        });

        it("should separate malformed input from a parsed complete non-delta CRL", () => {
            const malformed = parseCRLInfo(new Uint8Array([0xff, 0xff, 0xff]));
            expect(malformed.parsed).toBe(false);
            expect(malformed.isDelta).toBe(false);

            const complete = parseCRLInfo(createCrlFixture({ crlNumber: 1 }));
            expect(complete.parsed).toBe(true);
            expect(complete.isDelta).toBe(false);
        });

        it("should parse a CRL without extensions as non-delta with no numbers", () => {
            const info = parseCRLInfo(createCrlFixture());
            expect(info.parsed).toBe(true);
            expect(info.isDelta).toBe(false);
            expect(info.crlNumber).toBeUndefined();
            expect(info.deltaCrlNumber).toBeUndefined();
        });
    });

    describe("fetchCRL", () => {
        it("should return bytes on success", async () => {
            const mockCrl = new Uint8Array([1, 2, 3]);
            fetchMock.mockResolvedValueOnce(okResponse(mockCrl));

            const result = await fetchCRL("http://example.com/crl");
            expect(result).toEqual(mockCrl);
        });

        it("should NOT warn if no delta found (default)", async () => {
            const mockCrl = new Uint8Array([0x30, 0x00]);
            fetchMock.mockResolvedValueOnce(okResponse(mockCrl));
            await fetchCRL("http://example.com/crl", { fetchDeltaIfAvailable: true });
            expect(warnSpy).not.toHaveBeenCalled();
        });

        it("should fail fast with TimestampError on 404 without retrying", async () => {
            fetchMock.mockResolvedValue(
                new Response("missing", { status: 404, statusText: "Not Found" })
            );

            const error = await expectRejected(fetchCRL("http://example.com/404"));
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect(fetchMock).toHaveBeenCalledTimes(1);
        });
    });

    describe("Circuit Breaker Functions", () => {
        const testUrl = "http://example.com/crl";

        it("should return undefined for unknown URLs", () => {
            const state = getCRLCircuitState("http://unknown.com");
            expect(state).toBeUndefined();
        });

        it("should return CLOSED state after a successful fetch", async () => {
            fetchMock.mockResolvedValueOnce(okResponse(new Uint8Array([1, 2, 3])));

            await fetchCRL(testUrl);

            const state = getCRLCircuitState(testUrl);
            expect(state).toBe(CircuitState.CLOSED);
        });

        it("should reset circuit breakers", async () => {
            // Induce a failure to create a breaker entry
            fetchMock.mockResolvedValue(
                new Response("oops", { status: 500, statusText: "Server Error" })
            );

            await expectRejected(fetchCRL(testUrl));

            expect(getCRLCircuitState(testUrl)).toBeDefined();

            resetCRLCircuits();

            expect(getCRLCircuitState(testUrl)).toBeUndefined();
        });
    });
});
