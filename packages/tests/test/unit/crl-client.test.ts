import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { fetchCRL, parseCRLInfo, getCRLCircuitState, resetCRLCircuits } from '../../../core/src/pki/crl-client.js';
import { TimestampError } from '../../../core/src/types.js';
import { CircuitState } from '../../../core/src/utils/circuit-breaker.js';

// Global fetch mock
const fetchMock = vi.fn();
global.fetch = fetchMock;

// Mock Logger
const warnSpy = vi.fn();
vi.mock('../../../core/src/utils/logger.js', async (importOriginal) => {
    const mod = await importOriginal<typeof import('../../../core/src/utils/logger.js')>();
    return {
        ...mod,
        getLogger: () => ({
            debug: vi.fn(),
            info: vi.fn(),
            warn: warnSpy,
            error: vi.fn(),
        }),
    };
});

async function expectRejected<T>(promise: Promise<T>): Promise<unknown> {
    const captured = promise.catch((e: unknown) => e);
    await vi.runAllTimersAsync();
    return captured;
}

describe('CRL Client', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        resetCRLCircuits();
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    describe('parseCRLInfo', () => {
        it('should return false for non-delta CRL', () => {
            const randomBytes = new Uint8Array([0x30, 0x00]);
            const info = parseCRLInfo(randomBytes);
            expect(info.isDelta).toBe(false);
        });

        it('should return default info when CRL parsing throws', () => {
            const malformedBytes = new Uint8Array([0x02, 0x01, 0x01]);
            const info = parseCRLInfo(malformedBytes);
            expect(info.crl).toEqual(malformedBytes);
            expect(info.isDelta).toBe(false);
        });

        it('should return default info when ASN.1 parsing fails completely', () => {
            const invalidAsn1 = new Uint8Array([0xFF, 0xFF, 0xFF]);
            const info = parseCRLInfo(invalidAsn1);
            expect(info.crl).toEqual(invalidAsn1);
            expect(info.isDelta).toBe(false);
        });
    });

    describe('fetchCRL', () => {
        it('should return bytes on success', async () => {
            const mockCrl = new Uint8Array([1, 2, 3]);
            fetchMock.mockResolvedValueOnce({
                ok: true,
                arrayBuffer: () => Promise.resolve(mockCrl.buffer),
            });

            const result = await fetchCRL('http://example.com/crl');
            expect(result).toEqual(mockCrl);
        });

        it('should NOT warn if no delta found (default)', async () => {
            const mockCrl = new Uint8Array([0x30, 0x00]);
            fetchMock.mockResolvedValueOnce({
                ok: true,
                arrayBuffer: () => Promise.resolve(mockCrl.buffer),
            });
            await fetchCRL('http://example.com/crl', { fetchDeltaIfAvailable: true });
            expect(warnSpy).not.toHaveBeenCalled();
        });

        it('should throw TimestampError on 404', async () => {
            fetchMock.mockResolvedValue({
                ok: false,
                status: 404,
                statusText: 'Not Found',
            });

            const error = await expectRejected(fetchCRL('http://example.com/404'));
            expect(error).toBeInstanceOf(TimestampError);
        });
    });

    describe('Circuit Breaker Functions', () => {
        const testUrl = 'http://example.com/crl';

        it('should return undefined for unknown URLs', () => {
            const state = getCRLCircuitState('http://unknown.com');
            expect(state).toBeUndefined();
        });

        it('should return CLOSED state after a successful fetch', async () => {
            fetchMock.mockResolvedValueOnce({
                ok: true,
                arrayBuffer: () => Promise.resolve(new Uint8Array([1, 2, 3]).buffer),
            });

            await fetchCRL(testUrl);

            const state = getCRLCircuitState(testUrl);
            expect(state).toBe(CircuitState.CLOSED);
        });

        it('should reset circuit breakers', async () => {
            // Induce a failure to create a breaker entry
            fetchMock.mockResolvedValue({
                ok: false,
                status: 500,
                statusText: 'Server Error',
            });

            await expectRejected(fetchCRL(testUrl));

            expect(getCRLCircuitState(testUrl)).toBeDefined();

            resetCRLCircuits();

            expect(getCRLCircuitState(testUrl)).toBeUndefined();
        });
    });
});
