import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fetchCRL, parseCRLInfo } from '../../../core/src/pki/crl-client.js';
import { TimestampError } from '../../../core/src/types.js';

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

describe('CRL Client', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe('parseCRLInfo', () => {
        it('should return false for non-delta CRL', () => {
            const randomBytes = new Uint8Array([0x30, 0x00]);
            const info = parseCRLInfo(randomBytes);
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
            const mockCrl = new Uint8Array([0x30, 0x00]); // Valid-ish ASN.1 sequence
            fetchMock.mockResolvedValueOnce({
                ok: true,
                arrayBuffer: () => Promise.resolve(mockCrl.buffer),
            });
            await fetchCRL('http://example.com/crl', { fetchDeltaIfAvailable: true });
            expect(warnSpy).not.toHaveBeenCalled();
        });

        it('should throw TimestampError on 404', async () => {
            fetchMock.mockResolvedValueOnce({
                ok: false,
                status: 404,
                statusText: 'Not Found',
            });

            await expect(fetchCRL('http://example.com/404')).rejects.toThrow(TimestampError);
        });
    });
});
