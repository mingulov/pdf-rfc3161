import { bytesToHex } from "../../utils.js";
import type { ValidationCache } from "../validation-types.js";

/**
 * Default cap on retained cache entries.
 */
export const DEFAULT_VALIDATION_CACHE_MAX_ENTRIES = 256;

/**
 * Default cap on retained response bytes (20 MiB).
 */
export const DEFAULT_VALIDATION_CACHE_MAX_TOTAL_BYTES = 20 * 1024 * 1024;

/**
 * Default entry retention in milliseconds. Retention is not freshness
 * approval: expired entries simply miss and are refetched.
 */
export const DEFAULT_VALIDATION_CACHE_RETENTION_MS = 300000;

/**
 * Constructor limits for {@link InMemoryValidationCache}. Every field is
 * optional; omitted fields take the `DEFAULT_VALIDATION_CACHE_*` values.
 */
export interface InMemoryValidationCacheOptions {
    /** Maximum retained entries; the oldest entry is evicted first. */
    maxEntries?: number;
    /** Maximum retained response bytes; oldest entries are evicted first. */
    maxTotalBytes?: number;
    /** Entry retention in milliseconds; expired entries miss. */
    retentionMs?: number;
}

interface CacheEntry {
    response: Uint8Array;
    storedAt: number;
}

/**
 * Simple in-memory cache for revocation data.
 * Suitable for single-session caching. For multi-session caching,
 * consider implementing a persistent cache (Redis, file-based, etc.).
 *
 * Identity is exact: OCSP entries are keyed by the full request bytes
 * scoped by the exact URL, so equal-content requests hit while
 * shared-prefix/different-suffix requests miss. Bytes are copied on
 * insertion and retrieval so callers can never mutate cached entries,
 * and entries honor retention/entry/byte limits with oldest-first
 * eviction. Oversized single entries are not cached.
 */
export class InMemoryValidationCache implements ValidationCache {
    private readonly entries = new Map<string, CacheEntry>();
    private totalBytes = 0;
    private readonly maxEntries: number;
    private readonly maxTotalBytes: number;
    private readonly retentionMs: number;

    constructor(options: InMemoryValidationCacheOptions = {}) {
        this.maxEntries = options.maxEntries ?? DEFAULT_VALIDATION_CACHE_MAX_ENTRIES;
        this.maxTotalBytes = options.maxTotalBytes ?? DEFAULT_VALIDATION_CACHE_MAX_TOTAL_BYTES;
        this.retentionMs = options.retentionMs ?? DEFAULT_VALIDATION_CACHE_RETENTION_MS;
    }

    getOCSP(url: string, request: Uint8Array): Uint8Array | null {
        const key = `ocsp:${url.length.toString()}:${url}:${bytesToHex(request)}`;
        return this.lookup(key);
    }

    setOCSP(url: string, request: Uint8Array, response: Uint8Array): void {
        const key = `ocsp:${url.length.toString()}:${url}:${bytesToHex(request)}`;
        this.store(key, response);
    }

    getCRL(url: string): Uint8Array | null {
        return this.lookup(`crl:${url.length.toString()}:${url}`);
    }

    setCRL(url: string, response: Uint8Array): void {
        this.store(`crl:${url.length.toString()}:${url}`, response);
    }

    clear(): void {
        this.entries.clear();
        this.totalBytes = 0;
    }

    private lookup(key: string): Uint8Array | null {
        const entry = this.entries.get(key);
        if (!entry) return null;
        if (Date.now() - entry.storedAt >= this.retentionMs) {
            this.entries.delete(key);
            this.totalBytes -= entry.response.length;
            return null;
        }
        return new Uint8Array(entry.response);
    }

    private store(key: string, response: Uint8Array): void {
        const existing = this.entries.get(key);
        if (existing) {
            this.totalBytes -= existing.response.length;
            this.entries.delete(key);
        }
        if (this.maxEntries < 1 || response.length > this.maxTotalBytes) return;
        while (
            this.entries.size >= this.maxEntries ||
            this.totalBytes + response.length > this.maxTotalBytes
        ) {
            const oldest = this.entries.keys().next();
            if (oldest.done) break;
            const victim = this.entries.get(oldest.value);
            this.entries.delete(oldest.value);
            if (victim) this.totalBytes -= victim.response.length;
        }
        this.entries.set(key, { response: new Uint8Array(response), storedAt: Date.now() });
        this.totalBytes += response.length;
    }
}
