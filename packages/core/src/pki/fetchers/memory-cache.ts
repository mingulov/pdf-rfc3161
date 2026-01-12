import type { ValidationCache } from "../validation-types.js";

/**
 * Simple in-memory cache for revocation data.
 * Suitable for single-session caching. For multi-session caching,
 * consider implementing a persistent cache (Redis, file-based, etc.).
 */
export class InMemoryValidationCache implements ValidationCache {
    private ocspCache = new Map<string, Uint8Array>();
    private crlCache = new Map<string, Uint8Array>();

    getOCSP(url: string, request: Uint8Array): Uint8Array | null {
        // Create a simple cache key from URL and request hash
        const requestHash = Array.from(new Uint8Array(request.slice(0, 32)))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
        const cacheKey = `${url}:${requestHash}`;
        return this.ocspCache.get(cacheKey) ?? null;
    }

    setOCSP(url: string, request: Uint8Array, response: Uint8Array): void {
        // Create a simple cache key from URL and request hash
        const requestHash = Array.from(new Uint8Array(request.slice(0, 32)))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
        const cacheKey = `${url}:${requestHash}`;
        this.ocspCache.set(cacheKey, response);
    }

    getCRL(url: string): Uint8Array | null {
        return this.crlCache.get(url) ?? null;
    }

    setCRL(url: string, response: Uint8Array): void {
        this.crlCache.set(url, response);
    }

    clear(): void {
        this.ocspCache.clear();
        this.crlCache.clear();
    }
}
