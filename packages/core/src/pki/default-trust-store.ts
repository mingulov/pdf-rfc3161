import { SimpleTrustStore, type TrustStore } from "./trust-store.js";
import { getLogger } from "../utils/logger.js";
import { TimestampError, TimestampErrorCode } from "../types.js";

/**
 * Bundled root CA certificates for the TSAs in `KNOWN_TSA_URLS`.
 *
 * EMPTY in this commit. Curation of the actual root certs is the
 * follow-up step for the H3 closure -- it requires:
 *   1. Identifying the issuing root CA for each entry in tsa-urls.ts
 *      (DigiCert Global Root CA, Sectigo Public TSA, etc.).
 *   2. Fetching the DER-encoded root cert from the CA's CPS / cert
 *      repository (e.g. https://cacerts.digicert.com/...).
 *   3. Verifying fingerprint against Mozilla's CA list or another
 *      well-known store.
 *   4. Embedding the verified DER as a base64 literal here (one entry
 *      per cert), with provenance comments.
 *
 * Until that ships, getDefaultTrustStore() returns an empty store and
 * the verify path warns the caller (see verifyTimestamp).
 */
const BUNDLED_ROOT_CERTS_BASE64: readonly {
    /** Display name, e.g. "DigiCert Global Root G2" */
    name: string;
    /** Source URL (CA's published root cert) */
    source: string;
    /** Base64-encoded DER of the cert */
    derBase64: string;
}[] = [];

let cached: SimpleTrustStore | null = null;

/**
 * Returns a TrustStore preloaded with curated root CA certificates for known
 * TSAs. The result is cached after first call.
 *
 * @throws {TimestampError} with `code = STATE_ERROR` when the bundled root
 *   list is empty. As of 0.2.0 the bundle is still empty (curation requires
 *   a maintainer with network access to fetch and cross-verify the roots),
 *   so this function currently always throws. Audit H3: the previous
 *   empty-store-with-warn behaviour was hazardous because it invited
 *   callers to assume the store was usable -- a custom `TrustStore`
 *   implementation that returns `true` on empty trust would silently accept
 *   any chain.
 *
 * Callers have three correct responses:
 *  - Build a `SimpleTrustStore` with your own pinned roots:
 *    `const store = new SimpleTrustStore(); store.addCertificate(rootDer);`
 *  - Pass `{ trustStore: null }` to `verifyTimestamp` to skip chain
 *    validation explicitly (only cryptographic integrity is checked).
 *  - Wait for the curated bundle to land in a future release.
 */
export function getDefaultTrustStore(): TrustStore {
    if (cached) return cached;
    if (BUNDLED_ROOT_CERTS_BASE64.length === 0) {
        throw new TimestampError(
            TimestampErrorCode.STATE_ERROR,
            "Default trust store is empty (no curated roots ship in this release). " +
                "Supply your own SimpleTrustStore with addCertificate(rootDer), " +
                "or pass { trustStore: null } to verifyTimestamp to skip chain " +
                "validation explicitly."
        );
    }
    cached = new SimpleTrustStore();
    for (const entry of BUNDLED_ROOT_CERTS_BASE64) {
        try {
            const der = base64ToUint8Array(entry.derBase64);
            cached.addCertificate(der);
        } catch (e) {
            getLogger().warn(
                `[pdf-rfc3161] getDefaultTrustStore: skipped bundled root "${entry.name}" (${entry.source}): ${e instanceof Error ? e.message : String(e)}`
            );
        }
    }
    return cached;
}

function base64ToUint8Array(b64: string): Uint8Array {
    // atob is a global in Node 18+ (our minimum), Workers, Deno, and browsers.
    // No Buffer fallback -- it isn't available in Workers / Deno.
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

/**
 * Test-only: clear the cached default trust store. Exported so tests
 * exercise the empty-bundle warning path without leaking state across
 * cases.
 */
export function resetDefaultTrustStoreCache(): void {
    cached = null;
}
