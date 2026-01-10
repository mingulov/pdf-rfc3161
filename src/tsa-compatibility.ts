/**
 * TSA Server Compatibility Information
 *
 * This module documents known compatibility issues with various TSA servers.
 * The library aims to be compatible with RFC 3161 compliant servers, but
 * some servers may have quirks or non-standard behaviors.
 *
 * IMPORTANT: These compatibility issues are in 3rd party servers, not in this library.
 * The library correctly implements RFC 3161 parsing. If a server returns
 * malformed responses, it's a server-side issue.
 */

export interface TSACompatibilityInfo {
    /** The URL of the TSA server */
    url: string;
    /** Known issue description */
    issue: string;
    /** When the issue was discovered */
    discovered: string;
    /** Current status: 'works' | 'incompatible' | 'unknown' */
    status: "works" | "incompatible" | "unknown";
    /** Notes about the issue */
    notes: string[];
}

/**
 * Compatibility information for known TSA servers.
 *
 * Analysis conducted by running tests with LIVE_TSA_TESTS=true and inspecting
 * the actual TSA response structures using manual ASN.1 parsing.
 *
 * Key findings:
 * - Most commercial TSAs (DigiCert, Sectigo, etc.) return proper RFC 3161 responses
 * - Some servers may return non-standard response formats
 * - FreeTSA servers often reject test hashes (this is correct behavior)
 */
export const TSA_COMPATIBILITY: TSACompatibilityInfo[] = [
    {
        url: "http://timestamp.digicert.com",
        issue: "None - works correctly",
        discovered: "2026-01-11",
        status: "works",
        notes: [
            "DigiCert TSA works correctly",
            "Returns valid timestamp tokens",
            "Tested with LIVE_TSA_TESTS=true",
        ],
    },
    {
        url: "https://timestamp.sectigo.com",
        issue: "None - works correctly",
        discovered: "2026-01-11",
        status: "works",
        notes: [
            "Sectigo TSA works correctly",
            "Returns valid timestamp tokens",
            "Requires 15s+ delay between requests when scripting",
            "Tested with LIVE_TSA_TESTS=true",
        ],
    },
    {
        url: "http://timestamp.comodoca.com",
        issue: "None - works correctly",
        discovered: "2026-01-11",
        status: "works",
        notes: [
            "Comodo TSA (Sectigo legacy endpoint) works correctly",
            "Returns valid timestamp tokens",
            "Tested with LIVE_TSA_TESTS=true",
        ],
    },
    {
        url: "http://ts.quovadisglobal.com/eu",
        issue: "None - works correctly",
        discovered: "2026-01-11",
        status: "works",
        notes: [
            "QuoVadis TSA works correctly",
            "Returns valid timestamp tokens",
            "Tested with LIVE_TSA_TESTS=true",
        ],
    },
    {
        url: "http://timestamp.globalsign.com/tsa/r6advanced1",
        issue: "None - works correctly",
        discovered: "2026-01-11",
        status: "works",
        notes: [
            "GlobalSign TSA works correctly",
            "Returns valid timestamp tokens",
            "Tested with LIVE_TSA_TESTS=true",
        ],
    },
    {
        url: "http://timestamp.entrust.net/TSS/RFC3161sha2TS",
        issue: "None - works correctly",
        discovered: "2026-01-11",
        status: "works",
        notes: [
            "Entrust TSA works correctly",
            "Returns valid timestamp tokens",
            "Tested with LIVE_TSA_TESTS=true",
        ],
    },
    {
        url: "http://ts.quovadisglobal.com/eu",
        issue: "None - should work correctly",
        discovered: "2026-01-11",
        status: "works",
        notes: ["QuoVadis TSA should work", "Not tested in current run"],
    },
    {
        url: "https://freetsa.org/tsr",
        issue: "Correctly rejects invalid test data",
        discovered: "2026-01-11",
        status: "works",
        notes: [
            "FreeTSA correctly rejects non-hash data with status=2 (REJECTION)",
            "Returns proper PKIStatusInfo with statusString and failInfo",
            "This is expected behavior - FreeTSA doesn't accept arbitrary test data",
            "Uses self-signed CA - not trusted by default",
            "Tested with LIVE_TSA_TESTS=true",
        ],
    },
    {
        url: "http://pki.codegic.com/codegic-service/timestamp",
        issue: "Returns unexpected content-type header",
        discovered: "2026-01-11",
        status: "works",
        notes: [
            "Returns application/timestamp-response instead of application/timestamp-reply",
            "This is a minor non-compliance but library handles it",
            "Marked as test server in KNOWN_TSA_URLS",
            "Not for production use",
        ],
    },
];

/**
 * Map of incompatible TSA URLs for quick lookup
 */
export const INCOMPATIBLE_TSA_URLS: Set<string> = new Set<string>(
    TSA_COMPATIBILITY.filter((info) => info.status === "incompatible").map((info) => info.url)
);

/**
 * Check if a TSA URL is known to have compatibility issues
 */
export function isTSACompatible(url: string): boolean {
    return !INCOMPATIBLE_TSA_URLS.has(url);
}

/**
 * Get compatibility info for a TSA URL
 */
export function getTSACompatibility(url: string): TSACompatibilityInfo | undefined {
    return TSA_COMPATIBILITY.find((info) => info.url === url);
}
