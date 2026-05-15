import { TimestampError, TimestampErrorCode } from "../types.js";

/**
 * Options for {@link validateUrl}.
 */
export interface ValidateUrlOptions {
    /**
     * Allow URLs that target loopback / private / link-local addresses.
     * Default: false. Set true only in development or with great care --
     * disabling this check re-enables SSRF in any deployment that processes
     * untrusted PDFs or certificates (REVIEW-2026-02-09 H4).
     */
    allowPrivateUrls?: boolean;
}

const MAX_HOSTNAME_LENGTH = 253;

// Hostnames that route to the local machine no matter the deployment.
const RESTRICTED_LITERAL_HOSTNAMES = new Set([
    "localhost",
    "ip6-localhost",
    "ip6-loopback",
]);

function stripBrackets(hostname: string): string {
    if (hostname.startsWith("[") && hostname.endsWith("]")) {
        return hostname.slice(1, -1);
    }
    return hostname;
}

/**
 * Parse a 4-octet IPv4 dotted-quad. Returns null for anything else --
 * shortform (e.g. "127.1"), hex, octal, and IPv6 are intentionally not
 * accepted here; if a caller wants those they should pre-normalize. We
 * accept only the canonical dotted-quad because (a) that is what `new URL`
 * exposes via .hostname, and (b) anything else is suspicious and should
 * be rejected by the surrounding parse.
 */
function parseIPv4(hostname: string): number[] | null {
    const parts = hostname.split(".");
    if (parts.length !== 4) return null;
    const octets: number[] = [];
    for (const p of parts) {
        if (!/^\d{1,3}$/.test(p)) return null;
        const n = parseInt(p, 10);
        if (n < 0 || n > 255) return null;
        octets.push(n);
    }
    return octets;
}

function isPrivateIPv4(octets: number[]): boolean {
    const [a = 0, b = 0] = octets;
    // 10.0.0.0/8
    if (a === 10) return true;
    // 172.16.0.0/12
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16
    if (a === 192 && b === 168) return true;
    // 100.64.0.0/10 (CGN per RFC 6598)
    if (a === 100 && b >= 64 && b <= 127) return true;
    // 127.0.0.0/8 (all loopback, not just .0.1)
    if (a === 127) return true;
    // 169.254.0.0/16 (link-local incl. cloud metadata 169.254.169.254)
    if (a === 169 && b === 254) return true;
    // 0.0.0.0/8
    if (a === 0) return true;
    return false;
}

function isLikelyIPv6(hostname: string): boolean {
    // hostname() from new URL() returns IPv6 with brackets stripped by some
    // runtimes, with brackets by others. Strip then look for any ':'.
    return stripBrackets(hostname).includes(":");
}

function isPrivateIPv6(stripped: string): boolean {
    const lower = stripped.toLowerCase();
    // ::1 -- loopback
    if (lower === "::1") return true;
    // :: -- unspecified
    if (lower === "::") return true;
    // IPv4-mapped IPv6 (::ffff:0:0/96): canonical dotted form ::ffff:127.0.0.1
    // OR hex form ::ffff:7f00:1 (what Node's URL parser produces).
    if (lower.startsWith("::ffff:")) {
        const rest = lower.slice(7);
        const v4Dotted = parseIPv4(rest);
        if (v4Dotted && isPrivateIPv4(v4Dotted)) return true;
        // Hex form: two groups of up to 4 hex digits joined by ':'
        const hexGroups = rest.split(":");
        if (hexGroups.length === 2) {
            const hi = parseInt(hexGroups[0] ?? "", 16);
            const lo = parseInt(hexGroups[1] ?? "", 16);
            if (Number.isFinite(hi) && Number.isFinite(lo)) {
                const v4 = [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff];
                if (isPrivateIPv4(v4)) return true;
            }
        }
    }
    // fc00::/7 -- Unique local
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
    // fe80::/10 -- Link-local
    if (lower.startsWith("fe8") || lower.startsWith("fe9") ||
        lower.startsWith("fea") || lower.startsWith("feb")) return true;
    return false;
}

/**
 * Validate a URL is safe to fetch from the timestamping pipeline. Throws
 * TimestampError(NETWORK_ERROR) on:
 *   - non-http(s) protocols
 *   - empty or excessively long hostname
 *   - hostnames that point at the local machine
 *   - IP literals in private / loopback / link-local / IPv4-mapped IPv6 ranges
 *
 * This is a defence-in-depth check against the SSRF surface from
 * certificate-supplied AIA / OCSP / CRL URLs (REVIEW-2026-02-09 H4). It is
 * NOT a substitute for network egress controls -- a determined attacker
 * with DNS control can still cause a public name to resolve to a private
 * IP at fetch time (DNS rebinding). For that, use opt-in network policies.
 */
export function validateUrl(urlString: string, options: ValidateUrlOptions = {}): void {
    let url: URL;
    try {
        url = new URL(urlString);
    } catch (error) {
        throw new TimestampError(
            TimestampErrorCode.NETWORK_ERROR,
            `Invalid URL: ${urlString}`,
            error
        );
    }

    if (url.protocol !== "http:" && url.protocol !== "https:") {
        throw new TimestampError(
            TimestampErrorCode.NETWORK_ERROR,
            `Invalid URL protocol: ${url.protocol}. Only http: and https: are allowed.`
        );
    }

    const rawHost = url.hostname.toLowerCase();
    if (!rawHost) {
        throw new TimestampError(
            TimestampErrorCode.NETWORK_ERROR,
            `Invalid URL: missing hostname in ${urlString}`
        );
    }
    if (rawHost.length > MAX_HOSTNAME_LENGTH) {
        throw new TimestampError(
            TimestampErrorCode.NETWORK_ERROR,
            `Hostname too long (${rawHost.length.toString()} > ${MAX_HOSTNAME_LENGTH.toString()})`
        );
    }

    if (options.allowPrivateUrls) {
        return;
    }

    if (RESTRICTED_LITERAL_HOSTNAMES.has(rawHost)) {
        throw new TimestampError(
            TimestampErrorCode.NETWORK_ERROR,
            `URL targets a restricted hostname: ${rawHost}`
        );
    }

    // Trailing-dot canonicalisation: `localhost.` resolves to localhost.
    if (rawHost.endsWith(".")) {
        const stripped = rawHost.slice(0, -1);
        if (RESTRICTED_LITERAL_HOSTNAMES.has(stripped)) {
            throw new TimestampError(
                TimestampErrorCode.NETWORK_ERROR,
                `URL targets a restricted hostname: ${rawHost}`
            );
        }
    }

    const ipv4 = parseIPv4(rawHost);
    if (ipv4 && isPrivateIPv4(ipv4)) {
        throw new TimestampError(
            TimestampErrorCode.NETWORK_ERROR,
            `URL targets a private or reserved IPv4 address: ${rawHost}`
        );
    }

    if (isLikelyIPv6(rawHost)) {
        const stripped = stripBrackets(rawHost);
        if (isPrivateIPv6(stripped)) {
            throw new TimestampError(
                TimestampErrorCode.NETWORK_ERROR,
                `URL targets a private or reserved IPv6 address: ${rawHost}`
            );
        }
    }
}
