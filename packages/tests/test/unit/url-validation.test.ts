import { describe, it, expect } from "vitest";
import {
    sanitizeTransportCause,
    sanitizeTransportMessage,
    validateUrl,
} from "../../../core/src/utils/url.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";

function expectsRejection(url: string): void {
    expect(() => validateUrl(url)).toThrow(TimestampError);
    try {
        validateUrl(url);
    } catch (e) {
        expect(e).toBeInstanceOf(TimestampError);
        expect((e as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
    }
}

describe("validateUrl (H4 SSRF guard)", () => {
    describe("happy path", () => {
        it("allows plain http and https URLs", () => {
            expect(() => validateUrl("http://example.com")).not.toThrow();
            expect(() => validateUrl("https://example.com/ocsp")).not.toThrow();
            expect(() => validateUrl("https://tsa.example.org:8443/tsr")).not.toThrow();
        });

        it("allows IPv6-routable global unicast", () => {
            expect(() => validateUrl("https://[2001:db8::1]:443/")).not.toThrow();
        });
    });

    describe("protocol blocklist", () => {
        it("rejects ftp", () => expectsRejection("ftp://example.com"));
        it("rejects file", () => expectsRejection("file:///etc/passwd"));
        it("rejects gopher", () => expectsRejection("gopher://example.com"));
        it("rejects javascript:", () => expectsRejection("javascript:alert(1)"));
        it("rejects data:", () =>
            expectsRejection("data:text/plain;base64,SGVsbG8sIFdvcmxkIQ=="));
    });

    describe("loopback hostnames", () => {
        it("rejects localhost", () => expectsRejection("http://localhost"));
        it("rejects localhost with port", () => expectsRejection("http://localhost:8080"));
        it("rejects localhost with trailing dot", () => expectsRejection("http://localhost."));
        it("rejects LOCALHOST (case-insensitive)", () =>
            expectsRejection("https://LOCALHOST/foo"));
        it("rejects ip6-localhost", () => expectsRejection("http://ip6-localhost"));
        it("rejects ip6-loopback", () => expectsRejection("http://ip6-loopback"));
    });

    describe("IPv4 reserved ranges", () => {
        it("rejects 127.0.0.1", () => expectsRejection("http://127.0.0.1"));
        it("rejects 127.x.y.z (full /8)", () => expectsRejection("http://127.0.0.99"));
        it("rejects 0.0.0.0", () => expectsRejection("http://0.0.0.0"));
        it("rejects 10.0.0.0/8", () => expectsRejection("http://10.0.0.5"));
        it("rejects 172.16.0.0/12 low", () => expectsRejection("http://172.16.0.1"));
        it("rejects 172.16.0.0/12 high", () => expectsRejection("http://172.31.255.254"));
        it("rejects 192.168.0.0/16", () => expectsRejection("http://192.168.1.1"));
        it("rejects 169.254.169.254 (cloud metadata)", () =>
            expectsRejection("http://169.254.169.254"));
        it("rejects 100.64.0.0/10 (RFC 6598 CGN)", () =>
            expectsRejection("http://100.64.0.1"));

        it("does NOT reject a public IPv4 in 172.x outside 16-31", () => {
            expect(() => validateUrl("http://172.15.0.1")).not.toThrow();
            expect(() => validateUrl("http://172.32.0.1")).not.toThrow();
        });
    });

    describe("IPv6 reserved", () => {
        it("rejects ::1", () => expectsRejection("http://[::1]"));
        it("rejects ::", () => expectsRejection("http://[::]"));
        it("rejects fc00::/7 (fc-prefix)", () => expectsRejection("http://[fc00::1]"));
        it("rejects fc00::/7 (fd-prefix)", () => expectsRejection("http://[fd00::1]"));
        it("rejects fe80::/10", () => expectsRejection("http://[fe80::1]"));
        it("rejects ::ffff:127.0.0.1 (IPv4-mapped loopback)", () =>
            expectsRejection("http://[::ffff:127.0.0.1]"));
        it("rejects ::ffff:10.0.0.1 (IPv4-mapped RFC1918)", () =>
            expectsRejection("http://[::ffff:10.0.0.1]"));
    });

    describe("malformed input", () => {
        it("rejects bare strings that don't parse as URL", () => {
            expectsRejection("not-a-url");
        });

        it("rejects URLs with empty hostname", () => {
            expectsRejection("http://");
        });
    });

    describe("opt-in escape hatch", () => {
        it("allowPrivateUrls accepts loopback when explicitly opted-in", () => {
            expect(() =>
                validateUrl("http://localhost:8080/", { allowPrivateUrls: true })
            ).not.toThrow();
            expect(() =>
                validateUrl("http://127.0.0.1/", { allowPrivateUrls: true })
            ).not.toThrow();
        });

        it("allowPrivateUrls still rejects bad protocols", () => {
            expect(() =>
                validateUrl("file:///etc/passwd", { allowPrivateUrls: true })
            ).toThrow(TimestampError);
        });
    });
});

describe("sanitizeTransportMessage (M1-cause completion)", () => {
    it("matches full URL spans case-insensitively", () => {
        const cleaned = sanitizeTransportMessage(
            "fetch failed for HTTPS://u:p@tsa.example.com/ts?token=MARKER done"
        );

        expect(cleaned).toContain("https://tsa.example.com/ts");
        expect(cleaned).not.toContain("MARKER");
        expect(cleaned).not.toContain("u:p@");
    });

    it("removes query tails beyond the old match limit", () => {
        const longQuery = `${"a".repeat(2100)}&token=MARKER`;
        const cleaned = sanitizeTransportMessage(
            `fetch failed for https://tsa.example.com/ts?${longQuery} done`
        );

        expect(cleaned).toContain("https://tsa.example.com/ts");
        expect(cleaned).not.toContain("MARKER");
        expect(cleaned).toContain("done");
    });

    it("removes quoted query values after the URL span", () => {
        const cleaned = sanitizeTransportMessage(
            'request to https://h.example/p?token="abc MARKER" failed'
        );

        expect(cleaned).toContain("https://h.example/p");
        expect(cleaned).not.toContain("MARKER");
        expect(cleaned).toContain("failed");
    });

    it("keeps quoted URLs without query values intact", () => {
        const cleaned = sanitizeTransportMessage('see "https://h.example/p" now');

        expect(cleaned).toContain('"https://h.example/p"');
        expect(cleaned).toContain("now");
    });

    it("keeps messages without URLs intact", () => {
        expect(sanitizeTransportMessage("plain failure, no url")).toBe("plain failure, no url");
    });
});

describe("sanitizeTransportMessage quoted tails round 2 (T12 P1)", () => {
    const ORIGIN = "https://tsa.example.test/ts";

    it("F1-long-quoted-tail: redacts quoted values longer than 512 chars", () => {
        const marker = "T12_FIXTURE_SECRET";
        const cleaned = sanitizeTransportMessage(
            `request failed for https://tsa.example.test/ts?token="${"a".repeat(600)}${marker}"`
        );

        expect(cleaned).toContain(ORIGIN);
        expect(cleaned).not.toContain(marker);
    });

    it("F1-query-after-quoted-value: redacts the query tail after a closing quote", () => {
        const marker = "T12_FIXTURE_SECRET";
        const cleaned = sanitizeTransportMessage(
            `request failed for https://tsa.example.test/ts?first="short"&token=${marker}`
        );

        expect(cleaned).toContain(ORIGIN);
        expect(cleaned).not.toContain(marker);
    });

    it("variant: redacts single-quoted values with spaces plus an &tail", () => {
        const marker = "T12_VARIANT_SECRET";
        const cleaned = sanitizeTransportMessage(
            `request failed for https://tsa.example.test/ts?first='a b'&token=${marker}`
        );

        expect(cleaned).toContain(ORIGIN);
        expect(cleaned).not.toContain(marker);
    });

    it("unbalanced quote fails closed: redacts the rest of the message", () => {
        const marker = "T12_UNBALANCED_SECRET";
        const cleaned = sanitizeTransportMessage(
            `request failed for https://tsa.example.test/ts?token="${"a".repeat(600)}${marker}`
        );

        expect(cleaned).toContain(ORIGIN);
        expect(cleaned).not.toContain(marker);
    });

    it("cause path: redacts long quoted tails from message and stack", () => {
        const marker = "T12_FIXTURE_SECRET";
        const failure = new Error(
            `request failed for https://tsa.example.test/ts?token="${"a".repeat(600)}${marker}"`
        );

        const cleaned = sanitizeTransportCause(failure) as Error;

        expect(cleaned.message).not.toContain(marker);
        expect(cleaned.stack ?? "").not.toContain(marker);
    });
});

describe("sanitizeTransportMessage second quoted values round 3 (T12 N1)", () => {
    const ORIGIN = "https://tsa.example.test/ts";

    it("N1-second-quoted-tail-spaces: redacts spaces inside a second quoted value", () => {
        const marker = "T12_FIXTURE_SECRET";
        const cleaned = sanitizeTransportMessage(
            `request failed for https://tsa.example.test/ts?first="short"&token="first ${marker}" failed`
        );

        expect(cleaned).toContain(ORIGIN);
        expect(cleaned).not.toContain(marker);
        expect(cleaned.endsWith(" failed")).toBe(true);
    });

    it("variant: redacts spaces inside a second single-quoted value", () => {
        const marker = "T12_FIXTURE_SECRET";
        const cleaned = sanitizeTransportMessage(
            `request failed for https://tsa.example.test/ts?first='short'&token='first ${marker}' failed`
        );

        expect(cleaned).toContain(ORIGIN);
        expect(cleaned).not.toContain(marker);
        expect(cleaned.endsWith(" failed")).toBe(true);
    });

    it("variant: redacts spaces inside a second backtick-quoted value", () => {
        const marker = "T12_FIXTURE_SECRET";
        const cleaned = sanitizeTransportMessage(
            `request failed for https://tsa.example.test/ts?first=\`short\`&token=\`first ${marker}\` failed`
        );

        expect(cleaned).toContain(ORIGIN);
        expect(cleaned).not.toContain(marker);
        expect(cleaned.endsWith(" failed")).toBe(true);
    });

    it("N1-unbalanced-second-quoted-tail: fails closed on an unterminated second quote", () => {
        const marker = "T12_FIXTURE_SECRET";
        const cleaned = sanitizeTransportMessage(
            `request failed for https://tsa.example.test/ts?first="short"&token="first ${marker} failed`
        );

        expect(cleaned).toContain(ORIGIN);
        expect(cleaned).not.toContain(marker);
    });

    it("cause path: redacts second quoted values from message and stack", () => {
        const marker = "T12_FIXTURE_SECRET";
        const failure = new Error(
            `request failed for https://tsa.example.test/ts?first="short"&token="first ${marker}" failed`
        );

        const cleaned = sanitizeTransportCause(failure) as Error;

        expect(cleaned.message).not.toContain(marker);
        expect(cleaned.stack ?? "").not.toContain(marker);
        expect(cleaned.message.endsWith(" failed")).toBe(true);
    });
});

describe("sanitizeTransportCause (M1-cause completion)", () => {
    it("sanitizes cyclic causes instead of returning the unsanitized original", () => {
        const outer = new Error("outer https://u:p@h.example/?t=MARKERA");
        const inner = new Error("inner failure", { cause: outer });
        outer.cause = inner;

        const cleaned = sanitizeTransportCause(outer) as Error;

        expect(cleaned.message).not.toContain("MARKERA");
        const cleanedInner = cleaned.cause as Error;
        expect(cleanedInner.message).toBe("inner failure");
        expect((cleanedInner.cause as Error).message).not.toContain("MARKERA");
        expect(cleanedInner.cause).toBe(cleaned);
    });

    it("sanitizes stack-only secrets instead of taking the identity shortcut", () => {
        const failure = new Error("clean message");
        failure.stack =
            "Error: clean message\n    at fetch (https://u:p@h.example/?t=MARKERS)";

        const cleaned = sanitizeTransportCause(failure) as Error;

        expect(cleaned).not.toBe(failure);
        expect(cleaned.message).toBe("clean message");
        expect(cleaned.stack ?? "").not.toContain("MARKERS");
    });

    it("preserves non-leaking causes by identity", () => {
        const failure = new Error("down", { cause: new Error("nested down") });

        expect(sanitizeTransportCause(failure)).toBe(failure);
    });

    it("passes non-Error causes through", () => {
        expect(sanitizeTransportCause(undefined)).toBeUndefined();
        expect(sanitizeTransportCause(42)).toBe(42);
    });
});
