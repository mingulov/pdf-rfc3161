import { describe, it, expect } from "vitest";
import { validateUrl } from "../../../core/src/utils/url.js";
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
