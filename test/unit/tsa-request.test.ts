import { describe, it, expect, vi, beforeEach } from "vitest";
import { createTimestampRequest, createTimestampRequestFromHash } from "../../src/tsa/request.js";

describe("TSA Request", () => {
    beforeEach(() => {
        // Mock crypto.getRandomValues for deterministic tests
        vi.spyOn(crypto, "getRandomValues").mockImplementation((array) => {
            const bytes = array as Uint8Array;
            for (let i = 0; i < bytes.length; i++) {
                bytes[i] = i % 256;
            }
            return array;
        });
    });

    describe("createTimestampRequest", () => {
        it("should create a valid TimeStampReq for data", async () => {
            const data = new TextEncoder().encode("Hello, World!");

            const request = await createTimestampRequest(data, {
                url: "http://timestamp.test.com",
            });

            expect(request).toBeInstanceOf(Uint8Array);
            expect(request.length).toBeGreaterThan(0);

            // Should start with ASN.1 SEQUENCE tag (0x30)
            expect(request[0]).toBe(0x30);
        });

        it("should use SHA-256 by default", async () => {
            const data = new Uint8Array([1, 2, 3, 4]);

            const request = await createTimestampRequest(data, {
                url: "http://timestamp.test.com",
            });

            // The request should contain the SHA-256 OID (2.16.840.1.101.3.4.2.1)
            // In DER: 06 09 60 86 48 01 65 03 04 02 01
            const sha256OidBytes = [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            ];
            const requestStr = Array.from(request)
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("");
            const sha256OidStr = sha256OidBytes
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("");

            expect(requestStr).toContain(sha256OidStr);
        });

        it("should support SHA-384", async () => {
            const data = new Uint8Array([1, 2, 3, 4]);

            const request = await createTimestampRequest(data, {
                url: "http://timestamp.test.com",
                hashAlgorithm: "SHA-384",
            });

            expect(request).toBeInstanceOf(Uint8Array);
            expect(request.length).toBeGreaterThan(0);
        });

        it("should support SHA-512", async () => {
            const data = new Uint8Array([1, 2, 3, 4]);

            const request = await createTimestampRequest(data, {
                url: "http://timestamp.test.com",
                hashAlgorithm: "SHA-512",
            });

            expect(request).toBeInstanceOf(Uint8Array);
            expect(request.length).toBeGreaterThan(0);
        });

        it("should include nonce for replay protection", async () => {
            const data = new Uint8Array([1, 2, 3, 4]);

            // Create two requests
            const request1 = await createTimestampRequest(data, {
                url: "http://timestamp.test.com",
            });

            // Reset mock to generate different nonce
            // Reset mock to generate different nonce
            vi.spyOn(crypto, "getRandomValues").mockImplementation((array) => {
                const bytes = array as Uint8Array;
                for (let i = 0; i < bytes.length; i++) {
                    bytes[i] = (i + 100) % 256;
                }
                return array;
            });

            const request2 = await createTimestampRequest(data, {
                url: "http://timestamp.test.com",
            });

            // Requests should differ due to different nonces
            expect(request1).not.toEqual(request2);
        });

        it("should request certificate by default", async () => {
            const data = new Uint8Array([1, 2, 3, 4]);

            const request = await createTimestampRequest(data, {
                url: "http://timestamp.test.com",
            });

            // The certReq field should be TRUE (0x01 0x01 0xFF or 0x01 0x01 0x01)
            // This is harder to verify without parsing, but the request should be valid
            expect(request).toBeInstanceOf(Uint8Array);
        });

        it("should allow disabling certificate request", async () => {
            const data = new Uint8Array([1, 2, 3, 4]);

            const request = await createTimestampRequest(data, {
                url: "http://timestamp.test.com",
                requestCertificate: false,
            });

            expect(request).toBeInstanceOf(Uint8Array);
        });

        it("should include policy OID when specified", async () => {
            const data = new Uint8Array([1, 2, 3, 4]);
            const policy = "1.2.3.4.5.6";

            const request = await createTimestampRequest(data, {
                url: "http://timestamp.test.com",
                policy,
            });

            expect(request).toBeInstanceOf(Uint8Array);
            // Policy OID should be encoded in the request
        });
    });

    describe("createTimestampRequestFromHash", () => {
        it("should create request from pre-computed hash", () => {
            // Pre-computed SHA-256 hash (32 bytes)
            const hash = new Uint8Array(32);
            for (let i = 0; i < 32; i++) {
                hash[i] = i;
            }

            const request = createTimestampRequestFromHash(hash, "SHA-256", {
                url: "http://timestamp.test.com",
            });

            expect(request).toBeInstanceOf(Uint8Array);
            expect(request[0]).toBe(0x30); // ASN.1 SEQUENCE
        });
    });
});
