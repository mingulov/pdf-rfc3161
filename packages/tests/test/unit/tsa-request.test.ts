import { describe, it, expect, vi, beforeEach } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
    createTimestampRequest,
    createTimestampRequestFromHash,
} from "../../../core/src/tsa/request.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";

const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const SHA384_OID = "2.16.840.1.101.3.4.2.2";
const SHA512_OID = "2.16.840.1.101.3.4.2.3";

function parseRequest(request: Uint8Array): pkijs.TimeStampReq {
    const asn1 = asn1js.fromBER(request.slice().buffer);
    expect(asn1.offset).not.toBe(-1);
    return new pkijs.TimeStampReq({ schema: asn1.result });
}

describe("TSA Request", () => {
    beforeEach(() => {
        vi.spyOn(crypto, "getRandomValues").mockImplementation(
            <T extends ArrayBufferView<ArrayBuffer>>(array: T): T => {
                const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
                for (let i = 0; i < bytes.length; i++) {
                    bytes[i] = i % 256;
                }
                return array;
            }
        );
    });

    describe("createTimestampRequest", () => {
        it("should create a valid TimeStampReq for data", async () => {
            const data = new TextEncoder().encode("Hello, World!");

            const { request } = await createTimestampRequest(data);

            const tsReq = parseRequest(request);
            expect(tsReq.version).toBe(1);
            expect(tsReq.messageImprint).toBeDefined();
            expect(tsReq.messageImprint.hashedMessage.valueBlock.valueHexView.length).toBe(32);
        });

        it("should use SHA-256 by default", async () => {
            const data = new Uint8Array([1, 2, 3, 4]);

            const { request } = await createTimestampRequest(data);

            const tsReq = parseRequest(request);
            expect(tsReq.messageImprint.hashAlgorithm.algorithmId).toBe(SHA256_OID);
            expect(tsReq.messageImprint.hashedMessage.valueBlock.valueHexView.length).toBe(32);
        });

        it("should support SHA-384", async () => {
            const data = new Uint8Array([1, 2, 3, 4]);

            const { request } = await createTimestampRequest(data, {
                hashAlgorithm: "SHA-384",
            });

            const tsReq = parseRequest(request);
            expect(tsReq.messageImprint.hashAlgorithm.algorithmId).toBe(SHA384_OID);
            expect(tsReq.messageImprint.hashedMessage.valueBlock.valueHexView.length).toBe(48);
        });

        it("should support SHA-512", async () => {
            const data = new Uint8Array([1, 2, 3, 4]);

            const { request } = await createTimestampRequest(data, {
                hashAlgorithm: "SHA-512",
            });

            const tsReq = parseRequest(request);
            expect(tsReq.messageImprint.hashAlgorithm.algorithmId).toBe(SHA512_OID);
            expect(tsReq.messageImprint.hashedMessage.valueBlock.valueHexView.length).toBe(64);
        });

        it("should include nonce for replay protection", async () => {
            const data = new Uint8Array([1, 2, 3, 4]);

            const { request: request1 } = await createTimestampRequest(data);

            vi.spyOn(crypto, "getRandomValues").mockImplementation(
                <T extends ArrayBufferView<ArrayBuffer>>(array: T): T => {
                    const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
                    for (let i = 0; i < bytes.length; i++) {
                        bytes[i] = (i + 100) % 256;
                    }
                    return array;
                }
            );

            const { request: request2 } = await createTimestampRequest(data);

            const tsReq1 = parseRequest(request1);
            const tsReq2 = parseRequest(request2);

            expect(tsReq1.nonce).toBeDefined();
            expect(tsReq2.nonce).toBeDefined();
            const nonce1 = Array.from(tsReq1.nonce!.valueBlock.valueHexView);
            const nonce2 = Array.from(tsReq2.nonce!.valueBlock.valueHexView);
            expect(nonce1).not.toEqual(nonce2);
        });

        it("normalizes generated nonces to positive nonzero DER INTEGER values", async () => {
            vi.spyOn(crypto, "getRandomValues").mockImplementation(
                <T extends ArrayBufferView<ArrayBuffer>>(array: T): T => {
                    new Uint8Array(array.buffer, array.byteOffset, array.byteLength).fill(0xff);
                    return array;
                }
            );

            const { request, nonce } = await createTimestampRequest(new Uint8Array([1, 2, 3, 4]));
            const tsReq = parseRequest(request);

            expect(nonce[0]).toBe(0x7f);
            expect(tsReq.nonce).toBeDefined();
            expect(new Uint8Array(tsReq.nonce!.valueBlock.valueHexView)).toEqual(nonce);
        });

        it("should request certificate by default", async () => {
            const data = new Uint8Array([1, 2, 3, 4]);

            const { request } = await createTimestampRequest(data);

            const tsReq = parseRequest(request);
            expect(tsReq.certReq).toBe(true);
        });

        it("should allow disabling certificate request", async () => {
            const data = new Uint8Array([1, 2, 3, 4]);

            const { request } = await createTimestampRequest(data, {
                requestCertificate: false,
            });

            const tsReq = parseRequest(request);
            // certReq defaults to false in the ASN.1 schema; absence is encoded as false
            expect(tsReq.certReq ?? false).toBe(false);
        });

        it("should include policy OID when specified", async () => {
            const data = new Uint8Array([1, 2, 3, 4]);
            const policy = "1.2.3.4.5.6";

            const { request } = await createTimestampRequest(data, {
                policy,
            });

            const tsReq = parseRequest(request);
            expect(tsReq.reqPolicy).toBe(policy);
        });
    });

    describe("createTimestampRequestFromHash", () => {
        it("should create request from pre-computed hash", () => {
            const hash = new Uint8Array(32);
            for (let i = 0; i < 32; i++) {
                hash[i] = i;
            }

            const { request } = createTimestampRequestFromHash(hash, "SHA-256");

            const tsReq = parseRequest(request);
            expect(tsReq.messageImprint.hashAlgorithm.algorithmId).toBe(SHA256_OID);
            const actualHash = Array.from(tsReq.messageImprint.hashedMessage.valueBlock.valueHexView);
            expect(actualHash).toEqual(Array.from(hash));
        });

        // T11 (R19): RFC 3161 S2.4.1 requires the imprint length to match
        // the hash algorithm (32/48/64 bytes). Wrong lengths reject with
        // INVALID_ARGUMENT before serialization -- including offset views,
        // which must measure the view, not the backing buffer.
        it.each([
            ["SHA-256" as const, 32],
            ["SHA-384" as const, 48],
            ["SHA-512" as const, 64],
        ])("accepts an exact-length %s digest", (algorithm, length) => {
            const hash = new Uint8Array(length).fill(7);
            const { request } = createTimestampRequestFromHash(hash, algorithm);
            const tsReq = parseRequest(request);
            expect(tsReq.messageImprint.hashedMessage.valueBlock.valueHexView.length).toBe(length);
        });

        it.each([
            ["SHA-256" as const, 31, 32],
            ["SHA-256" as const, 33, 32],
            ["SHA-384" as const, 32, 48],
            ["SHA-384" as const, 49, 48],
            ["SHA-512" as const, 33, 64],
            ["SHA-512" as const, 65, 64],
            ["SHA-256" as const, 0, 32],
        ])("rejects a %s digest of %i bytes before serialization", (algorithm, length, expected) => {
            const hash = new Uint8Array(length).fill(7);
            try {
                createTimestampRequestFromHash(hash, algorithm);
            } catch (error) {
                expect(error).toBeInstanceOf(TimestampError);
                expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_ARGUMENT);
                expect((error as TimestampError).message).toContain(
                    `${algorithm} digest must be ${expected.toString()} bytes`
                );
                return;
            }
            throw new Error(`expected a ${length.toString()}-byte ${algorithm} digest to throw`);
        });

        it("measures offset views by the view, not the backing buffer", () => {
            const backing = new Uint8Array(96).fill(7);
            const shortView = backing.subarray(8, 39);
            expect(shortView.length).toBe(31);
            expect(() => createTimestampRequestFromHash(shortView, "SHA-256")).toThrow(TimestampError);

            const exactView = backing.subarray(8, 40);
            expect(exactView.length).toBe(32);
            const { request } = createTimestampRequestFromHash(exactView, "SHA-256");
            const tsReq = parseRequest(request);
            expect(Array.from(tsReq.messageImprint.hashedMessage.valueBlock.valueHexView)).toEqual(
                Array.from(exactView)
            );
        });
    });

    // Audit B: TimestampRequestOptions coverage gaps. The existing tests
    // cover policy / hash-algo / cert-by-default well, but the no-options
    // form, the explicit-certReq-false path, and createTimestampRequestFromHash
    // with policy + requestCertificate were untested.
    describe("TimestampRequestOptions coverage (audit B)", () => {
        it("createTimestampRequest(data) with no options object defaults to SHA-256 + certReq=true", async () => {
            const { request, nonce } = await createTimestampRequest(
                new Uint8Array([1, 2, 3, 4])
            );

            const tsReq = parseRequest(request);
            expect(tsReq.messageImprint.hashAlgorithm.algorithmId).toBe(SHA256_OID);
            expect(tsReq.certReq).toBe(true);
            expect(nonce.length).toBe(8);
        });

        it("createTimestampRequest with requestCertificate: false produces certReq=false in DER", async () => {
            const { request } = await createTimestampRequest(new Uint8Array([1, 2, 3, 4]), {
                requestCertificate: false,
            });

            const tsReq = parseRequest(request);
            // Some pkijs builds default certReq to false when absent; either
            // an explicit false or an absent field is acceptable.
            expect(tsReq.certReq ?? false).toBe(false);
        });

        it("createTimestampRequestFromHash forwards policy and requestCertificate options", () => {
            const hash = new Uint8Array(32);
            for (let i = 0; i < 32; i++) hash[i] = i;

            const { request } = createTimestampRequestFromHash(hash, "SHA-256", {
                policy: "1.2.3.4.5.6",
                requestCertificate: false,
            });

            const tsReq = parseRequest(request);
            expect(tsReq.reqPolicy).toBe("1.2.3.4.5.6");
            expect(tsReq.certReq ?? false).toBe(false);
        });

        it("createTimestampRequestFromHash with no options defaults to certReq=true", () => {
            const hash = new Uint8Array(32);
            const { request, nonce } = createTimestampRequestFromHash(hash, "SHA-256");

            const tsReq = parseRequest(request);
            expect(tsReq.certReq).toBe(true);
            expect(nonce.length).toBe(8);
        });
    });
});
