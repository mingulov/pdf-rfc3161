import { describe, it, expect, vi, beforeEach } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
    createTimestampRequest,
    createTimestampRequestFromHash,
} from "../../../core/src/tsa/request.js";

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
        vi.spyOn(crypto, "getRandomValues").mockImplementation((array: Uint8Array) => {
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

            vi.spyOn(crypto, "getRandomValues").mockImplementation((array: Uint8Array) => {
                const bytes = array as Uint8Array;
                for (let i = 0; i < bytes.length; i++) {
                    bytes[i] = (i + 100) % 256;
                }
                return array;
            });

            const { request: request2 } = await createTimestampRequest(data);

            const tsReq1 = parseRequest(request1);
            const tsReq2 = parseRequest(request2);

            expect(tsReq1.nonce).toBeDefined();
            expect(tsReq2.nonce).toBeDefined();
            const nonce1 = Array.from(tsReq1.nonce!.valueBlock.valueHexView);
            const nonce2 = Array.from(tsReq2.nonce!.valueBlock.valueHexView);
            expect(nonce1).not.toEqual(nonce2);
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
