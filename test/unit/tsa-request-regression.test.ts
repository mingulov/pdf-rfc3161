import { describe, it, expect, vi, beforeEach } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { createTimestampRequest, createTimestampRequestFromHash } from "../../src/tsa/request.js";

const TEST_CONFIG = { url: "http://timestamp.test.com" };

describe("Regression: Timestamp Request Validation", () => {
    beforeEach(() => {
        vi.spyOn(crypto, "getRandomValues").mockImplementation((array) => {
            const bytes = array as Uint8Array;
            for (let i = 0; i < bytes.length; i++) {
                bytes[i] = i % 256;
            }
            return array;
        });
    });

    it("should generate valid timestamp request", async () => {
        const data = new Uint8Array([1, 2, 3, 4, 5]);
        const request = await createTimestampRequest(data, TEST_CONFIG);

        expect(request.length).toBeGreaterThanOrEqual(60);
        expect(request[0]).toBe(0x30);

        const asn1 = asn1js.fromBER(request.slice().buffer);
        expect(asn1.offset).not.toBe(-1);

        const tsReq = new pkijs.TimeStampReq({ schema: asn1.result });
        expect(tsReq.version).toBe(1);
        expect(tsReq.messageImprint).toBeDefined();
        expect(tsReq.messageImprint.hashAlgorithm.algorithmId).toBe("2.16.840.1.101.3.4.2.1");
        expect(tsReq.messageImprint.hashedMessage.valueBlock.valueHexView.length).toBe(32);
        expect(tsReq.certReq).toBe(true);
        expect(tsReq.nonce).toBeDefined();
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        expect(tsReq.nonce!.valueBlock.valueHexView.length).toBe(8);
    });

    it("should work with different hash algorithms", async () => {
        const data = new Uint8Array([1, 2, 3, 4, 5]);

        const sha256 = await createTimestampRequest(data, {
            ...TEST_CONFIG,
            hashAlgorithm: "SHA-256",
        });
        expect(sha256.length).toBeGreaterThanOrEqual(60);
        expect(sha256[0]).toBe(0x30);

        const sha384 = await createTimestampRequest(data, {
            ...TEST_CONFIG,
            hashAlgorithm: "SHA-384",
        });
        expect(sha384.length).toBeGreaterThanOrEqual(76);
        expect(sha384[0]).toBe(0x30);

        const sha512 = await createTimestampRequest(data, {
            ...TEST_CONFIG,
            hashAlgorithm: "SHA-512",
        });
        expect(sha512.length).toBeGreaterThanOrEqual(92);
        expect(sha512[0]).toBe(0x30);
    });

    it("should handle large and small inputs", async () => {
        const largeData = new Uint8Array(1024 * 1024);
        crypto.getRandomValues(largeData);
        const largeRequest = await createTimestampRequest(largeData, TEST_CONFIG);
        expect(largeRequest.length).toBeGreaterThanOrEqual(60);
        expect(largeRequest[0]).toBe(0x30);

        const minimalData = new Uint8Array([0xff]);
        const minimalRequest = await createTimestampRequest(minimalData, TEST_CONFIG);
        expect(minimalRequest.length).toBeGreaterThanOrEqual(60);
        expect(minimalRequest[0]).toBe(0x30);
    });

    it("should work with pre-computed hash", () => {
        const hash = new Uint8Array(32);
        crypto.getRandomValues(hash);
        const request = createTimestampRequestFromHash(hash, "SHA-256", TEST_CONFIG);

        expect(request.length).toBeGreaterThanOrEqual(60);
        expect(request[0]).toBe(0x30);

        const asn1 = asn1js.fromBER(request.slice().buffer);
        expect(asn1.offset).not.toBe(-1);

        const tsReq = new pkijs.TimeStampReq({ schema: asn1.result });
        expect(tsReq.version).toBe(1);
        expect(tsReq.messageImprint.hashedMessage.valueBlock.valueHexView.length).toBe(32);
        expect(tsReq.nonce).toBeDefined();
    });

    it("should survive encode-decode round-trip", async () => {
        const data = new Uint8Array([1, 2, 3, 4, 5]);
        const request = await createTimestampRequest(data, TEST_CONFIG);

        const asn1 = asn1js.fromBER(request.slice().buffer);
        const tsReq = new pkijs.TimeStampReq({ schema: asn1.result });
        const schema = tsReq.toSchema();
        const berBuffer = schema.toBER(false);
        const reencoded = new Uint8Array(berBuffer);

        expect(Array.from(request)).toEqual(Array.from(reencoded));
    });

    it("should contain correct hash value", async () => {
        const data = new Uint8Array([1, 2, 3, 4, 5]);
        const expectedHashBuffer = await crypto.subtle.digest("SHA-256", data);
        const expectedHash = new Uint8Array(expectedHashBuffer);

        const request = await createTimestampRequest(data, TEST_CONFIG);
        const asn1 = asn1js.fromBER(request.slice().buffer);
        const tsReq = new pkijs.TimeStampReq({ schema: asn1.result });

        const actualHash = tsReq.messageImprint.hashedMessage.valueBlock.valueHexView;
        expect(actualHash).toBeDefined();

        expect(actualHash.length).toBe(32);
        expect(Array.from(actualHash)).toEqual(Array.from(expectedHash));
    });
});
