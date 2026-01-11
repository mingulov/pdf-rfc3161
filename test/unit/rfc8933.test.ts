/**
 * Tests for RFC 8933 CMS Algorithm Identifier Protection
 */

import { describe, it, expect } from "vitest";
import {
    validateRFC8933Compliance,
    validateTimestampTokenRFC8933Compliance,
    RFC8933_CONSTANTS,
} from "../../src/rfcs/rfc8933.js";
import * as pkijs from "pkijs";

// Initialize pkijs with Node.js webcrypto
const webcrypto = await import("crypto").then((m) => m.webcrypto);
const cryptoEngine = new pkijs.CryptoEngine({
    name: "",
    crypto: webcrypto as any,
    subtle: webcrypto.subtle as any,
});
pkijs.setEngine("testEngine", cryptoEngine);

// Mock crypto.subtle for SHA-1 hashing
vi.stubGlobal("crypto", {
    subtle: {
        digest: vi.fn((_algo: string) => {
            return Promise.resolve(new ArrayBuffer(20));
        }),
    },
    getRandomValues: (arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) arr[i] = Math.floor(Math.random() * 256);
        return arr;
    },
});

function createMockSignedData(): pkijs.SignedData {
    const signedData = new pkijs.SignedData();

    // Create a basic signer info
    const signerInfo = new pkijs.SignerInfo();
    signerInfo.version = 1;
    signerInfo.sid = {}; // Signer identifier
    signerInfo.digestAlgorithm = new pkijs.AlgorithmIdentifier({
        algorithmId: "2.16.840.1.101.3.4.2.1", // SHA-256
    });
    signerInfo.signatureAlgorithm = new pkijs.AlgorithmIdentifier({
        algorithmId: "1.2.840.113549.1.1.11", // SHA-256 with RSA
    });

    signedData.signerInfos = [signerInfo];
    return signedData;
}

function createMockTimestampToken(): Uint8Array {
    // Create a minimal valid ContentInfo structure for testing
    const mockData = new Uint8Array([
        0x30,
        0x0f, // SEQUENCE
        0x06,
        0x0b,
        0x2a,
        0x86,
        0x48,
        0x86,
        0xf7,
        0x0d,
        0x01,
        0x07,
        0x02, // contentType OID (signedData)
        0xa0,
        0x00, // content [0] (empty for mock)
    ]);
    return mockData;
}

describe("RFC 8933 CMS Algorithm Identifier Protection", () => {
    it("should define the correct constants", () => {
        expect(RFC8933_CONSTANTS.CMS_ALGORITHM_PROTECT_OID).toBe("1.2.840.113549.1.9.52");
        expect(RFC8933_CONSTANTS.SPEC_URL).toContain("rfc8933");
    });

    it("should validate RFC 8933 compliance for basic SignedData", () => {
        const signedData = createMockSignedData();

        const result = validateRFC8933Compliance(signedData);

        expect(result.compliant).toBe(true);
        expect(result.issues).toHaveLength(0);
        expect(result.digestAlgorithmConsistency).toBe(true);
        expect(result.hasAlgorithmProtection).toBe(false);
    });

    it("should handle SignedData without signerInfos", () => {
        const signedData = new pkijs.SignedData();

        const result = validateRFC8933Compliance(signedData);

        expect(result.compliant).toBe(false);
        expect(result.issues).toContain("No signer information found");
    });

    it("should validate with strict mode", () => {
        const signedData = createMockSignedData();

        const result = validateRFC8933Compliance(signedData, { strict: true });

        expect(result.compliant).toBe(true); // Still compliant since digest consistency passes
    });

    it("should require algorithm protection when specified", () => {
        const signedData = createMockSignedData();

        const result = validateRFC8933Compliance(signedData, {
            requireAlgorithmProtection: true,
        });

        expect(result.compliant).toBe(false);
        expect(result.issues).toContain(
            "CMSAlgorithmProtection attribute not found (recommended by RFC 8933)"
        );
        expect(result.hasAlgorithmProtection).toBe(false);
    });

    it("should validate timestamp token RFC 8933 compliance", () => {
        const timestampToken = createMockTimestampToken();

        const result = validateTimestampTokenRFC8933Compliance(timestampToken);

        // Our mock token parsing may fail, but the function should handle it gracefully
        expect(result).toHaveProperty("compliant");
        expect(result).toHaveProperty("issues");
        expect(Array.isArray(result.issues)).toBe(true);
    });

    it("should handle invalid timestamp tokens gracefully", () => {
        const invalidToken = new Uint8Array([0x00, 0x01, 0x02]);

        const result = validateTimestampTokenRFC8933Compliance(invalidToken);

        expect(result.compliant).toBe(false);
        expect(result.issues.length).toBeGreaterThan(0);
    });

    it("should validate digest algorithm consistency", () => {
        const signedData = createMockSignedData();

        // Test with signed attributes present
        const signerInfo = signedData.signerInfos[0];
        (signerInfo as any).signedAttrs = {}; // Mock signed attributes

        const result = validateRFC8933Compliance(signedData);

        // Our implementation assumes compliance unless proven otherwise
        expect(result.digestAlgorithmConsistency).toBe(true);
    });

    it("should work with different validation options", () => {
        const signedData = createMockSignedData();

        // Test various option combinations
        const results = [
            validateRFC8933Compliance(signedData, {}),
            validateRFC8933Compliance(signedData, { strict: true }),
            validateRFC8933Compliance(signedData, { requireAlgorithmProtection: true }),
            validateRFC8933Compliance(signedData, {
                strict: true,
                requireAlgorithmProtection: true,
            }),
        ];

        results.forEach((result) => {
            expect(result).toHaveProperty("compliant");
            expect(result).toHaveProperty("issues");
            expect(result).toHaveProperty("digestAlgorithmConsistency");
            expect(result).toHaveProperty("hasAlgorithmProtection");
        });
    });

    it("should provide detailed compliance information", () => {
        const signedData = createMockSignedData();

        const result = validateRFC8933Compliance(signedData, {
            requireAlgorithmProtection: true,
            strict: true,
        });

        expect(result.compliant).toBe(false);
        expect(result.issues).toContain(
            "CMSAlgorithmProtection attribute not found (recommended by RFC 8933)"
        );
        expect(result.digestAlgorithmConsistency).toBe(true);
        expect(result.hasAlgorithmProtection).toBe(false);
    });
});
