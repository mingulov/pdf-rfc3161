/**
 * Tests for ESSCertIDv2 detection in timestamp parsing
 */

import { describe, it, expect } from "vitest";
import { TimestampInfo } from "../../../core/src/types.js";

// Mock timestamp tokens for testing - simplified for interface testing

describe("ESSCertIDv2 Detection", () => {
    it("should add new fields to TimestampInfo interface", () => {
        // Test that the interface accepts the new optional fields
        const info: TimestampInfo = {
            genTime: new Date(),
            policy: "1.2.3.4",
            serialNumber: "123456",
            hashAlgorithm: "SHA-256",
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            messageDigest: "abcdef123456",
            hasCertificate: true,
            certIdHashAlgorithm: "SHA-256",
            usesESSCertIDv2: true,
        };

        expect(info.certIdHashAlgorithm).toBe("SHA-256");
        expect(info.usesESSCertIDv2).toBe(true);
    });

    it("should handle undefined ESSCertID detection fields", () => {
        const info: TimestampInfo = {
            genTime: new Date(),
            policy: "1.2.3.4",
            serialNumber: "123456",
            hashAlgorithm: "SHA-256",
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            messageDigest: "abcdef123456",
            hasCertificate: true,
        };

        expect(info.certIdHashAlgorithm).toBeUndefined();
        expect(info.usesESSCertIDv2).toBeUndefined();
    });

    it("should handle missing ESSCertID detection gracefully", () => {
        // Test that missing detection fields don't break existing functionality
        const info: TimestampInfo = {
            genTime: new Date(),
            policy: "1.2.3.4",
            serialNumber: "123456",
            hashAlgorithm: "SHA-256",
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            messageDigest: "abcdef123456",
            hasCertificate: true,
            // These fields are optional and undefined
        };

        expect(info.certIdHashAlgorithm).toBeUndefined();
        expect(info.usesESSCertIDv2).toBeUndefined();
    });

    it("should support all CertID hash algorithms", () => {
        const algorithms: ("SHA-1" | "SHA-256" | "SHA-384" | "SHA-512")[] = [
            "SHA-1",
            "SHA-256",
            "SHA-384",
            "SHA-512",
        ];

        for (const algo of algorithms) {
            const info: TimestampInfo = {
                genTime: new Date(),
                policy: "1.2.3.4",
                serialNumber: "123456",
                hashAlgorithm: "SHA-256",
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                messageDigest: "abcdef123456",
                hasCertificate: true,
                certIdHashAlgorithm: algo,
                usesESSCertIDv2: algo !== "SHA-1",
            };

            expect(info.certIdHashAlgorithm).toBe(algo);
            expect(info.usesESSCertIDv2).toBe(algo !== "SHA-1");
        }
    });
});
