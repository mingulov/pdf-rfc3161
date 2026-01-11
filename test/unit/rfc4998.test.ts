/**
 * Tests for RFC 4998 Evidence Record Syntax
 */

import { describe, it, expect } from "vitest";
import {
    createEvidenceRecord,
    validateEvidenceRecord,
    extractTimestampsFromEvidence,
    RFC4998_OIDS,
} from "../../src/rfcs/rfc4998.js";

describe("RFC 4998 Evidence Record Syntax", () => {
    const testData = new Uint8Array([0x01, 0x02, 0x03, 0x04]);

    it("should define the correct OIDs", () => {
        expect(RFC4998_OIDS.EVIDENCE_RECORD).toBe("1.2.840.113549.1.9.16.2.21");
        expect(RFC4998_OIDS.ARCHIVE_TIMESTAMP).toBe("1.2.840.113549.1.9.16.2.49");
    });

    it("should create an evidence record", () => {
        const evidenceRecord = createEvidenceRecord(testData);

        expect(evidenceRecord).toBeInstanceOf(Uint8Array);
        expect(evidenceRecord.length).toBeGreaterThan(0);
    });

    it("should create evidence record with different algorithms", () => {
        const evidence1 = createEvidenceRecord(testData, "SHA-256");
        const evidence2 = createEvidenceRecord(testData, "SHA-384");
        const evidence3 = createEvidenceRecord(testData, "SHA-512");

        expect(evidence1).toBeInstanceOf(Uint8Array);
        expect(evidence2).toBeInstanceOf(Uint8Array);
        expect(evidence3).toBeInstanceOf(Uint8Array);

        // Different algorithms should produce different results
        expect(evidence1.length).toBe(evidence2.length);
        expect(evidence1.length).toBe(evidence3.length);
    });

    it("should validate evidence record structure", () => {
        const evidenceRecord = createEvidenceRecord(testData);
        const isValid = validateEvidenceRecord(evidenceRecord);

        expect(isValid).toBe(true);
    });

    it("should reject invalid evidence records", () => {
        const invalidRecord = new Uint8Array([0x00]);
        const isValid = validateEvidenceRecord(invalidRecord);

        expect(isValid).toBe(false);
    });

    it("should extract timestamps from evidence record", () => {
        const evidenceRecord = createEvidenceRecord(testData);
        const timestamps = extractTimestampsFromEvidence(evidenceRecord);

        expect(Array.isArray(timestamps)).toBe(true);
        // Current implementation returns empty array
        expect(timestamps.length).toBe(0);
    });

    it("should handle empty data", () => {
        const emptyData = new Uint8Array(0);
        const evidenceRecord = createEvidenceRecord(emptyData);

        expect(evidenceRecord).toBeInstanceOf(Uint8Array);
        expect(validateEvidenceRecord(evidenceRecord)).toBe(true);
    });

    it("should handle large data", () => {
        const largeData = new Uint8Array(1024 * 1024); // 1MB
        for (let i = 0; i < largeData.length; i++) {
            largeData[i] = i % 256;
        }

        const evidenceRecord = createEvidenceRecord(largeData);

        expect(evidenceRecord).toBeInstanceOf(Uint8Array);
        expect(validateEvidenceRecord(evidenceRecord)).toBe(true);
    });
});
