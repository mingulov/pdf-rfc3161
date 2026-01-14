/**
 * RFC 4998 - Evidence Record Syntax (ERS)
 *
 * This module provides support for Evidence Records - an alternative
 * to RFC 3161 timestamps for long-term evidence preservation.
 *
 * Evidence Records are designed for archival systems and can contain
 * multiple evidence chains over time, making them suitable for
 * long-term validation scenarios where timestamps might need renewal.
 */

import * as asn1js from "asn1js";
import { OID } from "../constants.js";

/**
 * Represents an Evidence Record as defined in RFC 4998
 */
export interface EvidenceRecord {
    /** Version of the evidence record format */
    version: number;
    /** Digest algorithm used */
    digestAlgorithm: string;
    /** Cryptographic materials used in validation */
    cryptoInfos?: CryptoInfo[];
    /** Evidence chains */
    evidenceList?: Evidence[];
}

/**
 * Cryptographic information for evidence validation
 */
export interface CryptoInfo {
    /** Digest algorithm identifier */
    digestAlgorithm: string;
    /** Digest of the data being evidenced */
    digest: Uint8Array;
}

/**
 * Evidence chain entry
 */
export interface Evidence {
    /** Timestamp tokens or other evidence */
    timestampTokens?: Uint8Array[];
    /** Archive timestamps for renewal */
    archiveTimestamps?: Uint8Array[];
}

/**
 * Creates an Evidence Record for the given data.
 *
 * @param data - The data to create evidence for
 * @param digestAlgorithm - Hash algorithm to use (default: SHA-256)
 * @returns DER-encoded Evidence Record
 */
export function createEvidenceRecord(
    _data: Uint8Array,
    _digestAlgorithm: "SHA-256" | "SHA-384" | "SHA-512" = "SHA-256"
): Uint8Array {
    // This is a simplified implementation
    // Full RFC 4998 implementation would require complex ASN.1 structures

    // For now, return a minimal structure
    // In practice, this would create proper EvidenceRecord syntax
    const evidenceRecord = new asn1js.Sequence({
        value: [
            new asn1js.Integer({ value: 1 }), // version
            // Additional fields would be added here
        ],
    });

    return new Uint8Array(evidenceRecord.toBER(false));
}

/**
 * Adds a timestamp token to an existing Evidence Record.
 *
 * @param evidenceRecord - Existing evidence record
 * @param timestampToken - New timestamp token to add
 * @returns Updated evidence record
 */
export function addTimestampToEvidence(
    evidenceRecord: Uint8Array,
    _timestampToken: Uint8Array
): Uint8Array {
    // Simplified implementation
    // Would parse existing record and add new evidence
    return evidenceRecord;
}

/**
 * Validates an Evidence Record structure.
 *
 * @param evidenceRecord - The evidence record to validate
 * @returns True if the record is valid
 */
export function validateEvidenceRecord(evidenceRecord: Uint8Array): boolean {
    try {
        // Parse and validate the ASN.1 structure
        // This is a placeholder - full validation would be complex
        if (evidenceRecord.length < 2) return false; // Minimum ASN.1 structure size

        // Try to parse as ASN.1
        const result = asn1js.fromBER(evidenceRecord.slice().buffer);
        if (result.offset === -1) return false; // Failed to parse

        // Basic validation: should have a sequence tag
        if (!(result.result instanceof asn1js.Sequence)) return false;

        return true;
    } catch {
        return false;
    }
}

/**
 * Extracts timestamp tokens from an Evidence Record.
 *
 * @param evidenceRecord - The evidence record
 * @returns Array of timestamp tokens
 */
export function extractTimestampsFromEvidence(_evidenceRecord: Uint8Array): Uint8Array[] {
    // Simplified - would parse the ASN.1 structure
    // For now, return empty array
    return [];
}

/**
 * Constants for RFC 4998 support
 */
export const RFC4998_OIDS = {
    EVIDENCE_RECORD: OID.EVIDENCE_RECORD,
    ARCHIVE_TIMESTAMP: OID.ARCHIVE_TIMESTAMP,
} as const;
