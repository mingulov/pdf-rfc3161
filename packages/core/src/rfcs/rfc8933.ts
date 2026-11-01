/**
 * RFC 8933 - Update to CMS for Algorithm Identifier Protection
 *
 * This module validates RFC 8933 compliance in CMS SignedData structures,
 * particularly timestamp tokens, to ensure algorithm identifier protection.
 */

import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { TimestampError, TimestampErrorCode } from "../types.js";
import { toArrayBuffer } from "../utils.js";

/**
 * Validates RFC 8933 compliance for a CMS SignedData structure.
 *
 * RFC 8933 requires:
 * 1. Same digest algorithm used for content and signed attributes
 * 2. Recommendation to include CMSAlgorithmProtection attribute
 *
 * @param signedData - The SignedData structure to validate
 * @param options - Validation options
 * @returns Validation result
 *
 * @example
 * ```typescript
 * import { validateRFC8933Compliance } from "pdf-rfc3161/rfcs/rfc8933";
 * const report = validateRFC8933Compliance(signedData, { strict: true });
 * if (!report.compliant) console.warn("RFC 8933 issues:", report.issues);
 * ```
 */
export function validateRFC8933Compliance(
    signedData: pkijs.SignedData,
    options: {
        /** Require CMSAlgorithmProtection attribute (RFC 6211) */
        requireAlgorithmProtection?: boolean;
        /** Strict mode - reject non-compliant structures */
        strict?: boolean;
    } = {}
): RFC8933ValidationResult {
    const result: RFC8933ValidationResult = {
        compliant: true,
        issues: [],
        digestAlgorithmConsistency: true,
        hasAlgorithmProtection: false,
    };

    if (signedData.signerInfos.length === 0) {
        result.compliant = false;
        result.issues.push("No signer information found");
        return result;
    }

    for (const signerInfo of signedData.signerInfos) {
        // Check 1: declared digest matches the protected digest, when present
        const digestAlgorithmConsistency = validateDigestAlgorithmConsistency(signerInfo);
        if (!digestAlgorithmConsistency) {
            result.digestAlgorithmConsistency = false;
            result.issues.push(
                "Digest algorithm mismatch between SignerInfo and CMSAlgorithmProtection attribute"
            );
            if (options.strict) {
                result.compliant = false;
            }
        }

        // Check 2: Presence of CMSAlgorithmProtection attribute (recommended)
        const hasProtection = hasAlgorithmProtectionAttribute(signerInfo);
        if (hasProtection) {
            result.hasAlgorithmProtection = true;
        } else if (options.requireAlgorithmProtection) {
            result.issues.push(
                "CMSAlgorithmProtection attribute not found (recommended by RFC 8933)"
            );
            if (options.strict) {
                result.compliant = false;
            }
        }
    }

    // Overall compliance assessment
    result.compliant = result.issues.length === 0;

    return result;
}

/**
 * Detects digest-algorithm contradictions between SignerInfo and the optional
 * CMSAlgorithmProtection attribute (RFC 6211).
 *
 * This is deliberately narrower than RFC 8933 Section 3 ("the same digest
 * algorithm MUST be used to compute the digest of the encapContentInfo
 * eContent OCTET STRING and the message-digest attribute"): proving that
 * requires the original content plus async hashing, which this synchronous
 * report-level helper does not have. What it does check is real: when the
 * protection attribute is present, its repeated digest algorithm must equal
 * the SignerInfo digest algorithm. Absence of the (optional) attribute is
 * no contradicting evidence, so it yields true.
 *
 * @param signerInfo - The SignerInfo to validate
 * @returns False only on a detected contradiction or undecodable input
 */
function validateDigestAlgorithmConsistency(signerInfo: pkijs.SignerInfo): boolean {
    try {
        const signerDigestAlgorithm = signerInfo.digestAlgorithm.algorithmId;
        if (!signerDigestAlgorithm) {
            return false; // Cannot determine algorithm
        }
        if (!signerInfo.signedAttrs) {
            return true; // No signed attributes, nothing to compare
        }

        const signedAttrs =
            (signerInfo.signedAttrs as unknown as { attributes?: pkijs.Attribute[] }).attributes ??
            signerInfo.signedAttrs;
        if (!Array.isArray(signedAttrs)) {
            return true;
        }
        const protection = signedAttrs.find(
            (attr) => attr.type === RFC8933_CONSTANTS.CMS_ALGORITHM_PROTECT_OID
        );
        if (protection === undefined || protection.values.length === 0) {
            return true; // Optional attribute absent: no contradicting evidence
        }
        // CMSAlgorithmProtection ::= SEQUENCE { digestAlgorithm, signatureAlgorithm }
        const outer: unknown = protection.values[0];
        if (!(outer instanceof asn1js.Sequence)) {
            return false;
        }
        const inner = outer.valueBlock.value[0];
        if (!(inner instanceof asn1js.Sequence)) {
            return false;
        }
        const oidBlock = inner.valueBlock.value[0];
        if (!(oidBlock instanceof asn1js.ObjectIdentifier)) {
            return false;
        }
        return oidBlock.valueBlock.toString() === signerDigestAlgorithm;
    } catch {
        return false;
    }
}

/**
 * Checks if the CMSAlgorithmProtection attribute is present.
 *
 * @param signerInfo - The SignerInfo to check
 * @returns True if CMSAlgorithmProtection attribute is found
 */
function hasAlgorithmProtectionAttribute(signerInfo: pkijs.SignerInfo): boolean {
    try {
        if (!signerInfo.signedAttrs) {
            return false;
        }

        // RFC 6211 OID for cmsAlgorithmProtect
        const CMS_ALGORITHM_PROTECT_OID = "1.2.840.113549.1.9.52";

        // Type-safe attribute access
        const signedAttrs =
            (signerInfo.signedAttrs as unknown as { attributes?: pkijs.Attribute[] }).attributes ??
            signerInfo.signedAttrs;
        if (!Array.isArray(signedAttrs)) {
            return false;
        }

        return signedAttrs.some((attr) => attr.type === CMS_ALGORITHM_PROTECT_OID);
    } catch {
        return false;
    }
}

/**
 * Validates RFC 8933 compliance for a timestamp token.
 *
 * @param timestampToken - DER-encoded timestamp token
 * @param options - Validation options
 * @returns RFC 8933 compliance validation result
 */
export function validateTimestampTokenRFC8933Compliance(
    timestampToken: Uint8Array,
    options: {
        requireAlgorithmProtection?: boolean;
        strict?: boolean;
    } = {}
): RFC8933ValidationResult {
    try {
        // Parse the timestamp token to get SignedData
        const asn1 = asn1js.fromBER(toArrayBuffer(timestampToken));
        if (asn1.offset === -1) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Failed to parse timestamp token"
            );
        }

        const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
        const signedData = new pkijs.SignedData({
            schema: contentInfo.content,
        });

        return validateRFC8933Compliance(signedData, options);
    } catch (error) {
        return {
            compliant: false,
            issues: [
                `Failed to parse timestamp token: ${error instanceof Error ? error.message : String(error)}`,
            ],
            digestAlgorithmConsistency: false,
            hasAlgorithmProtection: false,
        };
    }
}

/**
 * Result of RFC 8933 compliance validation
 */
export interface RFC8933ValidationResult {
    /** Overall compliance status */
    compliant: boolean;
    /** List of compliance issues found */
    issues: string[];
    /**
     * No digest-algorithm contradiction detected. True when the optional
     * CMSAlgorithmProtection attribute is absent or repeats the declared
     * digest; this is absence-of-contradiction, not a verified content
     * binding (see validateDigestAlgorithmConsistency).
     */
    digestAlgorithmConsistency: boolean;
    /** Whether CMSAlgorithmProtection attribute is present */
    hasAlgorithmProtection: boolean;
}

/**
 * Constants for RFC 8933 support
 */
export const RFC8933_CONSTANTS = {
    /** RFC 8933 specification URL */
    SPEC_URL: "https://www.rfc-editor.org/rfc/rfc8933.html",
    /** RFC 6211 CMS Algorithm Protection OID */
    CMS_ALGORITHM_PROTECT_OID: "1.2.840.113549.1.9.52",
} as const;
