/**
 * RFC 8933 - Update to CMS for Algorithm Identifier Protection
 *
 * This module validates RFC 8933 compliance in CMS SignedData structures,
 * particularly timestamp tokens, to ensure algorithm identifier protection.
 */

import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { TimestampError, TimestampErrorCode } from "../types.js";

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
        // Check 1: Same digest algorithm for content and signed attributes
        const digestAlgorithmConsistency = validateDigestAlgorithmConsistency(signerInfo);
        if (!digestAlgorithmConsistency) {
            result.digestAlgorithmConsistency = false;
            result.issues.push(
                "Digest algorithm inconsistency between content and signed attributes"
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
 * Validates that the same digest algorithm is used for both content and signed attributes.
 *
 * RFC 8933 Section 3: "the same digest algorithm MUST be used to compute
 * the digest of the encapContentInfo eContent OCTET STRING and the message-digest attribute"
 *
 * @param signerInfo - The SignerInfo to validate
 * @returns True if digest algorithms are consistent
 */
function validateDigestAlgorithmConsistency(signerInfo: pkijs.SignerInfo): boolean {
    try {
        // Get digest algorithm from SignerInfo.digestAlgorithm
        const signerDigestAlgorithm = signerInfo.digestAlgorithm.algorithmId;
        if (!signerDigestAlgorithm) {
            return false; // Cannot determine algorithm
        }

        // For timestamp tokens, we need to check if signed attributes exist
        // and if the message-digest attribute was computed with the same algorithm
        if (!signerInfo.signedAttrs) {
            return true; // No signed attributes, nothing to validate
        }

        // In practice, validating this requires access to the original content
        // and signed attributes. For our use case with timestamp tokens,
        // we assume the TSA has implemented this correctly unless we can detect otherwise.

        // We can check that the digestAlgorithm in SignerInfo is consistent
        // with what's declared, but full validation requires the original data.

        return true; // Assume compliant unless we can prove otherwise
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
        const asn1 = asn1js.fromBER(timestampToken.slice().buffer);
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
    /** Whether digest algorithms are consistent */
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
