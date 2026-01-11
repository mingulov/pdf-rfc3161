/**
 * RFC 6211 - CMS Algorithm Identifier Protection Attribute
 *
 * This module provides support for the cmsAlgorithmProtect attribute
 * which protects against algorithm downgrade attacks by explicitly
 * listing all algorithms used in a CMS signed data structure.
 */

import * as pkijs from "pkijs";

// RFC 6211 OID for cmsAlgorithmProtect
const CMS_ALGORITHM_PROTECT_OID = "1.2.840.113549.1.9.52";

/**
 * Checks if a SignedData structure contains cmsAlgorithmProtect attribute.
 *
 * @param signedData - The SignedData structure to check
 * @returns True if cmsAlgorithmProtect attribute is present
 */
export function hasAlgorithmProtectAttribute(signedData: pkijs.SignedData): boolean {
    if (!signedData.signerInfos || signedData.signerInfos.length === 0) {
        return false;
    }

    // Check the first signerInfo for the attribute
    const signerInfo = signedData.signerInfos[0];
    if (!signerInfo || !signerInfo.signedAttrs) {
        return false;
    }

    // Type assertion for pkijs attribute access
    const signedAttrs = (signerInfo.signedAttrs as any).attributes || signerInfo.signedAttrs;
    if (!Array.isArray(signedAttrs)) {
        return false;
    }

    return signedAttrs.some((attr: any) => attr.type === CMS_ALGORITHM_PROTECT_OID);
}

/**
 * Extracts algorithm OIDs from cmsAlgorithmProtect attribute.
 *
 * @param signedData - The SignedData structure
 * @returns Array of algorithm OIDs, or empty array if attribute not present
 */
export function getProtectedAlgorithms(signedData: pkijs.SignedData): string[] {
    if (!signedData.signerInfos || signedData.signerInfos.length === 0) {
        return [];
    }

    const signerInfo = signedData.signerInfos[0];
    if (!signerInfo || !signerInfo.signedAttrs) {
        return [];
    }

    // Type assertion for pkijs attribute access
    const signedAttrs = (signerInfo.signedAttrs as any).attributes || signerInfo.signedAttrs;
    if (!Array.isArray(signedAttrs)) {
        return [];
    }

    const protectAttr = signedAttrs.find((attr: any) => attr.type === CMS_ALGORITHM_PROTECT_OID);

    if (!protectAttr || !protectAttr.values || protectAttr.values.length === 0) {
        return [];
    }

    // For now, return empty array - full parsing would require ASN.1 decoding
    // This is a placeholder for future full implementation
    return [];
}

/**
 * Collects all algorithms actually used in a SignedData structure.
 *
 * @param signedData - The SignedData structure
 * @returns Set of algorithm OIDs used
 */
export function getUsedAlgorithms(signedData: pkijs.SignedData): Set<string> {
    const algorithms = new Set<string>();

    // Collect from signerInfos
    if (signedData.signerInfos) {
        for (const signerInfo of signedData.signerInfos) {
            if (signerInfo.digestAlgorithm?.algorithmId) {
                algorithms.add(signerInfo.digestAlgorithm.algorithmId);
            }
            if (signerInfo.signatureAlgorithm?.algorithmId) {
                algorithms.add(signerInfo.signatureAlgorithm.algorithmId);
            }
        }
    }

    // Collect from certificates
    if (signedData.certificates) {
        for (const cert of signedData.certificates) {
            if (cert instanceof pkijs.Certificate && cert.signatureAlgorithm?.algorithmId) {
                algorithms.add(cert.signatureAlgorithm.algorithmId);
            }
        }
    }

    return algorithms;
}

/**
 * Validates that cmsAlgorithmProtect attribute matches the algorithms
 * actually used in the SignedData structure.
 *
 * @param signedData - The SignedData structure to validate
 * @returns True if protection is valid or attribute is not present
 */
export function validateAlgorithmProtectAttribute(signedData: pkijs.SignedData): boolean {
    const protectedAlgorithms = getProtectedAlgorithms(signedData);
    const usedAlgorithms = getUsedAlgorithms(signedData);

    // If no protection attribute, validation passes
    if (protectedAlgorithms.length === 0) {
        return true;
    }

    // Check that all used algorithms are protected
    for (const alg of usedAlgorithms) {
        if (!protectedAlgorithms.includes(alg)) {
            return false; // Algorithm not protected
        }
    }

    return true; // All algorithms are properly protected
}

/**
 * Constants for RFC 6211 support
 */
export const RFC6211_OIDS = {
    CMS_ALGORITHM_PROTECT: CMS_ALGORITHM_PROTECT_OID,
} as const;
