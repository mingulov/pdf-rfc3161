import { timestampPdf } from "../index.js";
import { extractTimestamps, verifyTimestamp } from "./extract.js";
import { addDSS, addVRI, extractLTVData, completeLTVData, type LTVData } from "./ltv.js";
import {
    TimestampError,
    TimestampErrorCode,
    type TimestampOptions,
    type TimestampResult,
    type VerificationOptions,
} from "../types.js";
import { getLogger } from "../utils/logger.js";
import { bytesToHex } from "../utils.js";

/**
 * Options for PAdES-LTA archive timestamping. Inherits every option from
 * {@link TimestampOptions} and adds archive-specific knobs.
 */
export interface ArchiveTimestampOptions extends TimestampOptions {
    /** Whether to include revocation data if available in existing signatures */
    includeExistingRevocationData?: boolean;
    /**
     * When true, fail the archive if any existing timestamp in the input PDF
     * fails verification (e.g. its TSA cert lacks `id-kp-timeStamping` EKU
     * since the 0.2.0 G1/G2 default flip).
     *
     * Default `false`: failed verifications are logged via getLogger().warn
     * but their cert / revocation material is still collected into the new
     * DSS. This preserves backward-compatible archive behaviour.
     *
     * Set `true` to refuse archiving a chain of trust that does not currently
     * verify. See audit H1.
     */
    strictExistingVerification?: boolean;

    /**
     * Verification options forwarded to `verifyTimestamp` for each existing
     * in-PDF timestamp during the archive's verify-and-collect loop. The
     * archive automatically passes the input `pdf` bytes so the
     * document-hash check runs; this option lets the caller add a
     * `trustStore`, opt out of G1/G2 strictness for legacy tokens, etc.
     *
     * Without this, the loop would only run the cryptographic-integrity
     * and G1/G2 checks (default-true since 0.2.0), missing:
     *   - document-hash mismatch (a tampered PDF whose timestamp signs an
     *     earlier revision still verifies cryptographically)
     *   - chain-of-trust validation against your roots
     *
     * Audit F7.
     */
    existingTimestampVerifyOptions?: VerificationOptions;
}

/**
 * Adds a PAdES-LTA Archive Timestamp to a PDF.
 *
 * This function:
 * 1. Extracts all existing timestamps and their certificates.
 * 2. Collects validation material (certificates, CRLs, OCSPs) from all signatures.
 * 3. Embeds them in a Document Security Store (DSS).
 * 4. Adds a final RFC 3161 timestamp covering the entire document including the DSS.
 *
 * This ensures the document remains verifiable even after the original certificates expire.
 *
 * @example
 * ```typescript
 * const result = await archiveTimestamp({
 *     pdf: existingPdfBytes,
 *     tsa: { url: KNOWN_TSA_URLS.FREETSA },
 * });
 * await writeFile("doc-lta.pdf", result.pdf);
 * ```
 */
export async function archiveTimestamp(options: ArchiveTimestampOptions): Promise<TimestampResult> {
    const {
        pdf,
        tsa,
        includeExistingRevocationData = true,
        strictExistingVerification = false,
        existingTimestampVerifyOptions,
    } = options;

    // 1. Extract all existing timestamps
    const existingTimestamps = await extractTimestamps(pdf, {
        ignoreEncryption: options.ignoreEncryption,
    });

    // 2. Verify all existing timestamps concurrently.
    //
    // Audit F7: always forward `pdf` so the document-hash check runs --
    // without it, a token signing an earlier revision of a tampered PDF
    // still reports `verified: true`, undermining the H1 surfacing. The
    // caller's `existingTimestampVerifyOptions` (trustStore, opt-outs)
    // override / augment as needed.
    const verifyOpts: VerificationOptions = {
        ...existingTimestampVerifyOptions,
        pdf,
    };
    const verifiedTimestamps = await Promise.all(
        existingTimestamps.map((ts) => verifyTimestamp(ts, verifyOpts))
    );

    const allCerts = new Set<string>();
    const certificates: Uint8Array[] = [];
    const crls: Uint8Array[] = [];
    const ocspResponses: Uint8Array[] = [];

    // 3. For each existing timestamp, extract its validation material.
    //
    // Audit H1: with the 0.2.0 G1/G2 default flips, legacy timestamps without
    // the id-kp-timeStamping EKU (or with a TSA cert that was expired by
    // signing time) now fail verification. Previously this loop silently
    // collected their material anyway, producing a misleadingly-"successful"
    // archive with a broken chain of trust. We now surface the failure: warn
    // by default, throw if strictExistingVerification is set.
    for (const verified of verifiedTimestamps) {
        if (!verified.verified) {
            const message = `Existing timestamp '${verified.fieldName}' failed verification: ${
                verified.verificationError ?? "no error message"
            }`;
            if (strictExistingVerification) {
                throw new TimestampError(TimestampErrorCode.VERIFICATION_FAILED, message);
            }
            getLogger().warn(message);
        }

        // Collect certificates
        if (verified.certificates) {
            for (const cert of verified.certificates) {
                const der = cert.toSchema().toBER(false);
                const derUint8 = new Uint8Array(der);
                const hex = bytesToHex(derUint8);

                if (!allCerts.has(hex)) {
                    allCerts.add(hex);
                    certificates.push(derUint8);
                }
            }
        }

        // Collect revocation data from the token if requested
        if (includeExistingRevocationData) {
            // Note: extractLTVData in ltv.ts handles this extraction from a token
            try {
                const ltv = extractLTVData(verified.token);

                // Add unique CRLs and OCSPs (simplified deduplication)
                for (const crl of ltv.crls) crls.push(crl);
                for (const ocsp of ltv.ocspResponses) ocspResponses.push(ocsp);
            } catch {
                // Skip malformed existing tokens
            }
        }
    }

    // 4. Update the DSS with collected information
    // If no new info was found, we still proceed to add the archive timestamp
    const ltvData: LTVData = {
        certificates,
        crls,
        ocspResponses,
    };

    // 4. Update the DSS with collected information
    // Fetch missing revocation data (best effort)
    let completeData = ltvData;
    const ltvResult = await completeLTVData(ltvData);
    completeData = ltvResult.data;

    // Log any errors encountered during LTV enrichment (for debugging)
    if (ltvResult.errors.length > 0) {
        const logger = getLogger();
        logger.warn("Warnings during LTV data completion:");
        for (const error of ltvResult.errors) {
            logger.warn(`  - ${error}`);
        }
    }

    // If no new info was found, we still proceed to add the archive timestamp

    // Use incremental addDSS
    let currentPdf = pdf;

    if (certificates.length > 0 || crls.length > 0 || ocspResponses.length > 0) {
        // Note: We do NOT pass pdfDoc here because addDSS needs to load fresh
        // from the bytes to get correct xref offsets for incremental save.
        currentPdf = await addDSS(pdf, completeData);
    }

    // 4.5 Add VRI entries for each signature
    // VRI associates validation material with specific signing certificates
    for (const verified of verifiedTimestamps) {
        try {
            if (verified.certificates && verified.certificates.length > 0) {
                // Use the first certificate as the signing certificate
                const signingCert = verified.certificates[0];
                if (!signingCert) continue;

                // Collect revocation data for this signature
                const revocationData: { crls?: Uint8Array[]; ocspResponses?: Uint8Array[] } = {};

                // Extract revocation data from this timestamp's token
                const ltv = extractLTVData(verified.token);
                if (ltv.crls.length > 0) {
                    revocationData.crls = ltv.crls;
                }
                if (ltv.ocspResponses.length > 0) {
                    revocationData.ocspResponses = ltv.ocspResponses;
                }

                // Add VRI entry for this signature
                if (Object.keys(revocationData).length > 0) {
                    currentPdf = await addVRI(currentPdf, signingCert, revocationData);
                }
            }
        } catch {
            // Skip VRI for malformed signatures
        }
    }

    // 5. Add the final archive timestamp
    // Note: We also do NOT pass pdfDoc here because the bytes may have changed
    // after addDSS. Let timestampPdf load fresh from currentPdf.
    //
    // Audit M9: `ArchiveTimestampOptions extends TimestampOptions`, so every
    // `TimestampOptions` field is accepted by the type. Previously only 5
    // were forwarded and the rest were silently dropped. We now forward
    // every applicable field. Two carve-outs:
    //   - `enableLTV` is force-overridden to `false`: archive owns the LTV
    //     pipeline (it builds the DSS above). If the caller explicitly set
    //     `enableLTV: true`, warn so they understand it's ignored.
    //   - `revocationData` is dropped: archive collects revocation material
    //     from existing in-PDF signatures rather than from caller-supplied
    //     pre-fetched data. Mixing the two would be confusing.
    if (options.enableLTV === true) {
        getLogger().warn(
            "archiveTimestamp: `enableLTV: true` is ignored; archive manages LTV internally."
        );
    }
    return timestampPdf({
        pdf: currentPdf,
        tsa,
        signatureFieldName: options.signatureFieldName ?? "ArchiveTimestamp",
        signatureSize: options.signatureSize,
        ignoreEncryption: options.ignoreEncryption,
        reason: options.reason,
        location: options.location,
        contactInfo: options.contactInfo,
        omitModificationTime: options.omitModificationTime,
        maxSize: options.maxSize,
        optimizePlaceholder: options.optimizePlaceholder,
        rejectOnRevocationWarning: options.rejectOnRevocationWarning,
        enableLTV: false, // see note above
    });
}

/**
 * @deprecated Renamed to {@link archiveTimestamp} in 0.2.0. The old name
 * remains available as an alias and will be removed in a future major.
 */
export const timestampPdfLTA = archiveTimestamp;
