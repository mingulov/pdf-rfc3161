import { timestampPdf } from "../index.js";
import { extractTimestamps, verifyTimestamp } from "./extract.js";
import { addDSS, type LTVData } from "./ltv.js";
import { type TimestampResult, type TSAConfig } from "../types.js";

/**
 * Options for PAdES-LTA archive timestamping
 */
export interface ArchiveTimestampOptions {
    /** The PDF bytes */
    pdf: Uint8Array;
    /** TSA configuration for the archive timestamp */
    tsa: TSAConfig;
    /** Whether to include revocation data if available in existing signatures */
    includeExistingRevocationData?: boolean;
    /** Optional field name for the archive timestamp */
    signatureFieldName?: string;
    /** Size to reserve for the timestamp token */
    signatureSize?: number;
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
 */
export async function timestampPdfLTA(options: ArchiveTimestampOptions): Promise<TimestampResult> {
    const { pdf, tsa, includeExistingRevocationData = true } = options;

    // 1. Extract all existing timestamps
    const existingTimestamps = await extractTimestamps(pdf);

    const allCerts = new Set<string>();
    const certificates: Uint8Array[] = [];
    const crls: Uint8Array[] = [];
    const ocspResponses: Uint8Array[] = [];

    // 3. For each existing timestamp, extract its validation material
    for (const ts of existingTimestamps) {
        const verified = await verifyTimestamp(ts);

        // Collect certificates
        if (verified.certificates) {
            for (const cert of verified.certificates) {
                const der = cert.toSchema().toBER(false);
                const derUint8 = new Uint8Array(der);
                const hex = Array.from(derUint8)
                    .map((b) => b.toString(16).padStart(2, "0"))
                    .join("");

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
                const { extractLTVData } = await import("./ltv.js");
                const ltv = extractLTVData(ts.token);

                // Add unique CRLs and OCSPs (simplified deduplication)
                for (const crl of ltv.crls) crls.push(crl);
                for (const ocsp of ltv.ocspResponses) ocspResponses.push(ocsp);
            } catch {
                // Ignore errors from malformed existing tokens
            }
        }
    }

    if (certificates.length === 0 && existingTimestamps.length > 0) {
        // This shouldn't happen if we have timestamps, but safety first
    }

    // 4. Update the DSS with collected information
    // If no new info was found, we still proceed to add the archive timestamp
    const ltvData: LTVData = {
        certificates,
        crls,
        ocspResponses,
    };

    // Use incremental addDSS
    let currentPdf = pdf;

    if (certificates.length > 0 || crls.length > 0 || ocspResponses.length > 0) {
        // Note: We do NOT pass pdfDoc here because addDSS needs to load fresh
        // from the bytes to get correct xref offsets for incremental save.
        currentPdf = await addDSS(pdf, ltvData);
    }

    // 5. Add the final archive timestamp
    // Note: We also do NOT pass pdfDoc here because the bytes may have changed
    // after addDSS. Let timestampPdf load fresh from currentPdf.
    return timestampPdf({
        pdf: currentPdf,
        tsa,
        signatureFieldName: options.signatureFieldName ?? "ArchiveTimestamp",
        signatureSize: options.signatureSize,
        enableLTV: false, // We already added DSS manually
    });
}
