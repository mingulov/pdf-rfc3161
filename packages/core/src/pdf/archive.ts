import { timestampPdf } from "../index.js";
import {
    discoverArchiveTimestamps,
    verifyTimestampsWithSharedIndex,
    type ExtractedTimestamp,
} from "./extract.js";
import { addDSS, extractLTVData, completeLTVData, type LTVData } from "./ltv.js";
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
 * Options for RFC 3161 document-timestamp renewal. Inherits every option from
 * {@link TimestampOptions} and adds renewal-specific controls.
 */
export interface ArchiveTimestampOptions extends TimestampOptions {
    /** Whether to collect candidate revocation material from verified existing document timestamps. */
    includeExistingRevocationData?: boolean;
    /**
     * When true, fail the archive if any existing timestamp in the input PDF
     * fails verification (e.g. its TSA cert lacks `id-kp-timeStamping` EKU
     * since the 0.2.0 G1/G2 default flip).
     *
     * Default `false`: failed verifications are logged via getLogger().warn
     * and contribute no certificate, OCSP, or CRL material to the new DSS.
     *
     * Set `true` to stop renewal when a recognized timestamp is malformed or
     * fails verification. The archive always supplies the input PDF, so its
     * ByteRange hash is checked; caller-supplied verification options control
     * the trust policy used for the remaining verification checks.
     */
    strictExistingVerification?: boolean;

    /**
     * Verification options forwarded to the shared timestamp verifier for
     * existing in-PDF values during the archive's verify-and-collect loop.
     * The archive automatically passes the input `pdf` bytes so the
     * document-hash check runs. This option lets the caller provide a
     * `trustStore`, opt out of G1/G2 strictness for legacy tokens, or set
     * other verification behavior.
     *
     * The archive always verifies the document hash because it forwards
     * `pdf`. Optional caller settings determine trust-policy and certificate
     * path checks in addition to the default cryptographic-integrity and
     * G1/G2 checks.
     *
     * Audit F7.
     */
    existingTimestampVerifyOptions?: VerificationOptions;

    /**
     * Caller-supplied raw validation material to merge into the global DSS.
     * It is embedded as caller-responsible candidate material; this renewal
     * operation does not cryptographically validate it.
     */
    revocationData?: TimestampOptions["revocationData"];
}

function signatureValueKey(timestamp: ExtractedTimestamp): string | undefined {
    if (timestamp.contentsObject === undefined) return undefined;
    const [offset1, length1, offset2, length2] = timestamp.byteRange;
    return [
        timestamp.contentsObject.objectNumber,
        timestamp.contentsObject.generationNumber,
        timestamp.contentsDirectValue ? "direct" : "indirect",
        offset1,
        length1,
        offset2,
        length2,
    ].join(":");
}

/**
 * Renews RFC 3161 document timestamps in a PDF.
 *
 * This function:
 * 1. Extracts and verifies recognized existing document timestamps.
 * 2. Collects candidate validation material only from timestamps that verify.
 * 3. Additively merges that aggregate material into the global DSS once.
 * 4. Adds a final RFC 3161 document timestamp covering the DSS revision.
 *
 * This is not a general approval-signature validator, a PAdES-LTA upgrader,
 * or a guarantee of indefinite validity. VRI remains opt-in through
 * {@link addVRIForSignature}; renewal never creates or imports VRI entries.
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
    const discovery = await discoverArchiveTimestamps(pdf, {
        ignoreEncryption: options.ignoreEncryption,
    });
    for (const fieldName of discovery.malformedFieldNames) {
        const message = `Existing RFC 3161 document timestamp '${fieldName}' is malformed and cannot be verified`;
        if (strictExistingVerification) {
            throw new TimestampError(TimestampErrorCode.VERIFICATION_FAILED, message);
        }
        getLogger().warn(message);
    }
    const existingTimestamps = discovery.timestamps;

    // 2. Verify existing values in field order. Strict discovery supplies its
    // scanner, so renewal neither reparses the PDF nor falls back to public
    // permissive discovery. Shared /V values are verified once, sequentially.
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
    const verifiedTimestamps = await verifyTimestampsWithSharedIndex(
        existingTimestamps,
        verifyOpts,
        discovery.occurrenceIndex
    );

    const allCerts = new Set<string>();
    const certificates = [...(options.revocationData?.certificates ?? [])];
    const crls = [...(options.revocationData?.crls ?? [])];
    const ocspResponses = [...(options.revocationData?.ocspResponses ?? [])];

    for (const certificate of certificates) {
        allCerts.add(bytesToHex(certificate));
    }

    // 3. For each existing timestamp, extract its validation material.
    //
    // A failed token never supplies validation material. It might be malformed,
    // bind an earlier document revision, or use a different signer than its
    // certificate set suggests.
    const collectedSignatureValues = new Set<string>();
    for (const verified of verifiedTimestamps) {
        if (!verified.verified) {
            const message = `Existing timestamp '${verified.fieldName}' failed verification: ${
                verified.verificationError ?? "no error message"
            }`;
            if (strictExistingVerification) {
                throw new TimestampError(TimestampErrorCode.VERIFICATION_FAILED, message);
            }
            getLogger().warn(message);
            continue;
        }

        // Multiple fields may inherit one valid selected /V. Its CMS token,
        // certificates, and embedded revocation data are identical, so avoid
        // repeated parsing and DER conversion while retaining per-field
        // warning/error behavior above.
        const valueKey = signatureValueKey(verified);
        if (valueKey !== undefined) {
            if (collectedSignatureValues.has(valueKey)) continue;
            collectedSignatureValues.add(valueKey);
        }

        // Verification selects the signer by CMS SID. Archive renewal does not
        // need to select a signer itself, so retain every embedded certificate
        // candidate from a successfully verified token rather than relying on
        // certificates[0].
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

        // This token already passed strict timestamp verification. Any token
        // parsing failure here is therefore a contradictory PDF state and is
        // surfaced instead of silently falling through a broad catch.
        if (includeExistingRevocationData) {
            const ltv = extractLTVData(verified.token);
            for (const crl of ltv.crls) crls.push(crl);
            for (const ocsp of ltv.ocspResponses) ocspResponses.push(ocsp);
        }
    }

    const ltvData: LTVData = {
        certificates,
        crls,
        ocspResponses,
    };

    // Fetch structural candidate material for verified-token certificates.
    const ltvResult = await completeLTVData(ltvData);
    const completeData = ltvResult.data;

    // Collection errors do not turn fetched or caller-provided bytes into
    // cryptographically validated revocation evidence.
    if (ltvResult.errors.length > 0) {
        const logger = getLogger();
        logger.warn("Warnings during validation-material collection:");
        for (const error of ltvResult.errors) {
            logger.warn(`  - ${error}`);
        }
    }

    // Always append exactly one additive global DSS revision. This preserves
    // existing DSS/VRI/unknown entries even when renewal adds no new bytes.
    const currentPdf = await addDSS(pdf, completeData, {
        ignoreEncryption: options.ignoreEncryption,
    });

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
    //   - `revocationData` has already been merged as caller-responsible raw
    //     candidate material in the archive-owned aggregate DSS update.
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
        // eslint-disable-next-line @typescript-eslint/no-deprecated -- forwarded for source compatibility
        rejectOnRevocationWarning: options.rejectOnRevocationWarning,
        enableLTV: false, // see note above
    });
}

/**
 * @deprecated Historical alias for {@link archiveTimestamp}. It remains
 * source-compatible but does not promise PAdES-LTA conformance or indefinite
 * validity; use archiveTimestamp for RFC 3161 document-timestamp renewal.
 */
export const timestampPdfLTA = archiveTimestamp;
