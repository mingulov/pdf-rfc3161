import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import {
    PDFDocument,
    PDFName,
    PDFArray,
    PDFRef,
    PDFDict,
} from "pdf-lib-incremental-save";
import { TimestampError, TimestampErrorCode, type ExtractOptions } from "../types.js";
import {
    getOCSPURI,
    createOCSPRequest,
    parseOCSPResponse,
    CertificateStatus,
} from "../pki/ocsp-utils.js";
import { fetchOCSPResponse } from "../pki/ocsp-client.js";
import { getCRLDistributionPoints } from "../pki/crl-utils.js";
import { fetchCRL } from "../pki/crl-client.js";
import { getCaIssuers, findIssuer } from "../pki/cert-utils.js";
import { parseCanonicalDERSequenceTree, requireSchemaRoundTrip } from "../pki/der-utils.js";
import { fetchCertificate } from "../pki/cert-client.js";
import { toArrayBuffer, bytesToHex } from "../utils.js";
import { getLogger } from "../utils/logger.js";
import { updateValidationStore } from "./validation-store.js";

/**
 * LTV (Long-Term Validation) data extracted from a timestamp token
 */
export interface LTVData {
    /** DER-encoded certificate candidate material from the timestamp token or caller. */
    certificates: Uint8Array[];
    /** DER-encoded CRL candidate material; caller-supplied bytes are caller-responsible. */
    crls: Uint8Array[];
    /** DER-encoded OCSP candidate material; caller-supplied bytes are caller-responsible. */
    ocspResponses: Uint8Array[];
}

/**
 * Settings for LTV data completion, allowing custom network fetchers.
 */
export interface LTVSettings {
    fetchers?: {
        certFetcher?: (url: string) => Promise<Uint8Array>;
        ocspFetcher?: (url: string, request: Uint8Array) => Promise<Uint8Array>;
        crlFetcher?: (url: string) => Promise<Uint8Array>;
    };
}

function parseCompleteCrlCandidate(crlBytes: Uint8Array): pkijs.CertificateRevocationList {
    const asn1 = parseCanonicalDERSequenceTree(crlBytes, "CRL candidate");
    if (!(asn1 instanceof asn1js.Sequence)) {
        throw new TimestampError(TimestampErrorCode.INVALID_RESPONSE, "CRL candidate must be a SEQUENCE");
    }

    const children = asn1.valueBlock.value;
    if (
        children.length !== 3 ||
        !(children[0] instanceof asn1js.Sequence) ||
        !(children[1] instanceof asn1js.Sequence) ||
        !(children[2] instanceof asn1js.BitString)
    ) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "CRL candidate must contain TBSCertList, AlgorithmIdentifier, and BIT STRING only"
        );
    }

    const crl = new pkijs.CertificateRevocationList({ schema: asn1 });
    const crlSchema = crl.toSchema(true) as asn1js.Sequence;
    requireSchemaRoundTrip(crlBytes, crlSchema.toBER(false), "CRL candidate");
    return crl;
}

/**
 * Extracts LTV validation data from a timestamp token.
 * This includes certificates from the SignedData structure.
 *
 * @param timestampToken - The DER-encoded timestamp token (ContentInfo)
 * @returns LTV data containing certificates and revocation info
 *
 * @example
 * ```typescript
 * const ltv = extractLTVData(timestamp.token);
 * console.log(`Certs: ${ltv.certificates.length}, CRLs: ${ltv.crls.length}`);
 * ```
 */
export function extractLTVData(timestampToken: Uint8Array): LTVData {
    try {
        // Parse the ContentInfo
        const asn1 = asn1js.fromBER(toArrayBuffer(timestampToken));
        if (asn1.offset === -1) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Failed to parse timestamp token ASN.1"
            );
        }

        const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
        const signedData = new pkijs.SignedData({ schema: contentInfo.content });

        const certificates: Uint8Array[] = [];
        const crls: Uint8Array[] = [];
        const ocspResponses: Uint8Array[] = [];

        // Extract certificates
        if (signedData.certificates) {
            for (const cert of signedData.certificates) {
                if (cert instanceof pkijs.Certificate) {
                    const certDer = cert.toSchema().toBER(false);
                    certificates.push(new Uint8Array(certDer));
                }
            }
        }

        // Extract CRLs if present
        if (signedData.crls) {
            for (const crl of signedData.crls) {
                if (crl instanceof pkijs.CertificateRevocationList) {
                    const crlAsn1 = crl.toSchema() as asn1js.Sequence;
                    const crlDer = crlAsn1.toBER(false);
                    crls.push(new Uint8Array(crlDer));
                }
            }
        }

        return {
            certificates,
            crls,
            ocspResponses,
        };
    } catch (error) {
        if (error instanceof TimestampError) {
            throw error;
        }
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            `Failed to extract LTV data: ${error instanceof Error ? error.message : String(error)}`,
            error
        );
    }
}

/**
 * Adds a Document Security Store (DSS) to a PDF for LTV enablement.
 * The DSS contains certificate and revocation candidate material for a
 * caller or validator to evaluate under its own trust policy. Embedding it
 * does not validate the material or guarantee validity after certificate expiry.
 *
 * Uses incremental save to append DSS without rewriting the existing
 * document structure, which would invalidate any existing signatures.
 *
 * @param pdfBytes - The PDF bytes (should already contain a timestamp)
 * @param ltvData - LTV validation data to embed
 * @param options - Additional options for PDF loading
 * @returns PDF bytes with DSS added incrementally
 *
 * @example
 * ```typescript
 * const pdfWithDss = await addDSS(timestampedPdf, {
 *     certificates: [issuerDer, rootDer],
 *     crls: [crlBytes],
 *     ocspResponses: [],
 * });
 * ```
 */
export async function addDSS(
    pdfBytes: Uint8Array,
    ltvData: LTVData,
    options?: ExtractOptions
): Promise<Uint8Array> {
    return updateValidationStore(pdfBytes, { validationData: ltvData }, options);
}

/** Options for adding VRI validation data for one signature field. */
export interface AddVRIForSignatureOptions extends ExtractOptions {
    validationData: LTVData;
}

/**
 * Adds validation data to a VRI entry bound to one PDF signature field.
 * The VRI key is derived from the complete decoded, padded /Contents bytes.
 */
export async function addVRIForSignature(
    pdfBytes: Uint8Array,
    signature: { fieldName: string },
    options: AddVRIForSignatureOptions
): Promise<Uint8Array> {
    return updateValidationStore(
        pdfBytes,
        { vri: { fieldName: signature.fieldName, validationData: options.validationData } },
        options
    );
}

export interface DeprecatedVRIOptions extends ExtractOptions {
    signatureFieldName?: string;
    hashAlgorithm?: "SHA-1" | "SHA-256";
    dssCertRefs?: PDFRef[];
    dssCrlRefs?: PDFRef[];
    dssOcspRefs?: PDFRef[];
    timestampRef?: PDFRef;
}

export interface AddVRIEnhancedOptions extends DeprecatedVRIOptions {
    revocationData?: { crls?: Uint8Array[]; ocspResponses?: Uint8Array[] };
}

function validateLegacyVriOptions(options: DeprecatedVRIOptions): string {
    if (options.signatureFieldName === undefined || options.signatureFieldName.length === 0) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_ARGUMENT,
            "addVRI requires signatureFieldName; use addVRIForSignature to bind validation data to a PDF signature"
        );
    }
    if (options.hashAlgorithm !== undefined && options.hashAlgorithm !== "SHA-1") {
        throw new TimestampError(
            TimestampErrorCode.INVALID_ARGUMENT,
            "VRI keys must use SHA-1 over PDF /Contents bytes"
        );
    }
    if (
        options.dssCertRefs !== undefined ||
        options.dssCrlRefs !== undefined ||
        options.dssOcspRefs !== undefined ||
        options.timestampRef !== undefined
    ) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_ARGUMENT,
            "VRI reference options cannot be reused across PDF load contexts; supply raw validation data"
        );
    }
    return options.signatureFieldName;
}

function legacyValidationData(
    signingCert: pkijs.Certificate,
    revocationData?: { crls?: Uint8Array[]; ocspResponses?: Uint8Array[] }
): LTVData {
    return {
        certificates: [new Uint8Array(signingCert.toSchema().toBER(false))],
        crls: revocationData?.crls ?? [],
        ocspResponses: revocationData?.ocspResponses ?? [],
    };
}

/**
 * @deprecated Use {@link addVRIForSignature} with a signature field name and raw validation data.
 */
export async function addVRI(
    pdfBytes: Uint8Array,
    signingCert: pkijs.Certificate,
    revocationData: { crls?: Uint8Array[]; ocspResponses?: Uint8Array[] },
    options: DeprecatedVRIOptions = {}
): Promise<Uint8Array> {
    const signatureFieldName = validateLegacyVriOptions(options);
    return addVRIForSignature(
        pdfBytes,
        { fieldName: signatureFieldName },
        { validationData: legacyValidationData(signingCert, revocationData), ...options }
    );
}

/**
 * @deprecated Use {@link addVRIForSignature} with a signature field name and raw validation data.
 */
export async function addVRIEnhanced(
    pdfBytes: Uint8Array,
    signingCert: pkijs.Certificate,
    options: AddVRIEnhancedOptions = {}
): Promise<Uint8Array> {
    const signatureFieldName = validateLegacyVriOptions(options);
    return addVRIForSignature(
        pdfBytes,
        { fieldName: signatureFieldName },
        { validationData: legacyValidationData(signingCert, options.revocationData), ...options }
    );
}

/**
 * Result of completing LTV data, including any errors encountered
 */
export interface CompletedLTVData {
    /**
     * The enriched candidate material. Network OCSP/CRL bytes are only
     * structurally parsed before collection, not signature/path/freshness or
     * revocation validated. Caller-supplied bytes remain caller responsibility.
     */
    data: LTVData;
    /** Any errors encountered during enrichment (for debugging/monitoring) */
    errors: string[];
}

/**
 * Attempts to fetch structurally valid revocation candidate material for the certificates in LTV data.
 * This is "best effort". It does not authenticate OCSP/CRL bytes, validate their
 * responder/issuer paths, check freshness, or establish a revocation decision.
 *
 * @param ltvData - The extracted LTV data (certs, CRLs)
 * @returns CompletedLTVData with enhanced data and any errors encountered
 */
export async function completeLTVData(
    ltvData: LTVData,
    settings?: LTVSettings
): Promise<CompletedLTVData> {
    const enrichedData: LTVData = {
        certificates: [...ltvData.certificates],
        crls: [...ltvData.crls],
        ocspResponses: [...ltvData.ocspResponses],
    };

    const errors: string[] = [];

    // Deduplication sets to prevent PDF bloat
    const seenCRLs = new Set<string>(enrichedData.crls.map((c) => bytesToHex(c)));
    const seenOCSPs = new Set<string>(enrichedData.ocspResponses.map((o) => bytesToHex(o)));

    try {
        // Parse all certificates to work with them
        const certs: pkijs.Certificate[] = [];
        for (const certBytes of enrichedData.certificates) {
            const asn1 = asn1js.fromBER(toArrayBuffer(certBytes));
            if (asn1.offset !== -1) {
                certs.push(new pkijs.Certificate({ schema: asn1.result }));
            }
        }

        // We need at least 2 certs to have an issuer-subject pair (unless self-signed, which don't have OCSP)
        if (certs.length < 2) {
            // Attempt to build chain via AIA if we only have the leaf
            await buildChainViaAIA(certs, enrichedData, errors, settings);
        } else {
            // Even if we have > 1, we might be missing the root or an intermediate
            // A smarter approach: check if the chain is complete.
            // For now, let's run the AIA builder anyway, it checks for missing issuers.
            await buildChainViaAIA(certs, enrichedData, errors, settings);
        }

        // Pre-index certificates by subject to speed up issuer lookups
        const certsBySubject = new Map<string, pkijs.Certificate[]>();
        for (const cert of certs) {
            const subject = cert.subject.toString();
            const list = certsBySubject.get(subject) ?? [];
            list.push(cert);
            certsBySubject.set(subject, list);
        }

        // Iterate over certs to find their issuers and fetch OCSP
        // We skip the root (last one usually, or self-signed) effectively because we won't find an issuer for it
        // that is *different* (or if we do, root OCSP is rare/uncommon).
        for (const cert of certs) {
            // Find issuer
            const issuer = findIssuer(cert, certsBySubject.get(cert.issuer.toString()) ?? []);

            if (!issuer) {
                // If we can't find the issuer, we can't fetch OCSP (needs issuer hash)
                // We might find it via AIA later, but for now skip
                continue;
            }

            // Avoid using cert as its own issuer for OCSP (unless strictly self-signed root, but OCSP typicaly for end-entity)
            if (issuer.serialNumber.isEqual(cert.serialNumber)) {
                continue;
            }

            // Try OCSP first
            let ocspSuccess = false;
            const ocspUrl = getOCSPURI(cert);
            if (ocspUrl) {
                try {
                    // Generate Request
                    const request = await createOCSPRequest(cert, issuer);

                    // Fetch Response
                    const response = settings?.fetchers?.ocspFetcher
                        ? await settings.fetchers.ocspFetcher(ocspUrl, request)
                        : await fetchOCSPResponse(ocspUrl, request);

                    // Only a complete, successful Basic OCSP response with a
                    // structurally good certificate status is a candidate.
                    // This is deliberately not responder-signature, CertID,
                    // freshness, or revocation-trust validation.
                    try {
                        const parsed = parseOCSPResponse(response);
                        if (parsed.certStatus !== CertificateStatus.GOOD) {
                            errors.push(
                                `Fetched OCSP candidate is structurally valid but certificate status is not good (${CertificateStatus[parsed.certStatus]}); attempting CRL fallback for cert serial: ${bytesToHex((cert.serialNumber as unknown as asn1js.Integer).valueBlock.valueHexView)}`
                            );
                        } else {
                            const ocspHash = bytesToHex(response);
                            if (!seenOCSPs.has(ocspHash)) {
                                seenOCSPs.add(ocspHash);
                                enrichedData.ocspResponses.push(response);
                            }
                            ocspSuccess = true;
                        }
                    } catch (parseError) {
                        errors.push(
                            `Fetched OCSP candidate failed structural parsing; attempting CRL fallback: ${parseError instanceof Error ? parseError.message : String(parseError)}`
                        );
                    }
                } catch (e) {
                    // OCSP fetch failed - log error and continue to CRL
                    errors.push(
                        `Failed to fetch OCSP for certificate (Serial: ${bytesToHex((cert.serialNumber as unknown as asn1js.Integer).valueBlock.valueHexView)}): ${e instanceof Error ? e.message : String(e)}`
                    );
                }
            }

            // If OCSP failed or wasn't available, try CRL
            if (!ocspSuccess) {
                const crlUrls = getCRLDistributionPoints(cert);
                for (const url of crlUrls) {
                    try {
                        const crlBytes = settings?.fetchers?.crlFetcher
                            ? await settings.fetchers.crlFetcher(url)
                            : await fetchCRL(url);

                        parseCompleteCrlCandidate(crlBytes);

                        // Keep structurally parsed CRL bytes as candidate material.
                        const crlHash = bytesToHex(crlBytes);
                        if (!seenCRLs.has(crlHash)) {
                            seenCRLs.add(crlHash);
                            enrichedData.crls.push(crlBytes);
                        }
                        // If we got one CRL, that's usually enough for this cert (ignoring delta CRLs for now)
                        break;
                    } catch (e) {
                        errors.push(
                            `Fetched CRL candidate failed structural parsing or retrieval from ${url}: ${e instanceof Error ? e.message : String(e)}`
                        );
                    }
                }
            }
        }
    } catch (e) {
        // Unexpected error in completeLTVData - log and return partial results
        errors.push(
            `Unexpected error completing LTV data: ${e instanceof Error ? e.message : String(e)}`
        );
    }

    return { data: enrichedData, errors };
}

/**
 * Returns information about the Document Security Store (DSS) in the PDF.
 * This indicates how many LTV validation objects are embedded in the document structure.
 *
 * @param pdfBytes - The PDF bytes
 * @param options - Extraction options
 * @returns Counts of Certs, CRLs, and OCSPs in the DSS
 */
export async function getDSSInfo(
    pdfBytes: Uint8Array,
    options?: ExtractOptions
): Promise<{ certs: number; crls: number; ocsps: number } | null> {
    try {
        const pdfDoc = await PDFDocument.load(pdfBytes, {
            updateMetadata: false,
            ignoreEncryption: options?.ignoreEncryption ?? false,
        });
        const catalog = pdfDoc.catalog;

        const dss = catalog.lookup(PDFName.of("DSS"));
        if (!dss || !(dss instanceof PDFDict)) {
            return null;
        }

        const countArray = (key: string): number => {
            const arr = dss.lookup(PDFName.of(key));
            if (arr instanceof PDFArray) {
                return arr.size();
            }
            return 0;
        };

        return {
            certs: countArray("Certs"),
            crls: countArray("CRLs"),
            ocsps: countArray("OCSPs"),
        };
    } catch {
        return null;
    }
}

/**
 * Helper to recursively build the certificate chain using AIA.
 * Mutates the certs array and enrichedData.
 */
async function buildChainViaAIA(
    certs: pkijs.Certificate[],
    enrichedData: LTVData,
    errors: string[],
    settings?: LTVSettings
): Promise<void> {
    const logger = getLogger();
    let madeProgress = true;
    let depth = 0;
    const MAX_DEPTH = 5;

    // Serial numbers we already have to avoid duplicates
    const seenSerials = new Set<string>(certs.map((c) => c.serialNumber.valueBlock.toString()));

    // Pre-calculate subject map to avoid O(N^2) searches inside the loop
    const subjectMap = new Map<string, pkijs.Certificate>();
    for (const c of certs) {
        subjectMap.set(c.subject.toString(), c);
    }

    while (madeProgress && depth < MAX_DEPTH) {
        madeProgress = false;
        depth++;

        // Copy array to iterate safely while potentially adding to 'certs'
        const currentCerts = [...certs];

        for (const cert of currentCerts) {
            const subjectStr = cert.subject.toString();
            const issuerStr = cert.issuer.toString();

            // If cert.subject == cert.issuer, it's a root (or self-signed leaf), stopping point.
            if (subjectStr === issuerStr) {
                continue;
            }

            // Check if we have the issuer
            const issuer = subjectMap.get(issuerStr);

            if (issuer) {
                continue;
            }

            // Issuer missing, check AIA
            const caIssuersUrls = getCaIssuers(cert);
            if (caIssuersUrls.length === 0) {
                continue;
            }

            // Try to fetch
            for (const url of caIssuersUrls) {
                try {
                    logger.debug(
                        `Fetching missing issuer for ${cert.serialNumber.valueBlock.toString()} from ${url}`
                    );
                    const certBytes = settings?.fetchers?.certFetcher
                        ? await settings.fetchers.certFetcher(url)
                        : await fetchCertificate(url);

                    // Parse to verify it's a cert and get details
                    const asn1 = asn1js.fromBER(toArrayBuffer(certBytes));
                    if (asn1.offset === -1) {
                        continue;
                    }
                    const newCert = new pkijs.Certificate({ schema: asn1.result });
                    const newSerial = newCert.serialNumber.valueBlock.toString();

                    if (!seenSerials.has(newSerial)) {
                        // Found a new cert!
                        logger.info(
                            `Found new intermediate certificate: ${newCert.subject.toString()}`
                        );
                        certs.push(newCert);
                        subjectMap.set(newCert.subject.toString(), newCert);
                        enrichedData.certificates.push(certBytes);
                        seenSerials.add(newSerial);
                        madeProgress = true;
                        break; // Found one valid issuer, move to next cert
                    }
                } catch (e) {
                    const msg = `Failed to fetch CA Issuer from ${url}: ${e instanceof Error ? e.message : String(e)}`;
                    logger.warn(msg);
                    errors.push(msg);
                    // try next URL
                }
            }
        }
    }
}
