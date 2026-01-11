import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import {
    PDFDocument,
    PDFName,
    PDFArray,
    PDFRawStream,
    PDFRef,
    PDFDict,
} from "pdf-lib-incremental-save";
import { TimestampError, TimestampErrorCode } from "../types.js";
import {
    getOCSPURI,
    createOCSPRequest,
    parseOCSPResponse,
    CertificateStatus,
} from "../pki/ocsp-utils.js";
import { fetchOCSPResponse } from "../pki/ocsp-client.js";
import { getCRLDistributionPoints } from "../pki/crl-utils.js";
import { fetchCRL } from "../pki/crl-client.js";
import { bytesToHex } from "../utils.js";

// SHA-1 hash function for VRI key (required by PDF 1.x / PAdES standards)
async function sha1Hex(data: Uint8Array): Promise<string> {
    const hashBuffer = await crypto.subtle.digest("SHA-1", data.slice().buffer);
    const hashArray = new Uint8Array(hashBuffer);
    return bytesToHex(hashArray);
}

// SHA-256 hash function for VRI key (PDF 2.0 extension level 8)
async function sha256Hex(data: Uint8Array): Promise<string> {
    const hashBuffer = await crypto.subtle.digest("SHA-256", data.slice().buffer);
    const hashArray = new Uint8Array(hashBuffer);
    return bytesToHex(hashArray);
}

/**
 * LTV (Long-Term Validation) data extracted from a timestamp token
 */
export interface LTVData {
    /** DER-encoded certificates from the timestamp token */
    certificates: Uint8Array[];
    /** DER-encoded CRLs if available */
    crls: Uint8Array[];
    /** DER-encoded OCSP responses if available */
    ocspResponses: Uint8Array[];
}

/**
 * Extracts LTV validation data from a timestamp token.
 * This includes certificates from the SignedData structure.
 *
 * @param timestampToken - The DER-encoded timestamp token (ContentInfo)
 * @returns LTV data containing certificates and revocation info
 */
export function extractLTVData(timestampToken: Uint8Array): LTVData {
    try {
        // Parse the ContentInfo
        const asn1 = asn1js.fromBER(timestampToken.slice().buffer);
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

        // Note: OCSP responses would typically need to be fetched separately
        // from the certificate's OCSP responder URL

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
 * The DSS contains certificates and revocation data needed to validate
 * signatures long after the signing certificates have expired.
 *
 * Uses incremental save to append DSS without rewriting the existing
 * document structure, which would invalidate any existing signatures.
 *
 * @param pdfBytes - The PDF bytes (should already contain a timestamp)
 * @param ltvData - LTV validation data to embed
 * @returns PDF bytes with DSS added incrementally
 */
export async function addDSS(pdfBytes: Uint8Array, ltvData: LTVData): Promise<Uint8Array> {
    // Load the PDF
    const sigPdfDoc = await PDFDocument.load(pdfBytes, {
        updateMetadata: false,
    });

    // Take snapshot BEFORE modifications for incremental save
    const snapshot = sigPdfDoc.takeSnapshot();

    const context = sigPdfDoc.context;

    // WORKAROUND: correctly track objects from previous incremental updates.
    // Scan bytes to ensure largestObjectNumber matches the actual file content,
    // preserving the object numbering sequence for incremental updates.
    const pdfString = new TextDecoder("latin1").decode(pdfBytes);
    const objMatches = pdfString.matchAll(/(\d{1,20})\s+\d{1,20}\s+obj/g);
    let maxObjNum = context.largestObjectNumber;
    for (const match of objMatches) {
        const objNum = parseInt(match[1] ?? "0", 10);
        if (objNum > maxObjNum) {
            maxObjNum = objNum;
        }
    }
    // internal property of PDFContext needed for the workaround
    interface PDFContextInternal {
        largestObjectNumber: number;
    }

    const contextInternal = context as unknown as PDFContextInternal;
    contextInternal.largestObjectNumber = maxObjNum;

    // Create arrays for certificates, CRLs, and OCSP responses
    const certsArray = PDFArray.withContext(context);
    const crlsArray = PDFArray.withContext(context);
    const ocspsArray = PDFArray.withContext(context);

    // Add certificates as streams
    for (const certData of ltvData.certificates) {
        const streamDict = context.obj({});
        const certStream = PDFRawStream.of(streamDict, certData);
        const certRef = context.register(certStream);
        certsArray.push(certRef);
    }

    // Add CRLs as streams
    for (const crlData of ltvData.crls) {
        const streamDict = context.obj({});
        const crlStream = PDFRawStream.of(streamDict, crlData);
        const crlRef = context.register(crlStream);
        crlsArray.push(crlRef);
    }

    // Add OCSP responses as streams
    for (const ocspData of ltvData.ocspResponses) {
        const streamDict = context.obj({});
        const ocspStream = PDFRawStream.of(streamDict, ocspData);
        const ocspRef = context.register(ocspStream);
        ocspsArray.push(ocspRef);
    }

    // Create the DSS dictionary
    const dssDict = context.obj({});

    if (ltvData.certificates.length > 0) {
        dssDict.set(PDFName.of("Certs"), certsArray);
    }

    if (ltvData.crls.length > 0) {
        dssDict.set(PDFName.of("CRLs"), crlsArray);
    }

    if (ltvData.ocspResponses.length > 0) {
        dssDict.set(PDFName.of("OCSPs"), ocspsArray);
    }

    // Register and add to catalog
    const dssRef = context.register(dssDict);
    sigPdfDoc.catalog.set(PDFName.of("DSS"), dssRef);

    // Mark all new objects for incremental save
    snapshot.markRefForSave(dssRef);

    // Mark all certificate/CRL/OCSP stream refs for save
    for (let i = 0; i < certsArray.size(); i++) {
        const ref = certsArray.get(i);
        if (ref instanceof PDFRef) {
            snapshot.markRefForSave(ref);
        }
    }
    for (let i = 0; i < crlsArray.size(); i++) {
        const ref = crlsArray.get(i);
        if (ref instanceof PDFRef) {
            snapshot.markRefForSave(ref);
        }
    }
    for (let i = 0; i < ocspsArray.size(); i++) {
        const ref = ocspsArray.get(i);
        if (ref instanceof PDFRef) {
            snapshot.markRefForSave(ref);
        }
    }

    // Mark the catalog as modified so DSS entry is included
    const catalogRef = context.trailerInfo.Root;
    if (catalogRef instanceof PDFRef) {
        snapshot.markRefForSave(catalogRef);
    }

    // Use incremental save to append DSS without destroying existing signatures
    const incrementalBytes = await sigPdfDoc.saveIncremental(snapshot);

    // Concatenate original + incremental bytes
    const finalBytes = new Uint8Array(pdfBytes.length + incrementalBytes.length);
    finalBytes.set(pdfBytes, 0);
    finalBytes.set(incrementalBytes, pdfBytes.length);

    return finalBytes;
}

/**
 * Adds a VRI (Validation-Related Information) dictionary for a signature.
 * Required by PAdES-LTA for full compliance.
 *
 * The VRI dictionary associates validation material (certificates, CRLs, OCSP responses)
 * with a specific signature by using the signing certificate's hash as the key.
 *
 * PAdES-LTA Compliance (ETSI EN 319 142-1):
 * - VRI dictionaries must be added to the catalog under "VRI" key
 * - Each VRI entry is named by the SHA-1 hash of the signing certificate
 * - VRI contains: Cert (reference), CRLs (array), OCSPs (array)
 *
 * Hash Algorithm Note:
 * SHA-1 is used for the VRI key as required by PDF 1.x / PAdES standards.
 * This is NOT a security-critical hash - SHA-1 here is used purely as a unique
 * identifier/key to look up the correct validation material for a signature.
 *
 * The actual cryptographic security comes from:
 * 1. The timestamp signature itself (uses SHA-256/384/512 as configured)
 * 2. The embedded certificate chain
 * 3. The OCSP/CRL revocation data
 *
 * PDF 2.0 (PDF 1.7 with extension level 8) allows SHA-256 for VRI keys.
 * For maximum compatibility with PDF 1.x viewers and tools, SHA-1 is used.
 * Future versions could add an optional hashAlgorithm parameter for PDF 2.0.
 *
 * @param pdfBytes - The PDF bytes
 * @param signingCert - The signing certificate (for VRI key generation)
 * @param revocationData - CRLs and OCSP responses to associate with this signature
 * @param options - Additional options
 * @returns PDF bytes with VRI added incrementally
 */
export async function addVRI(
    pdfBytes: Uint8Array,
    signingCert: pkijs.Certificate,
    revocationData: { crls?: Uint8Array[]; ocspResponses?: Uint8Array[] },
    options?: { hashAlgorithm?: "SHA-1" | "SHA-256" }
): Promise<Uint8Array> {
    return addVRIEnhanced(pdfBytes, signingCert, {
        revocationData,
        hashAlgorithm: options?.hashAlgorithm,
    });
}

/**
 * Enhanced VRI creation with proper DSS integration and PAdES compliance.
 *
 * This function creates VRI entries that properly reference DSS validation objects
 * instead of embedding duplicate data, improving PAdES compliance and reducing PDF size.
 *
 * @param pdfBytes - The PDF bytes containing DSS
 * @param signingCert - The signing certificate (for VRI key generation)
 * @param options - Configuration options
 * @returns PDF bytes with enhanced VRI added incrementally
 */
export async function addVRIEnhanced(
    pdfBytes: Uint8Array,
    signingCert: pkijs.Certificate,
    options: {
        revocationData?: { crls?: Uint8Array[]; ocspResponses?: Uint8Array[] };
        dssCertRefs?: PDFRef[];
        dssCrlRefs?: PDFRef[];
        dssOcspRefs?: PDFRef[];
        timestampRef?: PDFRef;
        hashAlgorithm?: "SHA-1" | "SHA-256";
    } = {}
): Promise<Uint8Array> {
    // Load the PDF
    const sigPdfDoc = await PDFDocument.load(pdfBytes, {
        updateMetadata: false,
    });

    // Take snapshot BEFORE modifications for incremental save
    const snapshot = sigPdfDoc.takeSnapshot();
    const context = sigPdfDoc.context;

    // Compute VRI key: hash of the signing certificate
    // Note: PDF 1.x / PAdES requires SHA-1 for VRI key names.
    // SHA-1 here is used as a lookup key, not for cryptographic security.
    const certDer = signingCert.toSchema().toBER(false);
    const vriKey =
        options.hashAlgorithm === "SHA-256"
            ? await sha256Hex(new Uint8Array(certDer))
            : await sha1Hex(new Uint8Array(certDer));

    // Get DSS references if available, otherwise create new streams
    let certRefs: PDFRef[] = [];
    let crlRefs: PDFRef[] = [];
    let ocspRefs: PDFRef[] = [];

    if (options.dssCertRefs) {
        certRefs = options.dssCertRefs;
    }

    if (options.dssCrlRefs) {
        crlRefs = options.dssCrlRefs;
    } else if (options.revocationData?.crls) {
        // Create new CRL streams if no DSS refs provided
        for (const crlData of options.revocationData.crls) {
            const streamDict = context.obj({});
            const crlStream = PDFRawStream.of(streamDict, crlData);
            const crlRef = context.register(crlStream);
            crlRefs.push(crlRef);
        }
    }

    if (options.dssOcspRefs) {
        ocspRefs = options.dssOcspRefs;
    } else if (options.revocationData?.ocspResponses) {
        // Create new OCSP streams if no DSS refs provided
        for (const ocspData of options.revocationData.ocspResponses) {
            const streamDict = context.obj({});
            const ocspStream = PDFRawStream.of(streamDict, ocspData);
            const ocspRef = context.register(ocspStream);
            ocspRefs.push(ocspRef);
        }
    }

    // Create VRI entry arrays
    const certsArray = PDFArray.withContext(context);
    const crlsArray = PDFArray.withContext(context);
    const ocspsArray = PDFArray.withContext(context);

    // Add certificate references
    for (const certRef of certRefs) {
        certsArray.push(certRef);
    }

    // Add CRL references
    for (const crlRef of crlRefs) {
        crlsArray.push(crlRef);
    }

    // Add OCSP references
    for (const ocspRef of ocspRefs) {
        ocspsArray.push(ocspRef);
    }

    // Create the VRI entry dictionary for this signature
    const vriEntry = context.obj({});

    // Add reference to the signing certificate itself
    // Note: In a full implementation, we'd find the exact ref to the cert in Certs array
    // For now, we create a reference that validators can follow

    // Add Cert references if available
    if (certRefs.length > 0) {
        vriEntry.set(PDFName.of("Cert"), certsArray);
    }

    // Add CRL references if available
    if (crlRefs.length > 0) {
        vriEntry.set(PDFName.of("CRL"), crlsArray);
    }

    // Add OCSP references if available
    if (ocspRefs.length > 0) {
        vriEntry.set(PDFName.of("OCSP"), ocspsArray);
    }

    // Add timestamp reference if provided (for document timestamps)
    if (options.timestampRef) {
        vriEntry.set(PDFName.of("TS"), options.timestampRef);
    }

    // Get or create the VRI dictionary in the catalog
    const vriDict: PDFDict = sigPdfDoc.catalog.has(PDFName.of("VRI"))
        ? (sigPdfDoc.catalog.lookup(PDFName.of("VRI")) as PDFDict)
        : (() => {
            const newVri = context.obj({});
            const vriRef = context.register(newVri);
            sigPdfDoc.catalog.set(PDFName.of("VRI"), vriRef);
            return newVri;
        })();

    // Add this VRI entry with the certificate hash as key
    vriDict.set(PDFName.of(vriKey), vriEntry);

    // Mark VRI dict ref for save
    const catalogRef = context.trailerInfo.Root;
    if (catalogRef instanceof PDFRef) {
        snapshot.markRefForSave(catalogRef);
    }

    // Use incremental save to append VRI without destroying existing signatures
    const incrementalBytes = await sigPdfDoc.saveIncremental(snapshot);

    // Concatenate original + incremental bytes
    const finalBytes = new Uint8Array(pdfBytes.length + incrementalBytes.length);
    finalBytes.set(pdfBytes, 0);
    finalBytes.set(incrementalBytes, pdfBytes.length);

    return finalBytes;
}

/**
 * Result of completing LTV data, including any errors encountered
 */
export interface CompletedLTVData {
    /** The enriched LTV data */
    data: LTVData;
    /** Any errors encountered during enrichment (for debugging/monitoring) */
    errors: string[];
}

/**
 * Attempts to fetch missing revocation data (OCSP) for the certificates in the LTV data.
 * This is "best effort" - if network fails or OCSP is unavailable, it returns the original data (or partial).
 *
 * @param ltvData - The extracted LTV data (certs, CRLs)
 * @returns CompletedLTVData with enhanced data and any errors encountered
 */
export async function completeLTVData(ltvData: LTVData): Promise<CompletedLTVData> {
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
            const asn1 = asn1js.fromBER(certBytes.slice().buffer);
            if (asn1.offset !== -1) {
                certs.push(new pkijs.Certificate({ schema: asn1.result }));
            }
        }

        // We need at least 2 certs to have an issuer-subject pair (unless self-signed, which don't have OCSP)
        if (certs.length < 2) {
            return { data: enrichedData, errors };
        }

        // Iterate over certs to find their issuers and fetch OCSP
        // We skip the root (last one usually, or self-signed) effectively because we won't find an issuer for it
        // that is *different* (or if we do, root OCSP is rare/uncommon).
        for (const cert of certs) {
            // Find issuer
            // Simple check: issuer's subject == cert's issuer
            // This is O(N^2) but N is small (chain length ~3-4)
            const issuer = certs.find(
                (c) =>
                    c.subject.toString() === cert.issuer.toString() &&
                    // Basic check to ensure we aren't using the cert as its own issuer (unless self-signed, but then no OCSP usually)
                    // Serial number check helps avoid self-match for non-root
                    c.serialNumber.toString() !== cert.serialNumber.toString()
            );

            if (!issuer) {
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
                    const response = await fetchOCSPResponse(ocspUrl, request);

                    // Validate OCSP response before embedding (best effort)
                    // If parsing fails, we still embed the response but log a warning
                    try {
                        const parsed = parseOCSPResponse(response);
                        if (parsed.certStatus !== CertificateStatus.GOOD) {
                            errors.push(
                                `OCSP indicates certificate is not good (Status: ${CertificateStatus[parsed.certStatus]}), skipping for cert serial: ${cert.serialNumber.valueBlock.toString()}`
                            );
                            continue;
                        }
                    } catch (parseError) {
                        // Parse failure - embed anyway but log warning
                        errors.push(
                            `Failed to parse OCSP response, embedding anyway: ${parseError instanceof Error ? parseError.message : String(parseError)}`
                        );
                    }

                    // Deduplicate OCSP responses
                    const ocspHash = bytesToHex(response);
                    if (!seenOCSPs.has(ocspHash)) {
                        seenOCSPs.add(ocspHash);
                        enrichedData.ocspResponses.push(response);
                    }
                    ocspSuccess = true;
                } catch (e) {
                    // OCSP fetch failed - log error and continue to CRL
                    errors.push(
                        `Failed to fetch OCSP for certificate (Serial: ${cert.serialNumber.valueBlock.toString()}): ${e instanceof Error ? e.message : String(e)}`
                    );
                }
            }

            // If OCSP failed or wasn't available, try CRL
            if (!ocspSuccess) {
                const crlUrls = getCRLDistributionPoints(cert);
                for (const url of crlUrls) {
                    try {
                        const crlBytes = await fetchCRL(url);

                        // Deduplicate CRLs
                        const crlHash = bytesToHex(crlBytes);
                        if (!seenCRLs.has(crlHash)) {
                            seenCRLs.add(crlHash);
                            enrichedData.crls.push(crlBytes);
                        }
                        // If we got one CRL, that's usually enough for this cert (ignoring delta CRLs for now)
                        break;
                    } catch (e) {
                        // CRL fetch failed - try next URL
                        errors.push(
                            `Failed to fetch CRL from ${url}: ${e instanceof Error ? e.message : String(e)}`
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
 * @returns Counts of Certs, CRLs, and OCSPs in the DSS
 */
export async function getDSSInfo(
    pdfBytes: Uint8Array
): Promise<{ certs: number; crls: number; ocsps: number }> {
    try {
        const pdfDoc = await PDFDocument.load(pdfBytes, {
            updateMetadata: false,
            ignoreEncryption: true,
        });
        const catalog = pdfDoc.catalog;

        const dss = catalog.lookup(PDFName.of("DSS"));
        if (!dss || !(dss instanceof PDFDict)) {
            return { certs: 0, crls: 0, ocsps: 0 };
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
        return { certs: 0, crls: 0, ocsps: 0 };
    }
}
