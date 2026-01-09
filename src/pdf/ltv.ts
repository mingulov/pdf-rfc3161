import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { PDFDocument, PDFName, PDFArray, PDFRawStream, PDFRef } from "pdf-lib-incremental-save";
import { TimestampError, TimestampErrorCode } from "../types.js";

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
    const pdfDoc = await PDFDocument.load(pdfBytes, {
        updateMetadata: false,
    });

    // Take snapshot BEFORE modifications for incremental save
    // This is critical - we must not rewrite the existing document
    // or we'll destroy the signature's ByteRange offsets
    const snapshot = pdfDoc.takeSnapshot();

    const context = pdfDoc.context;

    // WORKAROUND: pdf-lib-incremental-save doesn't correctly track objects from
    // previous incremental updates. We need to find the true largest object number
    // by scanning all xref sections in the PDF, otherwise new object registrations
    // will conflict with existing objects.
    const pdfString = new TextDecoder("latin1").decode(pdfBytes);
    const objMatches = pdfString.matchAll(/(\d+)\s+\d+\s+obj/g);
    let maxObjNum = context.largestObjectNumber;
    for (const match of objMatches) {
        const objNum = parseInt(match[1] ?? "0", 10);
        if (objNum > maxObjNum) {
            maxObjNum = objNum;
        }
    }
    // Update context to use the correct largest object number
    // This is a workaround - we access the private property directly
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
    (context as any).largestObjectNumber = maxObjNum;

    // Create arrays for certificates, CRLs, and OCSP responses
    const certsArray = PDFArray.withContext(context);
    const crlsArray = PDFArray.withContext(context);
    const ocspsArray = PDFArray.withContext(context);

    // Add certificates as streams
    for (const certData of ltvData.certificates) {
        // Create a raw stream with the certificate data
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
    pdfDoc.catalog.set(PDFName.of("DSS"), dssRef);

    // Mark all new objects for incremental save
    // The DSS ref must be marked
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
    const incrementalBytes = await pdfDoc.saveIncremental(snapshot);

    // Concatenate original + incremental bytes
    const finalBytes = new Uint8Array(pdfBytes.length + incrementalBytes.length);
    finalBytes.set(pdfBytes, 0);
    finalBytes.set(incrementalBytes, pdfBytes.length);

    return finalBytes;
}

/**
 * Fetches OCSP response for a certificate.
 * This is optional but recommended for full LTV support.
 *
 * @param certificate - DER-encoded certificate
 * @param issuerCertificate - DER-encoded issuer certificate
 * @returns DER-encoded OCSP response or null if not available
 */
export async function fetchOCSPResponse(
    certificate: Uint8Array,
    issuerCertificate: Uint8Array
): Promise<Uint8Array | null> {
    try {
        // Parse the certificate to get the OCSP responder URL
        const certAsn1 = asn1js.fromBER(certificate.slice().buffer);
        if (certAsn1.offset === -1) {
            return null;
        }

        const cert = new pkijs.Certificate({ schema: certAsn1.result });

        // Find the Authority Information Access extension
        const aiaExt = cert.extensions?.find(
            (ext) => ext.extnID === "1.3.6.1.5.5.7.1.1" // id-pe-authorityInfoAccess
        );

        if (!aiaExt?.parsedValue) {
            return null;
        }

        // Extract OCSP responder URL from AIA extension
        // The parsedValue is an array of AccessDescription objects
        const aia = aiaExt.parsedValue as {
            accessMethod: string;
            accessLocation: { value?: string };
        }[];

        const ocspAccess = aia.find(
            (desc) => desc.accessMethod === "1.3.6.1.5.5.7.48.1" // id-ad-ocsp
        );

        if (!ocspAccess?.accessLocation.value) {
            return null;
        }

        const ocspUrl = ocspAccess.accessLocation.value;

        // Parse issuer certificate
        const issuerAsn1 = asn1js.fromBER(issuerCertificate.slice().buffer);
        if (issuerAsn1.offset === -1) {
            return null;
        }
        const issuerCert = new pkijs.Certificate({ schema: issuerAsn1.result });

        // Create OCSP request
        const ocspReq = new pkijs.OCSPRequest();

        // Add the certificate to check
        await ocspReq.createForCertificate(cert, {
            hashAlgorithm: "SHA-256",
            issuerCertificate: issuerCert,
        });

        const ocspReqData = ocspReq.toSchema().toBER(false);

        // Send OCSP request
        const response = await fetch(ocspUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/ocsp-request",
            },
            body: new Uint8Array(ocspReqData),
        });

        if (!response.ok) {
            return null;
        }

        const ocspRespData = await response.arrayBuffer();
        return new Uint8Array(ocspRespData);
    } catch {
        // OCSP fetch is best-effort
        return null;
    }
}
