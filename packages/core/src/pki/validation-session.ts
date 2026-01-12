import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import {
    CertificateToValidate,
    ValidationResult,
    ValidationSessionOptions,
} from "./validation-types.js";
import { DefaultFetcher } from "./fetchers/default-fetcher.js";
import { InMemoryValidationCache } from "./fetchers/memory-cache.js";
import { CertificateStatus } from "./ocsp-utils.js";
import { getOCSPURI } from "./ocsp-utils.js";
import { getCRLDistributionPoints } from "./crl-utils.js";
import { createOCSPRequest } from "./ocsp-utils.js";
import { parseOCSPResponse, CertificateStatus as ParsedCertificateStatus } from "./ocsp-utils.js";
import { parseCRLInfo } from "./crl-client.js";
import { TimestampError, TimestampErrorCode } from "../types.js";

/**
 * Session for managing certificate validation with OCSP/CRL.
 *
 * Pattern inspired by TimestampSession:
 * - Step 1: Queue certificates for validation
 * - Step 2: Execute validation (with dependency resolution)
 * - Step 3: Retrieve results
 *
 * @example
 * ```typescript
 * const session = new ValidationSession({ preferOCSP: true });
 *
 * // Queue certificates for validation
 * session.queueCertificate(cert1, { issuer: issuerCert });
 * session.queueCertificate(cert2);
 *
 * // Execute validation
 * await session.validateAll();
 *
 * // Get results
 * for (const result of session.getResults()) {
 *     console.log(`Serial ${result.cert.serialNumber}: ${result.isValid ? "OK" : "REVOKED"}`);
 * }
 *
 * // Export LTV data for PDF embedding
 * const ltvData = session.exportLTVData();
 * ```
 */
export class ValidationSession {
    private certificates: CertificateToValidate[] = [];
    private results: ValidationResult[] = [];
    private options: Required<ValidationSessionOptions>;
    private state: "initialized" | "validating" | "completed" = "initialized";

    constructor(options: ValidationSessionOptions = {}) {
        this.options = {
            fetcher: options.fetcher ?? new DefaultFetcher(),
            cache: options.cache ?? new InMemoryValidationCache(),
            timeout: options.timeout ?? 5000,
            maxRetries: options.maxRetries ?? 3,
            preferOCSP: options.preferOCSP ?? true,
            trustStore: options.trustStore ?? [],
        };
    }

    /**
     * Queue a certificate for validation
     */
    queueCertificate(
        cert: pkijs.Certificate,
        options?: {
            issuer?: pkijs.Certificate;
            purposes?: string[];
        }
    ): void {
        if (this.state !== "initialized") {
            throw new TimestampError(
                TimestampErrorCode.PDF_ERROR,
                "Cannot queue certificates after validation started"
            );
        }

        this.certificates.push({
            cert,
            issuer: options?.issuer,
            purposes: options?.purposes,
        });
    }

    /**
     * Queue multiple certificates from a chain
     */
    queueChain(chain: pkijs.Certificate[]): void {
        for (const cert of chain) {
            const issuer = chain.find(
                (c) =>
                    c.subject.toString() === cert.issuer.toString() &&
                    c.serialNumber.toString() !== cert.serialNumber.toString()
            );
            this.queueCertificate(cert, { issuer });
        }
    }

    /**
     * Execute validation for all queued certificates
     */
    async validateAll(): Promise<ValidationResult[]> {
        if (this.state !== "initialized") {
            throw new TimestampError(
                TimestampErrorCode.PDF_ERROR,
                "Validation already in progress or completed"
            );
        }

        this.state = "validating";
        this.results = [];

        for (const certReq of this.certificates) {
            const result = await this.validateCertificate(certReq);
            this.results.push(result);
        }

        this.state = "completed";
        return this.results;
    }

    /**
     * Validate a single certificate
     */
    private async validateCertificate(req: CertificateToValidate): Promise<ValidationResult> {
        const result: ValidationResult = {
            cert: req.cert,
            isValid: true,
            sources: [],
            errors: [],
        };

        const ocspUrl = getOCSPURI(req.cert);

        if (ocspUrl && this.options.preferOCSP) {
            try {
                const ocspResponse = await this.fetchOCSPWithCache(ocspUrl, req.cert, req.issuer);
                const parsed = this.parseOCSPResponse(ocspResponse);

                if (parsed.certStatus === ParsedCertificateStatus.REVOKED) {
                    result.isValid = false;
                    result.errors.push("OCSP: Certificate revoked");
                } else if (parsed.certStatus === ParsedCertificateStatus.UNKNOWN) {
                    result.isValid = false;
                    result.errors.push("OCSP: Certificate status unknown");
                }
                result.sources.push("OCSP");
            } catch (e) {
                result.errors.push(`OCSP failed: ${e instanceof Error ? e.message : String(e)}`);
            }
        }

        if (!result.sources.includes("OCSP") || !result.isValid) {
            const crlUrls = getCRLDistributionPoints(req.cert);
            for (const url of crlUrls) {
                try {
                    const crl = await this.fetchCRLWithCache(url);
                    if (this.checkCRLForCert(crl, req.cert)) {
                        result.isValid = false;
                        result.sources.push("CRL");
                        break;
                    }
                    result.sources.push("CRL");
                } catch (e) {
                    result.errors.push(
                        `CRL from ${url} failed: ${e instanceof Error ? e.message : String(e)}`
                    );
                }
            }
        }

        return result;
    }

    private async fetchOCSPWithCache(
        url: string,
        cert: pkijs.Certificate,
        issuer?: pkijs.Certificate
    ): Promise<Uint8Array> {
        const issuerCert = issuer ?? this.findIssuer(cert);
        if (!issuerCert) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Cannot create OCSP request: issuer certificate not found"
            );
        }

        const request = await createOCSPRequest(cert, issuerCert);
        const cached = this.options.cache.getOCSP(url, request);
        if (cached) return cached;

        const response = await this.options.fetcher.fetchOCSP(url, request);
        this.options.cache.setOCSP(url, request, response);

        return response;
    }

    private async fetchCRLWithCache(url: string): Promise<Uint8Array> {
        const cached = this.options.cache.getCRL(url);
        if (cached) return cached;

        const response = await this.options.fetcher.fetchCRL(url);
        this.options.cache.setCRL(url, response);

        return response;
    }

    private findIssuer(cert: pkijs.Certificate): pkijs.Certificate | undefined {
        return this.certificates.find((c) => c.cert.subject.toString() === cert.issuer.toString())
            ?.cert;
    }

    private parseOCSPResponse(response: Uint8Array): {
        certStatus: CertificateStatus;
    } {
        try {
            const parsed = parseOCSPResponse(response);
            return { certStatus: parsed.certStatus };
        } catch {
            return { certStatus: CertificateStatus.UNKNOWN };
        }
    }

    private checkCRLForCert(crlBytes: Uint8Array, cert: pkijs.Certificate): boolean {
        try {
            const crlInfo = parseCRLInfo(crlBytes);

            const asn1 = asn1js.fromBER(crlInfo.crl.slice().buffer);
            if (asn1.offset === -1) return false;

            const crl = new pkijs.CertificateRevocationList({ schema: asn1.result });

            const revokedEntries = (
                crl as { revokedCertificateEntries?: pkijs.RevokedCertificate[] }
            ).revokedCertificateEntries;
            if (!revokedEntries) return false;

            for (const entry of revokedEntries) {
                if (
                    entry.userCertificate.valueBlock.toString() ===
                    cert.serialNumber.valueBlock.toString()
                ) {
                    return true;
                }
            }
        } catch {
            return false;
        }
        return false;
    }

    /**
     * Get all validation results
     */
    getResults(): ValidationResult[] {
        if (this.state !== "completed") {
            throw new TimestampError(
                TimestampErrorCode.PDF_ERROR,
                "Validation not completed - call validateAll() first"
            );
        }
        return this.results;
    }

    /**
     * Get validation results for a specific certificate
     */
    getResultForCert(cert: pkijs.Certificate): ValidationResult | undefined {
        if (this.state !== "completed") {
            throw new TimestampError(
                TimestampErrorCode.PDF_ERROR,
                "Validation not completed - call validateAll() first"
            );
        }
        return this.results.find(
            (r) => r.cert.serialNumber.toString() === cert.serialNumber.toString()
        );
    }

    /**
     * Export LTV data for PDF embedding
     */
    exportLTVData(): {
        certificates: Uint8Array[];
        crls: Uint8Array[];
        ocspResponses: Uint8Array[];
    } {
        const certs: Uint8Array[] = [];
        const crls: Uint8Array[] = [];
        const ocsps: Uint8Array[] = [];

        for (const result of this.results) {
            try {
                const der = result.cert.toSchema().toBER(false);
                certs.push(new Uint8Array(der));
            } catch {
                // Skip certificates that can't be serialized
            }
        }

        return { certificates: certs, crls, ocspResponses: ocsps };
    }

    /**
     * Dispose resources and reset state
     */
    dispose(): void {
        this.certificates = [];
        this.results = [];
        this.state = "initialized";
    }

    /**
     * Get the current state of the session
     */
    getState(): "initialized" | "validating" | "completed" {
        return this.state;
    }
}
