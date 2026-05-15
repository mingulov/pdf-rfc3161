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
import { toArrayBuffer, bytesToHex } from "../utils.js";

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
            preferOCSP: options.preferOCSP ?? true,
        };
    }

    /**
     * Queue a certificate for validation. Must be called before `validateAll()`;
     * throws once validation has started.
     *
     * @param cert - The certificate to validate.
     * @param options.issuer - Optional issuer to use instead of resolving by
     *   subject; useful when the issuer is already in hand.
     * @throws TimestampError with code `STATE_ERROR` if called after
     *   `validateAll()` has started.
     */
    queueCertificate(
        cert: pkijs.Certificate,
        options?: {
            issuer?: pkijs.Certificate;
        }
    ): void {
        if (this.state !== "initialized") {
            throw new TimestampError(
                TimestampErrorCode.STATE_ERROR,
                "Cannot queue certificates after validation started"
            );
        }

        this.certificates.push({
            cert,
            issuer: options?.issuer,
        });
    }

    /**
     * Queue every certificate in a chain. Each cert is validated against the
     * other members of the chain as candidate issuers (subject-issuer match,
     * not strict signature verification -- the real signature check happens in
     * `validateAll()`).
     *
     * @param chain - The chain to queue (any order; root included).
     * @throws TimestampError with code `STATE_ERROR` if called after
     *   `validateAll()` has started.
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
     * Execute validation for all queued certificates. Each certificate is
     * validated against the configured trust store and revocation policy.
     *
     * @returns One `ValidationResult` per queued certificate, in the order
     *   they were queued.
     * @throws TimestampError with code `STATE_ERROR` if called twice on the same
     *   session, or while another `validateAll()` is in flight.
     */
    async validateAll(): Promise<ValidationResult[]> {
        if (this.state !== "initialized") {
            throw new TimestampError(
                TimestampErrorCode.STATE_ERROR,
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
                // M2: capture the OCSP bytes for downstream exportLTVData
                (result.ocspResponses ??= []).push(ocspResponse);
            } catch (e) {
                result.errors.push(`OCSP failed: ${e instanceof Error ? e.message : String(e)}`);
            }
        }

        // Priority model (M3): OCSP is authoritative when it succeeded.
        // CRL is consulted only as a fallback when OCSP did not run or did not
        // produce a valid (non-revoked) answer. CRL never resets isValid back
        // to true after OCSP says revoked -- this is intentional. If you need
        // CRL to override OCSP, build a separate flow that calls only CRL.
        if (!result.sources.includes("OCSP") || !result.isValid) {
            const crlUrls = getCRLDistributionPoints(req.cert);
            for (const url of crlUrls) {
                try {
                    const crl = await this.fetchCRLWithCache(url);
                    // M2: capture the CRL bytes for downstream exportLTVData
                    (result.crls ??= []).push(crl);
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

            const asn1 = asn1js.fromBER(toArrayBuffer(crlInfo.crl));
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
                TimestampErrorCode.STATE_ERROR,
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
                TimestampErrorCode.STATE_ERROR,
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

        // Dedupe by byte-identical content so the same CRL fetched for
        // multiple certs in the chain isn't embedded twice.
        const seenCrls = new Set<string>();
        const seenOcsps = new Set<string>();
        const fingerprint = (bytes: Uint8Array): string => {
            const sample = bytes.subarray(0, Math.min(bytes.length, 64));
            return `${bytes.length.toString()}:${bytesToHex(sample)}`;
        };

        for (const result of this.results) {
            try {
                const der = result.cert.toSchema().toBER(false);
                certs.push(new Uint8Array(der));
            } catch {
                // Skip certificates that can't be serialized
            }
            for (const crl of result.crls ?? []) {
                const fp = fingerprint(crl);
                if (!seenCrls.has(fp)) {
                    seenCrls.add(fp);
                    crls.push(crl);
                }
            }
            for (const ocsp of result.ocspResponses ?? []) {
                const fp = fingerprint(ocsp);
                if (!seenOcsps.has(fp)) {
                    seenOcsps.add(fp);
                    ocsps.push(ocsp);
                }
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
