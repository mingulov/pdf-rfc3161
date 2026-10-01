import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import {
    CertificateToValidate,
    RevocationEvidenceResult,
    RevocationStatus,
    ValidationResult,
    ValidationSessionOptions,
} from "./validation-types.js";
import { DefaultFetcher } from "./fetchers/default-fetcher.js";
import { InMemoryValidationCache } from "./fetchers/memory-cache.js";
import {
    CertificateStatus,
    createOCSPRequest,
    getOCSPURI,
    parseOCSPResponse,
} from "./ocsp-utils.js";
import { getCRLDistributionPoints } from "./crl-utils.js";
import { parseCRLInfo } from "./crl-client.js";
import { TimestampError, TimestampErrorCode } from "../types.js";
import { toArrayBuffer, bytesToHex } from "../utils.js";

/**
 * Combines already-evaluated per-source evidence into one status. Revoked
 * dominates good; unknown contributes nothing, so an empty evaluation also
 * yields unknown. Only authenticated evaluators may produce good/revoked;
 * until they exist every evaluation is unknown and so is the result.
 */
function combineRevocationEvidence(evidence: RevocationEvidenceResult[]): RevocationStatus {
    let sawGood = false;
    for (const item of evidence) {
        if (item.status === "revoked") {
            return "revoked";
        }
        if (item.status === "good") {
            sawGood = true;
        }
    }
    return sawGood ? "good" : "unknown";
}

/**
 * Serial number in canonical hex: DER INTEGERs may carry a leading zero
 * pad byte, which must not defeat the comparison.
 */
function normalizeSerialNumber(serial: asn1js.Integer): string {
    const bytes = serial.valueBlock.valueHexView;
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) {
        start += 1;
    }
    return bytesToHex(bytes.subarray(start));
}

/**
 * Structural check for whether a CRL lists a certificate serial in its
 * revokedCertificates.
 *
 * @internal Unauthenticated structural scan for diagnostics and for the
 * future authenticated CRL evaluator. A match never yields a revoked
 * verdict and a miss never yields a good verdict; malformed input yields
 * false. Delta CRLs are not filtered here; callers must consult
 * parseCRLInfo and never treat a delta CRL as complete.
 */
export function crlContainsSerial(crlBytes: Uint8Array, cert: pkijs.Certificate): boolean {
    try {
        const asn1 = asn1js.fromBER(toArrayBuffer(crlBytes));
        if (asn1.offset === -1) return false;

        const crl = new pkijs.CertificateRevocationList({ schema: asn1.result });

        const revokedEntries = crl.revokedCertificates;
        if (!revokedEntries) return false;

        const wanted = normalizeSerialNumber(cert.serialNumber);
        return revokedEntries.some(
            (entry) => normalizeSerialNumber(entry.userCertificate) === wanted
        );
    } catch {
        return false;
    }
}

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
 *     console.log(`Serial ${result.cert.serialNumber}: ${result.revocationStatus}`);
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
     * evaluated against collected OCSP/CRL revocation evidence; the result
     * carries a revocation status relative to a verified issuing key, not
     * complete path trust. Until authenticated evaluators exist, structural
     * evidence alone yields "unknown" for every certificate.
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
     * Validate a single certificate.
     *
     * Attempt order follows `preferOCSP` (false tries CRL then OCSP).
     * Unknown permits fallback to the other source; only an authenticated
     * decisive result stops the walk. No authenticated evaluator exists
     * yet, so every evaluation below stays unknown by construction and the
     * combined status is always unknown.
     */
    private async validateCertificate(req: CertificateToValidate): Promise<ValidationResult> {
        const result: ValidationResult = {
            cert: req.cert,
            revocationStatus: "unknown",
            isValid: false,
            sources: [],
            errors: [],
        };

        const order: ("OCSP" | "CRL")[] = this.options.preferOCSP
            ? ["OCSP", "CRL"]
            : ["CRL", "OCSP"];
        const evidence: RevocationEvidenceResult[] = [];
        for (const source of order) {
            const evaluated =
                source === "OCSP"
                    ? await this.evaluateOCSPEvidence(req, result)
                    : await this.evaluateCRLEvidence(req, result);
            if (evaluated !== null) {
                evidence.push(evaluated);
                if (evaluated.status !== "unknown") {
                    break;
                }
            }
        }

        result.revocationStatus = combineRevocationEvidence(evidence);
        // Deprecated compatibility alias: true only for authenticated good.
        // eslint-disable-next-line @typescript-eslint/no-deprecated -- the session itself maintains the alias.
        result.isValid = result.revocationStatus === "good";

        return result;
    }

    /**
     * Attempts OCSP evidence collection for one certificate.
     *
     * Returns null when the certificate carries no OCSP responder URL
     * (source not attempted). Otherwise collects the response bytes (when
     * fetchable) into `result`, records diagnostics, and returns an unknown
     * evidence record: structural OCSP status is unauthenticated.
     */
    private async evaluateOCSPEvidence(
        req: CertificateToValidate,
        result: ValidationResult
    ): Promise<RevocationEvidenceResult | null> {
        const ocspUrl = getOCSPURI(req.cert);
        if (!ocspUrl) {
            return null;
        }
        const evidence: RevocationEvidenceResult = {
            status: "unknown",
            source: "OCSP",
            errors: [],
        };
        let response: Uint8Array;
        try {
            response = await this.fetchOCSPWithCache(ocspUrl, req.cert, req.issuer);
        } catch (e) {
            const message = `OCSP failed: ${e instanceof Error ? e.message : String(e)}`;
            evidence.errors.push(message);
            result.errors.push(message);
            return evidence;
        }
        // M2: capture the OCSP bytes for downstream exportLTVData
        (result.ocspResponses ??= []).push(response);
        result.sources.push("OCSP");
        const structural = this.describeOCSPStructure(response);
        const message =
            structural === "malformed"
                ? "OCSP: malformed response; revocation status unknown"
                : `OCSP: structural status "${structural}" is unauthenticated; revocation status unknown`;
        evidence.errors.push(message);
        result.errors.push(message);
        return evidence;
    }

    /**
     * Attempts CRL evidence collection for one certificate.
     *
     * Returns null when the certificate carries no distribution points
     * (source not attempted). Otherwise collects each fetchable CRL into
     * `result`, records per-URL diagnostics, and returns an unknown
     * evidence record: structural CRL contents are unauthenticated.
     */
    private async evaluateCRLEvidence(
        req: CertificateToValidate,
        result: ValidationResult
    ): Promise<RevocationEvidenceResult | null> {
        const crlUrls = getCRLDistributionPoints(req.cert);
        if (crlUrls.length === 0) {
            return null;
        }
        const evidence: RevocationEvidenceResult = {
            status: "unknown",
            source: "CRL",
            errors: [],
        };
        for (const url of crlUrls) {
            let message: string;
            try {
                const crl = await this.fetchCRLWithCache(url);
                // M2: capture the CRL bytes for downstream exportLTVData
                (result.crls ??= []).push(crl);
                result.sources.push("CRL");
                message =
                    `CRL from ${url}: ` +
                    `${this.describeCRLStructure(crl, req.cert)}; revocation status unknown`;
            } catch (e) {
                message = `CRL from ${url} failed: ${e instanceof Error ? e.message : String(e)}`;
            }
            evidence.errors.push(message);
            result.errors.push(message);
        }
        return evidence;
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

    /**
     * Structural OCSP status label for diagnostics only. Never a verdict:
     * the response signature, responder authorization, nonce, CertID match
     * and freshness are not verified here.
     */
    private describeOCSPStructure(
        response: Uint8Array
    ): "good" | "revoked" | "unknown" | "malformed" {
        try {
            const parsed = parseOCSPResponse(response);
            if (parsed.certStatus === CertificateStatus.GOOD) {
                return "good";
            }
            if (parsed.certStatus === CertificateStatus.REVOKED) {
                return "revoked";
            }
            return "unknown";
        } catch {
            return "malformed";
        }
    }

    /**
     * Structural CRL description for diagnostics only. Never a verdict:
     * target issuance, CRL issuer/key/signature, key usage, critical
     * extensions, scope and freshness are not verified here. A delta CRL is
     * detected via parseCRLInfo and is never treated as complete.
     */
    private describeCRLStructure(crlBytes: Uint8Array, cert: pkijs.Certificate): string {
        const info = parseCRLInfo(crlBytes);
        if (!info.parsed) {
            return "malformed response";
        }
        if (info.isDelta) {
            return "delta CRL is not a complete revocation source";
        }
        if (crlContainsSerial(crlBytes, cert)) {
            return "certificate serial is structurally listed but the CRL is unauthenticated";
        }
        return "certificate serial is not structurally listed and the CRL is unauthenticated";
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
     * Export LTV data for PDF embedding.
     *
     * Structural collection of fetched byte artifacts only; its output
     * never becomes a revocation verdict merely because it is embedded.
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
