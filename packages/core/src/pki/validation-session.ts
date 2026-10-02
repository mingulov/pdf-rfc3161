import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import {
    CertificateToValidate,
    RevocationDataFetcher,
    RevocationEvidenceResult,
    RevocationStatus,
    ValidationCache,
    ValidationResult,
    ValidationSessionOptions,
} from "./validation-types.js";
import { DefaultFetcher } from "./fetchers/default-fetcher.js";
import { InMemoryValidationCache } from "./fetchers/memory-cache.js";
import { createOCSPRequest, getOCSPURI, parseOCSPResponse } from "./ocsp-utils.js";
import { validateOCSPEvidence } from "./ocsp-validation.js";
import { validateCRLEvidence } from "./crl-validation.js";
import { getCRLDistributionPoints } from "./crl-utils.js";
import { parseCRLInfo } from "./crl-client.js";
import { certificatesByteEqual, resolveVerifiedIssuer, verifyIssuance } from "./cert-utils.js";
import { TimestampError, TimestampErrorCode } from "../types.js";
import { toArrayBuffer, bytesToHex } from "../utils.js";
import { getLogger } from "../utils/logger.js";
import { DEFAULT_CRL_CONFIG, DEFAULT_OCSP_CONFIG } from "../constants.js";
import {
    OperationBudget,
    assertValidOperationBudgetLimits,
    type OperationBudgetLimits,
} from "../utils/operation-budget.js";

/**
 * Structural view of DefaultFetcher's @internal budgeted entries for the
 * session's capability probe. The probe is typeof-only: the supported
 * ESM/CJS mixing means a genuine instance may come from the other realm's
 * constructor, and subclass-override detection happens inside the entry
 * itself via a same-realm prototype comparison.
 */
type InternalBudgetedFetcher = Partial<
    Pick<DefaultFetcher, "fetchOCSPWithBudget" | "fetchCRLWithBudget">
>;

/**
 * Default accepted OCSP clock skew: 5 minutes in both directions.
 * Module-internal like the other session helpers (not re-exported from
 * the package entries); tests pin the value through this module.
 */
export const DEFAULT_OCSP_CLOCK_SKEW_MS = 5 * 60 * 1000;

/**
 * Default freshness horizon for OCSP responses without nextUpdate: 7
 * days. Module-internal (see above).
 */
export const DEFAULT_OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_MS = 7 * 24 * 60 * 60 * 1000;

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
 * Serial number in canonical hex: the minimal-DER magnitude bytes, or
 * null when the encoding is not a non-negative minimal INTEGER. A bare
 * leading-zero strip would conflate -128 (`80`) with 128 (`00 80`) and
 * match empty integers, and `valueDec` loses precision past 2^53 --
 * neither reaches a comparison here or in the strict CRL validator.
 */
function normalizeSerialNumber(serial: asn1js.Integer): string | null {
    const bytes = serial.valueBlock.valueHexView;
    if (bytes.length === 0) return null;
    const first = bytes[0];
    if (first === undefined) return null;
    if (bytes.length > 1) {
        const second = bytes[1];
        if (second === undefined) return null;
        if (first === 0x00 && (second & 0x80) === 0) return null;
        if (first === 0xff && (second & 0x80) !== 0) return null;
    }
    if (first >= 0x80) return null;
    const magnitude = bytes.length > 1 && first === 0x00 ? bytes.subarray(1) : bytes;
    return bytesToHex(magnitude);
}

/**
 * Structural check for whether a CRL lists a certificate serial in its
 * revokedCertificates.
 *
 * @internal Unauthenticated structural scan for diagnostics. A match
 * never yields a revoked verdict and a miss never yields a good
 * verdict; malformed input yields false. Serial comparison is exact
 * numeric identity (no lossy `valueDec`, no -128/128 conflation).
 * Delta CRLs are not filtered here; callers must consult parseCRLInfo
 * and never treat a delta CRL as complete.
 */
export function crlContainsSerial(crlBytes: Uint8Array, cert: pkijs.Certificate): boolean {
    try {
        const asn1 = asn1js.fromBER(toArrayBuffer(crlBytes));
        if (asn1.offset === -1) return false;

        const crl = new pkijs.CertificateRevocationList({ schema: asn1.result });

        const revokedEntries = crl.revokedCertificates;
        if (!revokedEntries) return false;

        const wanted = normalizeSerialNumber(cert.serialNumber);
        if (wanted === null) return false;
        return revokedEntries.some((entry) => {
            const candidate = normalizeSerialNumber(entry.userCertificate);
            return candidate !== null && candidate === wanted;
        });
    } catch {
        return false;
    }
}

/**
 * Compares two byte strings for exact equality.
 */
function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
    if (left.length !== right.length) return false;
    for (let index = 0; index < left.length; index++) {
        if (left[index] !== right[index]) return false;
    }
    return true;
}

/**
 * Deduplicates byte artifacts by exact content using length buckets and
 * binary comparison. Never constructs hex strings, so large artifacts
 * cannot exhaust memory via string amplification. Order-preserving:
 * the first occurrence of each distinct artifact is retained.
 */
export function deduplicateByteArtifacts(artifacts: Uint8Array[]): Uint8Array[] {
    const buckets = new Map<number, Uint8Array[]>();
    const unique: Uint8Array[] = [];
    for (const bytes of artifacts) {
        const bucket = buckets.get(bytes.length);
        if (bucket !== undefined) {
            let duplicate = false;
            for (const seen of bucket) {
                if (bytesEqual(seen, bytes)) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) continue;
            bucket.push(bytes);
        } else {
            buckets.set(bytes.length, [bytes]);
        }
        unique.push(bytes);
    }
    return unique;
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
    private options: {
        fetcher: RevocationDataFetcher;
        cache: ValidationCache;
        preferOCSP: boolean;
        checkDate: Date | undefined;
        clockSkewMs: number;
        maxAgeWithoutNextUpdateMs: number;
        includeOCSPNonce: boolean;
        budget: OperationBudgetLimits | undefined;
    };
    private state: "initialized" | "validating" | "completed" = "initialized";

    constructor(options: ValidationSessionOptions = {}) {
        if (
            options.checkDate !== undefined &&
            (!(options.checkDate instanceof Date) || !Number.isFinite(options.checkDate.getTime()))
        ) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_ARGUMENT,
                "ValidationSession checkDate must be a finite date"
            );
        }
        if (
            options.clockSkewMs !== undefined &&
            (!Number.isFinite(options.clockSkewMs) || options.clockSkewMs < 0)
        ) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_ARGUMENT,
                "ValidationSession clockSkewMs must be finite and non-negative"
            );
        }
        if (
            options.maxAgeWithoutNextUpdateMs !== undefined &&
            (!Number.isFinite(options.maxAgeWithoutNextUpdateMs) ||
                options.maxAgeWithoutNextUpdateMs < 0)
        ) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_ARGUMENT,
                "ValidationSession maxAgeWithoutNextUpdateMs must be finite and non-negative"
            );
        }
        if (options.budget !== undefined) {
            assertValidOperationBudgetLimits(options.budget);
        }
        this.options = {
            fetcher: options.fetcher ?? new DefaultFetcher(),
            cache: options.cache ?? new InMemoryValidationCache(),
            preferOCSP: options.preferOCSP ?? true,
            checkDate:
                options.checkDate === undefined ? undefined : new Date(options.checkDate.getTime()),
            clockSkewMs: options.clockSkewMs ?? DEFAULT_OCSP_CLOCK_SKEW_MS,
            maxAgeWithoutNextUpdateMs:
                options.maxAgeWithoutNextUpdateMs ?? DEFAULT_OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_MS,
            includeOCSPNonce: options.includeOCSPNonce ?? true,
            budget: options.budget === undefined ? undefined : { ...options.budget },
        };
    }

    /**
     * Queue a certificate for validation. Must be called before `validateAll()`;
     * throws once validation has started.
     *
     * @param cert - The certificate to validate.
     * @param options.issuer - Optional explicitly supplied issuer; verified
     *   at use (it must have issued `cert`), never trusted unchecked.
     * @param options.issuerCandidates - Optional candidate issuers, as
     *   stored by `queueChain`; narrowed and signature-verified at use.
     * @throws TimestampError with code `STATE_ERROR` if called after
     *   `validateAll()` has started.
     */
    queueCertificate(
        cert: pkijs.Certificate,
        options?: {
            issuer?: pkijs.Certificate;
            issuerCandidates?: pkijs.Certificate[];
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
            issuerCandidates: options?.issuerCandidates,
        });
    }

    /**
     * Queue every certificate in a chain. Each cert stores the other chain
     * members with a matching subject as candidate issuers (excluding
     * itself by exact bytes, not by serial); no first name match becomes
     * an unchecked authoritative issuer. Candidates are narrowed and
     * signature-verified when issuer-dependent evidence is built.
     *
     * @param chain - The chain to queue (any order; root included).
     * @throws TimestampError with code `STATE_ERROR` if called after
     *   `validateAll()` has started.
     */
    queueChain(chain: pkijs.Certificate[]): void {
        for (const cert of chain) {
            const issuerCandidates = chain.filter(
                (candidate) =>
                    !certificatesByteEqual(candidate, cert) &&
                    candidate.subject.toString() === cert.issuer.toString()
            );
            this.queueCertificate(cert, { issuerCandidates });
        }
    }

    /**
     * Execute validation for all queued certificates. Each certificate is
     * evaluated against collected OCSP/CRL revocation evidence; the result
     * carries a revocation status relative to a verified issuing key, not
     * complete path trust. OCSP and CRL evidence are both authenticated;
     * anything unauthenticated or unsupported yields "unknown".
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
        // One budget per run, carrying the single check-time capture: every
        // fetch, retry, and cache refetch below consumes from it, and every
        // evaluation reads the same checkDate from it.
        const budget = new OperationBudget(this.options.budget ?? {}, {
            checkTime: this.options.checkDate ?? new Date(),
        });
        try {
            for (const certReq of this.certificates) {
                if (!budget.admitCertificate()) {
                    // Structural admission refusal, never a verdict: one
                    // unknown result per queued certificate, in order.
                    this.results.push({
                        cert: certReq.cert,
                        revocationStatus: "unknown",
                        isValid: false,
                        sources: [],
                        errors: [budget.certificateRefusal()],
                    });
                    continue;
                }
                const result = await this.validateCertificate(certReq, budget);
                this.results.push(result);
            }
        } finally {
            budget.dispose();
        }

        this.state = "completed";
        return this.results;
    }

    /**
     * Validate a single certificate.
     *
     * Attempt order follows `preferOCSP` (false tries CRL then OCSP).
     * Unknown permits fallback to the other source; only an authenticated
     * decisive result stops the walk. Both OCSP and CRL evidence are
     * authenticated; revoked dominates and is never overwritten by a
     * later good.
     */
    private async validateCertificate(
        req: CertificateToValidate,
        budget: OperationBudget
    ): Promise<ValidationResult> {
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
                    ? await this.evaluateOCSPEvidence(req, result, budget)
                    : await this.evaluateCRLEvidence(req, result, budget);
            if (evaluated !== null) {
                evidence.push(evaluated);
                if (evaluated.status !== "unknown") {
                    break;
                }
            }
        }
        if (evidence.length === 0) {
            // T04 F3 decision: no source was attempted (the certificate
            // carries no OCSP responder URL and no CRL distribution
            // points). Record one result-level diagnostic so "nothing to
            // check" never looks like "not evaluated". Per-source
            // evidence stays absent; shared with T07 for the CRL side.
            result.errors.push(
                "No revocation endpoints attempted: certificate has no OCSP responder URL " +
                    "and no CRL distribution points; revocation status unknown"
            );
        }

        result.revocationStatus = combineRevocationEvidence(evidence);
        // Deprecated compatibility alias: true only for authenticated good.
        // eslint-disable-next-line @typescript-eslint/no-deprecated -- the session itself maintains the alias.
        result.isValid = result.revocationStatus === "good";

        return result;
    }

    /**
     * Attempts OCSP evidence evaluation for one certificate.
     *
     * Returns null when the certificate carries no OCSP responder URL
     * (source not attempted). Otherwise builds the request with the
     * verified issuer, collects the response bytes (cached or fetched)
     * into `result`, and routes them through validateOCSPEvidence with
     * the exact request bytes. Candidate bytes and sources are preserved
     * even when strict evaluation stays unknown (C06).
     */
    private async evaluateOCSPEvidence(
        req: CertificateToValidate,
        result: ValidationResult,
        budget: OperationBudget
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
        let issuerCert: pkijs.Certificate;
        let request: Uint8Array;
        let response: Uint8Array;
        try {
            issuerCert = await this.resolveIssuerForOCSP(req);
            request = await createOCSPRequest(req.cert, issuerCert, {
                includeNonce: this.options.includeOCSPNonce,
            });
            response = await this.fetchOCSPWithCache(ocspUrl, request, budget);
        } catch (e) {
            const message = `OCSP failed: ${e instanceof Error ? e.message : String(e)}`;
            evidence.errors.push(message);
            result.errors.push(message);
            return evidence;
        }
        // M2: capture the OCSP bytes for downstream exportLTVData
        (result.ocspResponses ??= []).push(response);
        result.sources.push("OCSP");
        // The nonce/freshness profile applies equally to cached and
        // fetched bytes: validation runs after cache retrieval either way.
        let evaluated: RevocationEvidenceResult;
        try {
            evaluated = await validateOCSPEvidence(response, {
                cert: req.cert,
                issuer: issuerCert,
                requestBytes: request,
                checkDate: budget.checkTime,
                clockSkewMs: this.options.clockSkewMs,
                maxAgeWithoutNextUpdateMs: this.options.maxAgeWithoutNextUpdateMs,
            });
        } catch (e) {
            const message = `OCSP failed: ${e instanceof Error ? e.message : String(e)}`;
            evidence.errors.push(message);
            result.errors.push(message);
            return evidence;
        }
        // An authenticated verdict completing past the elapsed deadline
        // is discarded: the completion ran out of time, so the evidence
        // cannot vouch for it. The clock (not the signal) is read so a
        // starved timer cannot smuggle a stale verdict through.
        if (budget.isElapsed()) {
            const message = `OCSP failed: ${budget.exhaustionError().message}`;
            evidence.errors.push(message);
            result.errors.push(message);
            return evidence;
        }
        evidence.status = evaluated.status;
        evidence.errors.push(...evaluated.errors);
        result.errors.push(...evaluated.errors);
        return evidence;
    }

    /**
     * Attempts CRL evidence evaluation for one certificate.
     *
     * Returns null when the certificate carries no distribution points
     * (source not attempted, feeding the shared no-endpoint diagnostic).
     * Otherwise resolves the verified issuer once, then collects each
     * fetchable CRL into `result` and routes the bytes through
     * validateCRLEvidence: the first decisive CRL stops the walk, while
     * unknown CRLs record per-URL diagnostics and yield to the next
     * distribution point. Candidate bytes and sources are preserved even
     * when strict evaluation stays unknown (C06).
     */
    private async evaluateCRLEvidence(
        req: CertificateToValidate,
        result: ValidationResult,
        budget: OperationBudget
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
        // Lazily resolved on the first fetched CRL: fetching needs only
        // the leaf distribution point, so bytes and sources are recorded
        // even when authentication later proves impossible (the T05
        // preservation contract); only the verdict needs the verified
        // issuer. Resolution is URL-independent, so one failure stops
        // the URL loop: no later URL can validate either.
        let issuerCert: pkijs.Certificate | null = null;
        for (const url of crlUrls) {
            let crl: Uint8Array;
            try {
                crl = await this.fetchCRLWithCache(url, budget);
            } catch (e) {
                const message = `CRL from ${url} failed: ${e instanceof Error ? e.message : String(e)}`;
                evidence.errors.push(message);
                result.errors.push(message);
                // A spent budget refuses every remaining URL identically.
                if (budget.exhausted) break;
                continue;
            }
            // M2: capture the CRL bytes for downstream exportLTVData
            (result.crls ??= []).push(crl);
            result.sources.push("CRL");
            if (issuerCert === null) {
                try {
                    issuerCert = await this.resolveIssuerForCRL(req);
                } catch (e) {
                    const message = `CRL failed: ${e instanceof Error ? e.message : String(e)}`;
                    evidence.errors.push(message);
                    result.errors.push(message);
                    break;
                }
            }
            // The scope/freshness/signature profile applies equally to
            // cached and fetched bytes: validation runs after cache
            // retrieval either way. No refetch on authentication
            // failure: an auth outcome is an issuer verdict, not cache
            // corruption (the T06 verdict-vs-corruption distinction);
            // structurally poisoned bytes were already refetched once
            // inside fetchCRLWithCache.
            let evaluated: RevocationEvidenceResult;
            try {
                evaluated = await validateCRLEvidence(crl, {
                    cert: req.cert,
                    issuer: issuerCert,
                    checkDate: budget.checkTime,
                    clockSkewMs: this.options.clockSkewMs,
                });
            } catch (e) {
                const message = `CRL from ${url} failed: ${e instanceof Error ? e.message : String(e)}`;
                evidence.errors.push(message);
                result.errors.push(message);
                continue;
            }
            // An authenticated verdict completing past the elapsed
            // deadline is discarded (see the OCSP site): unknown with an
            // exhaustion diagnostic, no further URLs.
            if (budget.isElapsed()) {
                const message = `CRL from ${url} failed: ${budget.exhaustionError().message}`;
                evidence.errors.push(message);
                result.errors.push(message);
                return evidence;
            }
            if (evaluated.status === "unknown") {
                for (const diagnostic of evaluated.errors) {
                    const message = `CRL from ${url}: ${diagnostic}`;
                    evidence.errors.push(message);
                    result.errors.push(message);
                }
                continue;
            }
            evidence.status = evaluated.status;
            evidence.errors.push(...evaluated.errors);
            result.errors.push(...evaluated.errors);
            return evidence;
        }
        return evidence;
    }

    /**
     * Resolves the verified issuer for OCSP request building. An explicitly
     * supplied issuer must have issued the target; otherwise stored chain
     * candidates plus the other queued certificates are narrowed and
     * signature-verified. The target itself is never its own issuer.
     */
    private async resolveIssuerForOCSP(req: CertificateToValidate): Promise<pkijs.Certificate> {
        if (req.issuer) {
            if (
                !certificatesByteEqual(req.issuer, req.cert) &&
                (await verifyIssuance(req.cert, req.issuer))
            )
                return req.issuer;
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Cannot create OCSP request: supplied issuer certificate did not issue " +
                    "the target certificate"
            );
        }
        const queued = this.certificates
            .map((queued) => queued.cert)
            .filter((candidate) => !certificatesByteEqual(candidate, req.cert));
        const verified = await resolveVerifiedIssuer(req.cert, [
            ...(req.issuerCandidates ?? []),
            ...queued,
        ]);
        if (!verified) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Cannot create OCSP request: issuer certificate not found"
            );
        }
        return verified;
    }

    /**
     * Resolves the verified issuer for CRL evidence validation. An
     * explicitly supplied issuer must have issued the target; otherwise
     * stored chain candidates plus the other queued certificates are
     * narrowed and signature-verified. The target itself is never its
     * own issuer. Resolved lazily, once, after the first fetch:
     * evaluateCRLEvidence records bytes/sources first (the T05
     * preservation contract) and breaks the URL loop when resolution
     * fails, since resolution is URL-independent. Pinned by "fetches
     * but cannot validate when the issuer is missing" and "stops after
     * the first CRL when the issuer is missing" in
     * test/unit/crl-authentication.test.ts. (Unlike
     * resolveIssuerForOCSP, where resolve-before-fetch is genuine:
     * request building needs the issuer key up front.)
     */
    private async resolveIssuerForCRL(req: CertificateToValidate): Promise<pkijs.Certificate> {
        if (req.issuer) {
            if (
                !certificatesByteEqual(req.issuer, req.cert) &&
                (await verifyIssuance(req.cert, req.issuer))
            )
                return req.issuer;
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Cannot validate CRL evidence: supplied issuer certificate did not issue " +
                    "the target certificate"
            );
        }
        const queued = this.certificates
            .map((queued) => queued.cert)
            .filter((candidate) => !certificatesByteEqual(candidate, req.cert));
        const verified = await resolveVerifiedIssuer(req.cert, [
            ...(req.issuerCandidates ?? []),
            ...queued,
        ]);
        if (!verified) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Cannot validate CRL evidence: issuer certificate not found"
            );
        }
        return verified;
    }

    /**
     * Structural usability check for cached OCSP bytes. Rejects poisoned
     * entries; passing it authenticates nothing (every served response is
     * authenticated after retrieval).
     */
    private isUsableCachedOCSP(response: Uint8Array): boolean {
        try {
            parseOCSPResponse(response);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Structural usability check for cached CRL bytes. Rejects poisoned
     * entries; passing it authenticates nothing (every served CRL is
     * authenticated after retrieval).
     */
    private isUsableCachedCRL(crl: Uint8Array): boolean {
        try {
            return parseCRLInfo(crl).parsed;
        } catch {
            return false;
        }
    }

    private async fetchOCSPWithCache(
        url: string,
        request: Uint8Array,
        budget: OperationBudget
    ): Promise<Uint8Array> {
        const cached = this.options.cache.getOCSP(url, request);
        if (cached) {
            // Elapsed exhaustion refuses even free cache hits: serving
            // them would accept evidence past the completion deadline.
            if (this.isUsableCachedOCSP(cached)) {
                if (budget.isElapsed()) throw budget.exhaustionError();
                return cached;
            }
            // Rejected cached evidence is refetched once under the normal
            // operation budget; the fresh bytes overwrite the entry below.
            getLogger().debug(
                "ValidationSession: rejecting unusable cached OCSP evidence; refetching once"
            );
        }

        // A genuine built-in fetcher counts every physical attempt
        // itself (retries included) through its internal budgeted entry,
        // so it must not be claimed again here. Anything without that
        // entry -- custom fetchers -- is caller-counted as one attempt
        // per call with returned bytes counted (an approximation for
        // opaque I/O). The probe is capability (typeof), never
        // constructor identity: the supported ESM/CJS mixing gives
        // genuine instances different constructors, and the internal
        // entry self-checks for subclass overrides in its own realm
        // (falling back to the custom path itself, overrides invoked).
        // The closure hands the fetcher a fresh signal-only object, never
        // the internal live-budget context (R19).
        const fetcher = this.options.fetcher;
        const internal = fetcher as unknown as InternalBudgetedFetcher;
        const response =
            typeof internal.fetchOCSPWithBudget === "function"
                ? await internal.fetchOCSPWithBudget(url, request, budget)
                : await budget.countCustomFetch(
                      "OCSP",
                      DEFAULT_OCSP_CONFIG.maxResponseBytes,
                      ({ signal }) => fetcher.fetchOCSP(url, request, { signal })
                  );
        this.options.cache.setOCSP(url, request, response);

        return response;
    }

    private async fetchCRLWithCache(url: string, budget: OperationBudget): Promise<Uint8Array> {
        const cached = this.options.cache.getCRL(url);
        if (cached) {
            // Elapsed exhaustion refuses even free cache hits (see the
            // OCSP site).
            if (this.isUsableCachedCRL(cached)) {
                if (budget.isElapsed()) throw budget.exhaustionError();
                return cached;
            }
            // Rejected cached evidence is refetched once under the normal
            // operation budget; the fresh bytes overwrite the entry below.
            getLogger().debug(
                "ValidationSession: rejecting unusable cached CRL evidence; refetching once"
            );
        }

        // Capability probe, mirroring fetchOCSPWithCache (see above).
        const fetcher = this.options.fetcher;
        const internal = fetcher as unknown as InternalBudgetedFetcher;
        const response =
            typeof internal.fetchCRLWithBudget === "function"
                ? await internal.fetchCRLWithBudget(url, budget)
                : await budget.countCustomFetch(
                      "CRL",
                      DEFAULT_CRL_CONFIG.maxResponseBytes,
                      ({ signal }) => fetcher.fetchCRL(url, { signal })
                  );
        this.options.cache.setCRL(url, response);

        return response;
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
     * Get validation results for a specific certificate, matched by exact
     * certificate bytes. Serial twins under different issuers resolve to
     * their own results.
     */
    getResultForCert(cert: pkijs.Certificate): ValidationResult | undefined {
        if (this.state !== "completed") {
            throw new TimestampError(
                TimestampErrorCode.STATE_ERROR,
                "Validation not completed - call validateAll() first"
            );
        }
        return this.results.find((r) => certificatesByteEqual(r.cert, cert));
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
        const allCrls: Uint8Array[] = [];
        const allOcsps: Uint8Array[] = [];

        for (const result of this.results) {
            try {
                const der = result.cert.toSchema().toBER(false);
                certs.push(new Uint8Array(der));
            } catch {
                // Skip certificates that can't be serialized
            }
            for (const crl of result.crls ?? []) {
                allCrls.push(crl);
            }
            for (const ocsp of result.ocspResponses ?? []) {
                allOcsps.push(ocsp);
            }
        }

        // Dedupe by full byte-identical content so the same artifact
        // fetched for multiple certs in the chain isn't embedded twice,
        // while same-length same-prefix artifacts with different tails
        // are all retained. Binary comparison avoids hex-string memory
        // amplification over large artifacts.
        return {
            certificates: certs,
            crls: deduplicateByteArtifacts(allCrls),
            ocspResponses: deduplicateByteArtifacts(allOcsps),
        };
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
