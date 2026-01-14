import * as pkijs from "pkijs";
import { CertificateStatus } from "../pki/ocsp-utils.js";

export { CertificateStatus };

export const VALIDATION_CONTRACTS_VERSION = "1.0.0";

export enum ValidationStatus {
    VALID = "VALID",
    INVALID = "INVALID",
    INDETERMINATE = "INDETERMINATE",
    PENDING_REVOCATION_CHECK = "PENDING_REVOCATION_CHECK",
}

export enum ValidationErrorCode {
    NO_ERROR = "NO_ERROR",
    EXPIRED_CERTIFICATE = "EXPIRED_CERTIFICATE",
    NOT_YET_VALID = "NOT_YET_VALID",
    REVOKED = "REVOKED",
    TRUST_ANCHOR_MISSING = "TRUST_ANCHOR_MISSING",
    INCOMPLETE_CHAIN = "INCOMPLETE_CHAIN",
    INVALID_SIGNATURE = "INVALID_SIGNATURE",
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM",
    OCSP_FETCH_FAILED = "OCSP_FETCH_FAILED",
    CRL_FETCH_FAILED = "CRL_FETCH_FAILED",
    CERTIFICATE_FETCH_FAILED = "CERTIFICATE_FETCH_FAILED",
    AIA_FETCH_TIMEOUT = "AIA_FETCH_TIMEOUT",
    MAX_CHAIN_DEPTH_EXCEEDED = "MAX_CHAIN_DEPTH_EXCEEDED",
    MISSING_SIGNING_CERTIFICATE_ATTR = "MISSING_SIGNING_CERTIFICATE_ATTR",
    ESS_CERT_ID_MISMATCH = "ESS_CERT_ID_MISMATCH",
    TIMESTAMP_MISMATCH = "TIMESTAMP_MISMATCH",
    REVOCATION_STATUS_UNKNOWN = "REVOCATION_STATUS_UNKNOWN",
    UNKNOWN = "UNKNOWN",
}

export enum ValidationWarningCode {
    NO_WARNING = "NO_WARNING",
    WEAK_ALGORITHM = "WEAK_ALGORITHM",
    EXPIRING_SOON = "EXPIRING_SOON",
    REVOCATION_STATUS_UNKNOWN = "REVOCATION_STATUS_UNKNOWN",
    PARTIAL_CHAIN = "PARTIAL_CHAIN",
    AIA_NOT_FOUND = "AIA_NOT_FOUND",
    CACHED_RESPONSE_USED = "CACHED_RESPONSE_USED",
    NON_TLS_TRUST_ANCHOR = "NON_TLS_TRUST_ANCHOR",
}

export interface ValidationEvent {
    type: "info" | "warning" | "error" | "debug";
    timestamp: Date;
    category: string;
    code: string | ValidationErrorCode | ValidationWarningCode;
    message: string;
    context?: Record<string, unknown>;
}

export interface ChainNode {
    certificate: pkijs.Certificate;
    isTrusted: boolean;
    isSelfSigned: boolean;
    issuer?: ChainNode;
    subject: string;
    serialNumber: string;
    notBefore: Date;
    notAfter: Date;
}

export interface CertificateChain {
    nodes: ChainNode[];
    complete: boolean;
    trustedRoot?: ChainNode;
    depth: number;
}

export interface RevocationInfo {
    type: "OCSP" | "CRL";
    url: string;
    status: CertificateStatus | "UNKNOWN" | "ERROR";
    thisUpdate?: Date;
    nextUpdate?: Date;
    rawResponse: Uint8Array;
    source: "NETWORK" | "CACHE" | "EMBEDDED";
}

export interface ValidationDetail {
    stage:
        | "CHAIN_BUILDING"
        | "REVOCATION_CHECK"
        | "SIGNATURE_VERIFICATION"
        | "ESS_VALIDATION"
        | "TIMESTAMP_MATCH";
    status: ValidationStatus;
    errorCode?: ValidationErrorCode;
    warningCode?: ValidationWarningCode;
    message?: string;
    details?: Record<string, unknown>;
}

export interface RichValidationResult {
    overallStatus: ValidationStatus;
    isValid: boolean;
    certificateChain?: CertificateChain;
    revocationInfo: RevocationInfo[];
    details: ValidationDetail[];
    errors: ValidationErrorCode[];
    warnings: ValidationWarningCode[];
    events: ValidationEvent[];
    timestamp?: Date;
    validatedAt: Date;
    profile?: string;
    strictnessLevel?: number;
}

export interface ITrustStore {
    addCertificate(cert: Uint8Array | pkijs.Certificate): void;
    addCertificates(certs: (Uint8Array | pkijs.Certificate)[]): void;
    removeCertificate(cert: Uint8Array | pkijs.Certificate): void;
    clear(): void;
    contains(cert: pkijs.Certificate): boolean;
    verifyChain(chain: (Uint8Array | pkijs.Certificate)[]): Promise<RichValidationResult>;
    getTrustedCertificates(): pkijs.Certificate[];
}

export interface FetcherOptions {
    timeout?: number;
    maxRetries?: number;
    userAgent?: string;
    headers?: Record<string, string>;
}

export interface IFetcher {
    fetchCertificate(url: string, options?: FetcherOptions): Promise<Uint8Array>;
    fetchOCSP(url: string, request: Uint8Array, options?: FetcherOptions): Promise<Uint8Array>;
    fetchCRL(url: string, options?: FetcherOptions): Promise<Uint8Array>;
}

export interface IValidationCache {
    getCertificate(url: string): Uint8Array | null;
    setCertificate(url: string, cert: Uint8Array): void;
    getOCSP(url: string, request: Uint8Array): Uint8Array | null;
    setOCSP(url: string, request: Uint8Array, response: Uint8Array): void;
    getCRL(url: string): Uint8Array | null;
    setCRL(url: string, crl: Uint8Array): void;
    clear(): void;
    size(): number;
}

export interface ChainBuilderOptions {
    maxDepth?: number;
    enableAIAFetching?: boolean;
    fetcher?: IFetcher;
    cache?: IValidationCache;
    allowedCAIssuers?: string[];
    blockedCAIssuers?: string[];
}

export interface IChainBuilder {
    buildChain(
        leafCertificate: pkijs.Certificate,
        options?: ChainBuilderOptions
    ): Promise<CertificateChain>;
    findIssuer(
        cert: pkijs.Certificate,
        knownCerts: pkijs.Certificate[]
    ): pkijs.Certificate | undefined;
}

export interface RevocationCheckerOptions {
    preferOCSP?: boolean;
    allowCRLFallback?: boolean;
    fetcher?: IFetcher;
    cache?: IValidationCache;
    timeout?: number;
}

export interface IRevocationChecker {
    checkRevocation(
        certificate: pkijs.Certificate,
        issuer: pkijs.Certificate,
        options?: RevocationCheckerOptions
    ): Promise<RevocationInfo | null>;
    checkChainRevocation(
        chain: CertificateChain,
        options?: RevocationCheckerOptions
    ): Promise<RevocationInfo[]>;
}

export interface ValidationOptions {
    trustStore?: ITrustStore;
    chainBuilder?: IChainBuilder;
    revocationChecker?: IRevocationChecker;
    fetcher?: IFetcher;
    cache?: IValidationCache;
    strictnessLevel?: 1 | 2 | 3 | 4;
    profile?: PadesProfileType;
    requireESSSigningCertificate?: boolean;
    expectedTimestamp?: Date;
    maxChainDepth?: number;
    requireRevocationCheck?: boolean;
    allowExpiredCertificates?: boolean;
    eventCallback?: (event: ValidationEvent) => void;
}

export enum PadesProfileType {
    BASIC = "PAdES-BASIC",
    LT = "PAdES-LT",
    LTA = "PAdES-LTA",
    B_BASELINE = "PAdES-B-BASELINE",
    B_LT = "PAdES-B-LT",
    B_LTA = "PAdES-B-LTA",
    LL_T = "PAdES-LL-T",
    LL_LTA = "PAdES-LL-LTA",
}

export interface PadesProfile {
    type: PadesProfileType;
    displayName: string;
    description: string;
    requirements: ProfileRequirement[];
    strictnessLevel: 1 | 2 | 3 | 4;
}

export interface ProfileRequirement {
    rule: string;
    description: string;
    severity: "error" | "warning" | "info";
    check: (result: RichValidationResult) => boolean;
}

export const PADES_PROFILES: Record<PadesProfileType, PadesProfile> = {
    [PadesProfileType.BASIC]: {
        type: PadesProfileType.BASIC,
        displayName: "PAdES Basic",
        description: "Basic PDF signature with timestamp support",
        requirements: [
            {
                rule: "SIGNATURE_PRESENT",
                description: "PDF signature must be present",
                severity: "error",
                check: (r) =>
                    r.details.some(
                        (d) =>
                            d.stage === "SIGNATURE_VERIFICATION" &&
                            d.status === ValidationStatus.VALID
                    ),
            },
        ],
        strictnessLevel: 1,
    },
    [PadesProfileType.LT]: {
        type: PadesProfileType.LT,
        displayName: "PAdES Long-Term",
        description: "PDF signature with embedded validation data (DSS)",
        requirements: [
            {
                rule: "SIGNATURE_PRESENT",
                description: "PDF signature must be present",
                severity: "error",
                check: (r) =>
                    r.details.some(
                        (d) =>
                            d.stage === "SIGNATURE_VERIFICATION" &&
                            d.status === ValidationStatus.VALID
                    ),
            },
            {
                rule: "CERTIFICATES_EMBEDDED",
                description: "Certificates must be embedded",
                severity: "error",
                check: (r) => !!r.certificateChain && r.certificateChain.nodes.length > 0,
            },
        ],
        strictnessLevel: 2,
    },
    [PadesProfileType.LTA]: {
        type: PadesProfileType.LTA,
        displayName: "PAdES Long-Term with Archive",
        description: "PAdES-LT with document timestamp for long-term preservation",
        requirements: [
            {
                rule: "SIGNATURE_PRESENT",
                description: "PDF signature must be present",
                severity: "error",
                check: (r) =>
                    r.details.some(
                        (d) =>
                            d.stage === "SIGNATURE_VERIFICATION" &&
                            d.status === ValidationStatus.VALID
                    ),
            },
            {
                rule: "CERTIFICATES_EMBEDDED",
                description: "Certificates must be embedded",
                severity: "error",
                check: (r) => !!r.certificateChain && r.certificateChain.nodes.length > 0,
            },
            {
                rule: "REVOCATION_CHECKED",
                description: "Revocation must be checked",
                severity: "error",
                check: (r) =>
                    r.revocationInfo.length > 0 ||
                    r.errors.includes(ValidationErrorCode.REVOCATION_STATUS_UNKNOWN),
            },
        ],
        strictnessLevel: 3,
    },
    [PadesProfileType.B_BASELINE]: {
        type: PadesProfileType.B_BASELINE,
        displayName: "PAdES B-Baseline",
        description: "Baseline profile with basic requirements",
        requirements: [
            {
                rule: "SIGNATURE_PRESENT",
                description: "PDF signature must be present",
                severity: "error",
                check: (r) =>
                    r.details.some(
                        (d) =>
                            d.stage === "SIGNATURE_VERIFICATION" &&
                            d.status === ValidationStatus.VALID
                    ),
            },
            {
                rule: "ESS_SIGNING_CERTIFICATE_PRESENT",
                description: "ESS Signing Certificate attribute must be present",
                severity: "error",
                check: (r) =>
                    !r.errors.includes(ValidationErrorCode.MISSING_SIGNING_CERTIFICATE_ATTR),
            },
        ],
        strictnessLevel: 2,
    },
    [PadesProfileType.B_LT]: {
        type: PadesProfileType.B_LT,
        displayName: "PAdES B-LT",
        description: "Baseline profile with Long-Term validation",
        requirements: [
            {
                rule: "SIGNATURE_PRESENT",
                description: "PDF signature must be present",
                severity: "error",
                check: (r) =>
                    r.details.some(
                        (d) =>
                            d.stage === "SIGNATURE_VERIFICATION" &&
                            d.status === ValidationStatus.VALID
                    ),
            },
            {
                rule: "ESS_SIGNING_CERTIFICATE_PRESENT",
                description: "ESS Signing Certificate attribute must be present",
                severity: "error",
                check: (r) =>
                    !r.errors.includes(ValidationErrorCode.MISSING_SIGNING_CERTIFICATE_ATTR),
            },
            {
                rule: "CERTIFICATES_EMBEDDED",
                description: "Certificates must be embedded",
                severity: "error",
                check: (r) => !!r.certificateChain && r.certificateChain.nodes.length > 0,
            },
        ],
        strictnessLevel: 3,
    },
    [PadesProfileType.B_LTA]: {
        type: PadesProfileType.B_LTA,
        displayName: "PAdES B-LTA",
        description: "Baseline profile with Long-Term validation and archive",
        requirements: [
            {
                rule: "SIGNATURE_PRESENT",
                description: "PDF signature must be present",
                severity: "error",
                check: (r) =>
                    r.details.some(
                        (d) =>
                            d.stage === "SIGNATURE_VERIFICATION" &&
                            d.status === ValidationStatus.VALID
                    ),
            },
            {
                rule: "ESS_SIGNING_CERTIFICATE_PRESENT",
                description: "ESS Signing Certificate attribute must be present",
                severity: "error",
                check: (r) =>
                    !r.errors.includes(ValidationErrorCode.MISSING_SIGNING_CERTIFICATE_ATTR),
            },
            {
                rule: "CERTIFICATES_EMBEDDED",
                description: "Certificates must be embedded",
                severity: "error",
                check: (r) => !!r.certificateChain && r.certificateChain.nodes.length > 0,
            },
            {
                rule: "REVOCATION_CHECKED",
                description: "Revocation must be checked",
                severity: "error",
                check: (r) =>
                    r.revocationInfo.length > 0 ||
                    r.errors.includes(ValidationErrorCode.REVOCATION_STATUS_UNKNOWN),
            },
        ],
        strictnessLevel: 4,
    },
    [PadesProfileType.LL_T]: {
        type: PadesProfileType.LL_T,
        displayName: "PAdES LL-T",
        description: "Legacy Long-Term with document timestamp",
        requirements: [
            {
                rule: "SIGNATURE_PRESENT",
                description: "PDF signature must be present",
                severity: "error",
                check: (r) =>
                    r.details.some(
                        (d) =>
                            d.stage === "SIGNATURE_VERIFICATION" &&
                            d.status === ValidationStatus.VALID
                    ),
            },
            {
                rule: "DOCUMENT_TIMESTAMP",
                description: "Document timestamp must be present",
                severity: "error",
                check: (r) => !!r.timestamp,
            },
        ],
        strictnessLevel: 2,
    },
    [PadesProfileType.LL_LTA]: {
        type: PadesProfileType.LL_LTA,
        displayName: "PAdES LL-LTA",
        description: "Legacy Long-Term with archive timestamps",
        requirements: [
            {
                rule: "SIGNATURE_PRESENT",
                description: "PDF signature must be present",
                severity: "error",
                check: (r) =>
                    r.details.some(
                        (d) =>
                            d.stage === "SIGNATURE_VERIFICATION" &&
                            d.status === ValidationStatus.VALID
                    ),
            },
            {
                rule: "DOCUMENT_TIMESTAMP",
                description: "Document timestamp must be present",
                severity: "error",
                check: (r) => !!r.timestamp,
            },
            {
                rule: "CERTIFICATES_EMBEDDED",
                description: "Certificates must be embedded",
                severity: "error",
                check: (r) => !!r.certificateChain && r.certificateChain.nodes.length > 0,
            },
            {
                rule: "REVOCATION_CHECKED",
                description: "Revocation must be checked",
                severity: "error",
                check: (r) =>
                    r.revocationInfo.length > 0 ||
                    r.errors.includes(ValidationErrorCode.REVOCATION_STATUS_UNKNOWN),
            },
        ],
        strictnessLevel: 3,
    },
};

export interface IValidationEngine {
    validate(
        timestampToken: Uint8Array,
        options?: ValidationOptions
    ): Promise<RichValidationResult>;
    validatePdf(pdfBytes: Uint8Array, options?: ValidationOptions): Promise<RichValidationResult>;
    getProfile(profile: PadesProfileType): PadesProfile | undefined;
    checkProfileCompliance(
        result: RichValidationResult,
        profile: PadesProfileType
    ): { compliant: boolean; failedRequirements: ProfileRequirement[] };
}

export interface ChainValidatorConfig {
    trustStore?: ITrustStore;
    fetcher?: IFetcher;
    cache?: IValidationCache;
    maxChainDepth?: number;
    enableRevocationCheck?: boolean;
    revocationOptions?: RevocationCheckerOptions;
    strictnessLevel?: 1 | 2 | 3 | 4;
    eventCallback?: (event: ValidationEvent) => void;
}

export type {
    ValidationSessionOptions,
    CertificateToValidate,
    ValidationResult,
    RevocationDataFetcher,
    ValidationCache,
} from "../pki/validation-types.js";
