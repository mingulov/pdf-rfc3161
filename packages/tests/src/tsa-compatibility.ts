/**
 * TSA Server Compatibility Information
 *
 * This module documents known compatibility issues with various TSA servers.
 * The library aims to be compatible with RFC 3161 compliant servers, but
 * some servers may have quirks or non-standard behaviors.
 *
 * IMPORTANT: These compatibility issues are in 3rd party servers, not in this library.
 * The library correctly implements RFC 3161 parsing. If a server returns
 * malformed responses, it's a server-side issue.
 */

export interface TSACompatibilityInfo {
    /** The URL of the TSA server */
    url: string;
    /** Known issue description */
    issue: string;
    /** When the issue was discovered */
    discovered: string;
    /** Current status: 'works' | 'incompatible' | 'unknown' */
    status: "works" | "incompatible" | "unknown";
    /** Trust list status */
    trustStatus: "QUALIFIED" | "TRUSTED" | "UNTRUSTED" | "UNKNOWN";
    /** Signature size estimation (approximate bytes for SHA-256) */
    signatureSize: {
        /** Approximate size of timestamp token without certificate */
        tokenBytes: number;
        /** Approximate size with full certificate chain */
        withCertificateBytes: number;
        /** Approximate LTV data size including certs, CRLs, OCSP */
        ltvBytes: number;
    };
    /** Error handling behavior */
    errorBehavior: {
        /** Whether server returns proper RFC 3161 error responses */
        properErrorResponse: boolean;
        /** Type of error response: 'PKIStatusInfo' | 'generic' | 'none' */
        errorResponseType: "PKIStatusInfo" | "generic" | "none" | "custom";
        /** Common error codes returned */
        commonErrors: string[];
        /** HTTP status codes used for errors */
        httpStatusBehavior: "standard" | "always200" | "nonStandard";
    };
    /** Response characteristics */
    responseCharacteristics: {
        /** Content-Type header behavior */
        contentType: "standard" | "alternative" | "missing" | "wrong";
        /** Whether certificates are included in response */
        includesCertificate: boolean;
        /** Certificate chain length (0 = none, 1 = leaf, 2+ = with intermediate(s)) */
        certificateChainLength: number;
        /** Whether nonce is echoed back correctly */
        nonceEchoed: boolean;
        /** Response time characteristics */
        responseTime: "fast" | "normal" | "slow" | "variable";
    };
    /** Feature compatibility */
    features: {
        /** SHA-256 support */
        sha256: boolean;
        /** SHA-384 support */
        sha384: boolean;
        /** SHA-512 support */
        sha512: boolean;
        /** Policy OID support */
        policyOid: boolean;
        /** CertReq flag support */
        certReq: boolean;
    };
    /** Known quirks or non-standard behaviors */
    quirks: string[];
    /** Rate limiting or usage restrictions */
    restrictions: string[];
    /** Notes about the server */
    notes: string[];
}

/**
 * Detailed compatibility information for known TSA servers.
 *
 * This data is used for comprehensive testing to ensure the library
 * handles all server behaviors correctly, including non-standard ones.
 *
 * Data sources:
 * - Live testing with LIVE_TSA_TESTS=true
 * - Server documentation and policy documents
 * - Community reports and user feedback
 * - Analysis of actual server responses
 */
export const TSA_COMPATIBILITY: TSACompatibilityInfo[] = [
    // ==================== QUALIFIED (EU Trust List) ====================
    {
        url: "http://tss.accv.es:8318/tsa",
        issue: "None - fully compliant",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "QUALIFIED",
        signatureSize: {
            tokenBytes: 1200,
            withCertificateBytes: 2800,
            ltvBytes: 12000,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["BAD_ALGORITHM", "BAD_REQUEST", "BAD_DATA_FORMAT"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "fast",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [],
        restrictions: [],
        notes: [
            "ACCV TSA (Agencia de Certificacion Electronica)",
            "Spanish government certification authority",
            "LTV enabled - full revocation data available",
        ],
    },
    {
        url: "https://timestamp.aped.gov.gr/qtss",
        issue: "None - fully compliant",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "QUALIFIED",
        signatureSize: {
            tokenBytes: 1100,
            withCertificateBytes: 2600,
            ltvBytes: 10000,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["POLICY_ERROR", "REQUEST_TOO_OLD"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "normal",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [],
        restrictions: [],
        notes: [
            "APED TSA (Hellenic Ministry of Digital Governance)",
            "Greek government public digital services",
            "EU eIDAS qualified service",
        ],
    },
    {
        url: "http://tsa.baltstamp.lt",
        issue: "None - fully compliant",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "QUALIFIED",
        signatureSize: {
            tokenBytes: 1150,
            withCertificateBytes: 2700,
            ltvBytes: 11000,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["GRANTED", "GRANTED_WITH_MODS"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "fast",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [],
        restrictions: [],
        notes: [
            "BaltStamp TSA",
            "Baltic region timestamping service",
            "LTV enabled - full revocation data available",
        ],
    },
    {
        url: "http://tsa.belgium.be/connect",
        issue: "None - fully compliant",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "QUALIFIED",
        signatureSize: {
            tokenBytes: 1200,
            withCertificateBytes: 2900,
            ltvBytes: 11500,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["SUCCESS"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 3,
            nonceEchoed: true,
            responseTime: "fast",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [],
        restrictions: [],
        notes: [
            "Belgium Federal Government TSA",
            "EU eIDAS qualified service",
            "LTV enabled - Belgian government PKI",
        ],
    },
    {
        url: "http://ts.cartaodecidadao.pt/tsa/server",
        issue: "None - fully compliant",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "QUALIFIED",
        signatureSize: {
            tokenBytes: 1100,
            withCertificateBytes: 2500,
            ltvBytes: 10500,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["OK"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "fast",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [],
        restrictions: [],
        notes: [
            "Portuguese Citizen Card TSA",
            "Portugal's Cartao de Cidadao timestamping service",
            "LTV enabled - Portuguese eIDAS qualified",
        ],
    },
    {
        url: "http://ts.quovadisglobal.com/eu",
        issue: "None - fully compliant",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "QUALIFIED",
        signatureSize: {
            tokenBytes: 1150,
            withCertificateBytes: 2800,
            ltvBytes: 11000,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["GRANTED", "GRANTED_WITH_MODS"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "normal",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: ["May return GRANTED_WITH_MODS for some requests"],
        restrictions: [],
        notes: [
            "QuoVadis EU TSA",
            "QUALIFIED - EU Trust List",
            "Swiss-based EU eIDAS compliant",
            "LTV enabled",
        ],
    },
    {
        url: "http://tsa.izenpe.com",
        issue: "None - fully compliant",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "QUALIFIED",
        signatureSize: {
            tokenBytes: 1050,
            withCertificateBytes: 2400,
            ltvBytes: 9500,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["Granted"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "fast",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [],
        restrictions: [],
        notes: [
            "Izenpe TSA",
            "Basque government CA (Instituto Vasco de Consumo)",
            "LTV enabled - EU eIDAS qualified",
        ],
    },
    {
        url: "http://timestamp.sectigo.com/qualified",
        issue: "None - fully compliant",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "QUALIFIED",
        signatureSize: {
            tokenBytes: 1250,
            withCertificateBytes: 3000,
            ltvBytes: 13000,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["granted", "grantedWithMods"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "normal",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: ["Higher assurance policy OIDs available"],
        restrictions: ["May require 15s+ delay between scripted requests"],
        notes: [
            "Sectigo Qualified TSA",
            "QUALIFIED - EU Trust List",
            "Higher assurance timestamping for EU compliance",
        ],
    },
    // ==================== TRUSTED (Adobe Trust List) ====================
    {
        url: "http://timestamp.digicert.com",
        issue: "None - fully compliant",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "TRUSTED",
        signatureSize: {
            tokenBytes: 1000,
            withCertificateBytes: 2200,
            ltvBytes: 8500,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["0", "1"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "fast",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [],
        restrictions: [],
        notes: [
            "DigiCert TSA",
            "Trusted by Adobe",
            "Widely used commercial TSA",
            "Excellent reliability",
        ],
    },
    {
        url: "https://timestamp.sectigo.com",
        issue: "None - fully compliant",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "TRUSTED",
        signatureSize: {
            tokenBytes: 1100,
            withCertificateBytes: 2500,
            ltvBytes: 10000,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["granted", "grantedWithMods"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "normal",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [],
        restrictions: ["Requires 15s+ delay between scripted requests"],
        notes: ["Sectigo TSA", "Trusted by Adobe", "Commercial, widely trusted"],
    },
    {
        url: "http://timestamp.comodoca.com",
        issue: "None - fully compliant",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "TRUSTED",
        signatureSize: {
            tokenBytes: 1100,
            withCertificateBytes: 2500,
            ltvBytes: 10000,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["granted", "grantedWithMods"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "normal",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [],
        restrictions: ["Requires 15s+ delay between scripted requests"],
        notes: [
            "Comodo TSA (Sectigo legacy endpoint)",
            "Trusted by Adobe",
            "Legacy endpoint for backward compatibility",
        ],
    },
    {
        url: "http://timestamp.entrust.net/TSS/RFC3161sha2TS",
        issue: "None - fully compliant",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "TRUSTED",
        signatureSize: {
            tokenBytes: 1300,
            withCertificateBytes: 3200,
            ltvBytes: 14000,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["granted", "grantedWithMods"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 3,
            nonceEchoed: true,
            responseTime: "normal",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: ["Longer certificate chain"],
        restrictions: [],
        notes: ["Entrust TSA", "Trusted by Adobe (issued by Sectigo)", "LTV enabled"],
    },
    {
        url: "http://timestamp.identrust.com",
        issue: "None - fully compliant",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "TRUSTED",
        signatureSize: {
            tokenBytes: 1050,
            withCertificateBytes: 2300,
            ltvBytes: 9000,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["0", "1"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "normal",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [],
        restrictions: [],
        notes: [
            "IdenTrust Time Stamping Authority",
            "Trusted by Adobe",
            "Commercial TSA, widely recognized in US",
        ],
    },
    {
        url: "http://ts.ssl.com",
        issue: "None - fully compliant",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "TRUSTED",
        signatureSize: {
            tokenBytes: 1000,
            withCertificateBytes: 2200,
            ltvBytes: 8500,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["0", "1"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "fast",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [],
        restrictions: [],
        notes: ["SSL.com TSA", "Trusted by Adobe", "Commercial CA and trust service provider"],
    },
    {
        url: "http://tsa.swisssign.net",
        issue: "None - fully compliant",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "TRUSTED",
        signatureSize: {
            tokenBytes: 1150,
            withCertificateBytes: 2700,
            ltvBytes: 11000,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["granted", "grantedWithMods"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "normal",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [],
        restrictions: [],
        notes: [
            "SwissSign TSA",
            "Trusted by Adobe",
            "Swiss trust service provider, EU eIDAS compliant",
        ],
    },
    {
        url: "https://tsa.wotrus.com",
        issue: "None - fully compliant",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "TRUSTED",
        signatureSize: {
            tokenBytes: 1000,
            withCertificateBytes: 2200,
            ltvBytes: 8500,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["0", "1"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "fast",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [],
        restrictions: [],
        notes: [
            "WoTrust TSA",
            "Trusted by Adobe",
            "Commercial trust service provider",
            "May have absorbed mesign.com traffic",
        ],
    },
    // ==================== UNTRUSTED ====================
    {
        url: "http://timestamp.apple.com/ts01",
        issue: "UNTRUSTED - works but not on trust lists",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "UNTRUSTED",
        signatureSize: {
            tokenBytes: 900,
            withCertificateBytes: 1800,
            ltvBytes: 7000,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["granted"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 1,
            nonceEchoed: true,
            responseTime: "variable",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: false,
            certReq: true,
        },
        quirks: ["Limited policy OID support", "Rate limiting for bulk requests"],
        restrictions: ["May throttle high-volume requests"],
        notes: [
            "Apple's official Time Stamp Service",
            "UNTRUSTED - not on Adobe or EU trust lists",
            "HTTP endpoint",
        ],
    },
    {
        url: "http://time.certum.pl",
        issue: "UNTRUSTED - works but not on trust lists",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "UNTRUSTED",
        signatureSize: {
            tokenBytes: 950,
            withCertificateBytes: 2000,
            ltvBytes: 8000,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["0", "1"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "fast",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [],
        restrictions: [],
        notes: ["Certum TSA (Asseco)", "UNTRUSTED - not on Adobe or EU trust lists", "Polish TSA"],
    },
    {
        url: "http://timestamp.globalsign.com/tsa/r6advanced1",
        issue: "UNTRUSTED - works but not on trust lists",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "UNTRUSTED",
        signatureSize: {
            tokenBytes: 1000,
            withCertificateBytes: 2200,
            ltvBytes: 9000,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["granted", "grantedWithMods"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "normal",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [],
        restrictions: [],
        notes: [
            "GlobalSign TSA",
            "UNTRUSTED - not on Adobe or EU trust lists",
            "Commercial, widely used",
        ],
    },
    {
        url: "https://freetsa.org/tsr",
        issue: "UNTRUSTED - self-signed CA",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "UNTRUSTED",
        signatureSize: {
            tokenBytes: 800,
            withCertificateBytes: 1500,
            ltvBytes: 5000,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["2"], // REJECTION
            httpStatusBehavior: "always200",
        },
        responseCharacteristics: {
            contentType: "alternative",
            includesCertificate: true,
            certificateChainLength: 1,
            nonceEchoed: true,
            responseTime: "normal",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [
            "Self-signed CA - not trusted by default",
            "Correctly rejects non-hash data with status=2 (REJECTION)",
        ],
        restrictions: [],
        notes: [
            "FreeTSA",
            "UNTRUSTED - not on Adobe or EU trust lists",
            "Free community TSA",
            "Uses self-signed CA",
        ],
    },
    {
        url: "http://tsa.izenpe.com",
        issue: "UNTRUSTED - works but not on Adobe list",
        discovered: "2026-01-11",
        status: "works",
        trustStatus: "QUALIFIED",
        signatureSize: {
            tokenBytes: 1050,
            withCertificateBytes: 2400,
            ltvBytes: 9500,
        },
        errorBehavior: {
            properErrorResponse: true,
            errorResponseType: "PKIStatusInfo",
            commonErrors: ["Granted"],
            httpStatusBehavior: "standard",
        },
        responseCharacteristics: {
            contentType: "standard",
            includesCertificate: true,
            certificateChainLength: 2,
            nonceEchoed: true,
            responseTime: "fast",
        },
        features: {
            sha256: true,
            sha384: true,
            sha512: true,
            policyOid: true,
            certReq: true,
        },
        quirks: [],
        restrictions: [],
        notes: ["Izenpe TSA", "QUALIFIED - EU Trust List", "Basque government CA"],
    },
    // ==================== NOT WORKING ====================
    {
        url: "http://tsa.mesign.com",
        issue: "Not working - timeout/crash",
        discovered: "2026-01-11",
        status: "incompatible",
        trustStatus: "UNTRUSTED",
        signatureSize: {
            tokenBytes: 0,
            withCertificateBytes: 0,
            ltvBytes: 0,
        },
        errorBehavior: {
            properErrorResponse: false,
            errorResponseType: "none",
            commonErrors: ["timeout"],
            httpStatusBehavior: "nonStandard",
        },
        responseCharacteristics: {
            contentType: "missing",
            includesCertificate: false,
            certificateChainLength: 0,
            nonceEchoed: false,
            responseTime: "slow",
        },
        features: {
            sha256: false,
            sha384: false,
            sha512: false,
            policyOid: false,
            certReq: false,
        },
        quirks: ["Service appears to have moved or discontinued"],
        restrictions: ["Service unavailable"],
        notes: [
            "Mesign TSA - NOT WORKING",
            "Timeout/crash reported",
            "Traffic may have moved to https://tsa.wotrus.com",
        ],
    },
    {
        url: "https://tsp.iaik.tugraz.at/tsp/TspRequest",
        issue: "Not working - error response",
        discovered: "2026-01-11",
        status: "incompatible",
        trustStatus: "UNTRUSTED",
        signatureSize: {
            tokenBytes: 0,
            withCertificateBytes: 0,
            ltvBytes: 0,
        },
        errorBehavior: {
            properErrorResponse: false,
            errorResponseType: "custom",
            commonErrors: ["server_error"],
            httpStatusBehavior: "nonStandard",
        },
        responseCharacteristics: {
            contentType: "wrong",
            includesCertificate: false,
            certificateChainLength: 0,
            nonceEchoed: false,
            responseTime: "fast",
        },
        features: {
            sha256: false,
            sha384: false,
            sha512: false,
            policyOid: false,
            certReq: false,
        },
        quirks: ["Returns non-standard error format"],
        restrictions: ["Service not functioning correctly"],
        notes: [
            "IAIK TU Graz TSA - NOT WORKING",
            "Academic/research TSA from Graz University of Technology",
            "Returns error responses",
        ],
    },
    {
        url: "http://tsa.safecreative.org",
        issue: "Not working - timeout/crash",
        discovered: "2026-01-11",
        status: "incompatible",
        trustStatus: "UNTRUSTED",
        signatureSize: {
            tokenBytes: 0,
            withCertificateBytes: 0,
            ltvBytes: 0,
        },
        errorBehavior: {
            properErrorResponse: false,
            errorResponseType: "none",
            commonErrors: ["timeout"],
            httpStatusBehavior: "nonStandard",
        },
        responseCharacteristics: {
            contentType: "missing",
            includesCertificate: false,
            certificateChainLength: 0,
            nonceEchoed: false,
            responseTime: "slow",
        },
        features: {
            sha256: false,
            sha384: false,
            sha512: false,
            policyOid: false,
            certReq: false,
        },
        quirks: ["Service appears to be discontinued"],
        restrictions: ["Service unavailable"],
        notes: ["SafeCreative TSA - NOT WORKING", "Timeout/crash reported"],
    },
    {
        url: "http://tsa.sep.bg",
        issue: "Not working - service gone",
        discovered: "2026-01-11",
        status: "incompatible",
        trustStatus: "UNTRUSTED",
        signatureSize: {
            tokenBytes: 0,
            withCertificateBytes: 0,
            ltvBytes: 0,
        },
        errorBehavior: {
            properErrorResponse: false,
            errorResponseType: "none",
            commonErrors: ["not_found"],
            httpStatusBehavior: "nonStandard",
        },
        responseCharacteristics: {
            contentType: "missing",
            includesCertificate: false,
            certificateChainLength: 0,
            nonceEchoed: false,
            responseTime: "slow",
        },
        features: {
            sha256: false,
            sha384: false,
            sha512: false,
            policyOid: false,
            certReq: false,
        },
        quirks: ["Service has been discontinued"],
        restrictions: ["Service no longer available"],
        notes: ["SEP BG TSA - NOT WORKING", "Timeout - service gone"],
    },
    {
        url: "https://sha256timestamp.ws.symantec.com/sha256/timestamp",
        issue: "Not working - timeout/error",
        discovered: "2026-01-11",
        status: "incompatible",
        trustStatus: "UNTRUSTED",
        signatureSize: {
            tokenBytes: 0,
            withCertificateBytes: 0,
            ltvBytes: 0,
        },
        errorBehavior: {
            properErrorResponse: false,
            errorResponseType: "generic",
            commonErrors: ["internal_error"],
            httpStatusBehavior: "nonStandard",
        },
        responseCharacteristics: {
            contentType: "wrong",
            includesCertificate: false,
            certificateChainLength: 0,
            nonceEchoed: false,
            responseTime: "slow",
        },
        features: {
            sha256: false,
            sha384: false,
            sha512: false,
            policyOid: false,
            certReq: false,
        },
        quirks: ["Symantec has deprecated this service"],
        restrictions: ["Service deprecated"],
        notes: [
            "Symantec TSA - NOT WORKING",
            "Timeout/error reported",
            "Service may have been discontinued after Broadcom acquisition",
        ],
    },
    {
        url: "http://psis.catcert.cat/psis/catcert/tsp",
        issue: "Not working - timeout",
        discovered: "2026-01-11",
        status: "incompatible",
        trustStatus: "UNTRUSTED",
        signatureSize: {
            tokenBytes: 0,
            withCertificateBytes: 0,
            ltvBytes: 0,
        },
        errorBehavior: {
            properErrorResponse: false,
            errorResponseType: "none",
            commonErrors: ["timeout"],
            httpStatusBehavior: "nonStandard",
        },
        responseCharacteristics: {
            contentType: "missing",
            includesCertificate: false,
            certificateChainLength: 0,
            nonceEchoed: false,
            responseTime: "slow",
        },
        features: {
            sha256: false,
            sha384: false,
            sha512: false,
            policyOid: false,
            certReq: false,
        },
        quirks: ["Catalan government service may have changed"],
        restrictions: ["Service unavailable"],
        notes: ["CatCert TSA - NOT WORKING", "Timeout reported", "Catalan government service"],
    },
];

/**
 * Map of incompatible TSA URLs for quick lookup
 */
export const INCOMPATIBLE_TSA_URLS: Set<string> = new Set<string>(
    TSA_COMPATIBILITY.filter((info) => info.status === "incompatible").map((info) => info.url)
);

/**
 * Check if a TSA URL is known to have compatibility issues
 */
export function isTSACompatible(url: string): boolean {
    return !INCOMPATIBLE_TSA_URLS.has(url);
}

/**
 * Get compatibility info for a TSA URL
 */
export function getTSACompatibility(url: string): TSACompatibilityInfo | undefined {
    return TSA_COMPATIBILITY.find((info) => info.url === url);
}
