# PDF RFC 3161 Validation API Documentation

## Overview

This document describes the new contract-first validation API introduced in version 0.2.0. The API provides a comprehensive, extensible framework for validating RFC 3161 timestamps and PAdES-compliant signatures.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    ValidationEngine                              │
│  (Main entry point for all validation operations)                │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────┐ │
│  │   ChainBuilder   │  │RevocationChecker │  │ PadesProfile   │ │
│  │   (AIA fetching) │  │  (OCSP/CRL)      │  │  (Compliance)  │ │
│  └──────────────────┘  └──────────────────┘  └────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                    IFetcher / IValidationCache                   │
│  (Pluggable network and caching implementations)                 │
└─────────────────────────────────────────────────────────────────┘
```

## Core Interfaces

### IValidationEngine

The main interface for performing timestamp and PDF validation.

```typescript
interface IValidationEngine {
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
```

**Usage Example:**

```typescript
import { createValidationEngine, PadesProfileType } from "pdf-rfc3161";

const engine = createValidationEngine();

const result = await engine.validatePdf(pdfBytes, {
    trustStore: myTrustStore,
    profile: PadesProfileType.B_LTA,
    strictnessLevel: 3,
});

if (result.overallStatus === "VALID") {
    console.log("Timestamp is valid");
    console.log(
        `Profile compliance: ${engine.checkProfileCompliance(result, PadesProfileType.B_LTA).compliant}`
    );
}
```

### IFetcher

Pluggable network fetcher interface for custom HTTP behavior.

```typescript
interface IFetcher {
    fetchCertificate(url: string, options?: FetcherOptions): Promise<Uint8Array>;
    fetchOCSP(url: string, request: Uint8Array, options?: FetcherOptions): Promise<Uint8Array>;
    fetchCRL(url: string, options?: FetcherOptions): Promise<Uint8Array>;
}
```

**Custom Fetcher Example:**

```typescript
class CustomFetcher implements IFetcher {
    async fetchCertificate(url: string): Promise<Uint8Array> {
        const response = await fetch(url, { headers: { "User-Agent": "MyApp/1.0" } });
        return new Uint8Array(await response.arrayBuffer());
    }
    // ... implement other methods
}
```

### IValidationCache

Interface for caching revocation data to improve performance.

```typescript
interface IValidationCache {
    getCertificate(url: string): Uint8Array | null;
    setCertificate(url: string, cert: Uint8Array): void;
    getOCSP(url: string, request: Uint8Array): Uint8Array | null;
    setOCSP(url: string, request: Uint8Array, response: Uint8Array): void;
    getCRL(url: string): Uint8Array | null;
    setCRL(url: string, crl: Uint8Array): void;
    clear(): void;
}
```

## RichValidationResult

The comprehensive validation result type with detailed information.

```typescript
interface RichValidationResult {
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
```

### ValidationStatus Enum

```typescript
enum ValidationStatus {
    VALID = "VALID",
    INVALID = "INVALID",
    INDETERMINATE = "INDETERMINATE",
    PENDING_REVOCATION_CHECK = "PENDING_REVOCATION_CHECK",
}
```

### ValidationErrorCode Enum

```typescript
enum ValidationErrorCode {
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
```

## PAdES Profile Support

The API includes predefined PAdES profiles for common compliance requirements.

### Available Profiles

| Profile          | Type             | Description            | Strictness |
| ---------------- | ---------------- | ---------------------- | ---------- |
| PAdES-BASIC      | PAdES-BASIC      | Basic PDF signature    | 1          |
| PAdES-LT         | PAdES-LT         | Long-Term with DSS     | 2          |
| PAdES-LTA        | PAdES-LTA        | Long-Term with Archive | 3          |
| PAdES-B-BASELINE | PAdES-B-BASELINE | Baseline profile       | 2          |
| PAdES-B-LT       | PAdES-B-LT       | Baseline + LTV         | 3          |
| PAdES-B-LTA      | PAdES-B-LTA      | Baseline + Archive     | 4          |
| PAdES-LL-T       | PAdES-LL-T       | Legacy Long-Term       | 2          |
| PAdES-LL-LTA     | PAdES-LL-LTA     | Legacy Archive         | 3          |

### Profile Validation Example

```typescript
import { createValidationEngine, PadesProfileType } from "pdf-rfc3161";

const engine = createValidationEngine();

const result = await engine.validatePdf(pdfBytes, {
    profile: PadesProfileType.B_LTA,
});

const compliance = engine.checkProfileCompliance(result, PadesProfileType.B_LTA);

if (!compliance.compliant) {
    console.log("Failed requirements:");
    for (const req of compliance.failedRequirements) {
        console.log(`  - ${req.rule}: ${req.description}`);
    }
}
```

## ChainValidator

Low-level API for certificate chain validation.

```typescript
import { ChainValidator, createSimpleTrustStore } from "pdf-rfc3161";

const validator = new ChainValidator({
    maxChainDepth: 10,
    enableRevocationCheck: true,
});

const result = await validator.validateChain(leafCertificate, trustStore);

console.log(`Chain complete: ${result.chain.complete}`);
console.log(`Depth: ${result.chain.depth}`);
console.log(`Errors: ${result.errors}`);
```

## Events and Observability

The validation engine supports event callbacks for monitoring and debugging.

```typescript
const result = await engine.validatePdf(pdfBytes, {
    eventCallback: (event) => {
        console.log(`[${event.timestamp.toISOString()}] ${event.category}: ${event.message}`);
    },
});
```

## Migration from Legacy API

### Before (v0.1.x)

```typescript
import { verifyTimestamp, extractTimestamps } from "pdf-rfc3161";

const timestamps = await extractTimestamps(pdfBytes);
if (timestamps.length > 0) {
    const verified = await verifyTimestamp(timestamps[0]);
    // Limited validation result
}
```

### After (v0.2.0)

```typescript
import { createValidationEngine } from "pdf-rfc3161";

const engine = createValidationEngine();
const result = await engine.validatePdf(pdfBytes, {
    trustStore: myTrustStore,
    profile: "PAdES-B-LTA",
    strictnessLevel: 4,
});

// Rich result with detailed error information
if (result.isValid) {
    console.log("Valid timestamp");
    console.log(`Certificate chain depth: ${result.certificateChain?.depth}`);
    console.log(`Revocation checks: ${result.revocationInfo.length}`);
}
```

## Complete Example

```typescript
import {
    createValidationEngine,
    PadesProfileType,
    InMemoryValidationCache,
    DefaultFetcher,
} from "pdf-rfc3161";

async function validatePdfWithFullChecking(pdfBytes: Uint8Array) {
    const engine = createValidationEngine({
        trustStore: defaultTrustStore,
        requireRevocationCheck: true,
        maxChainDepth: 10,
    });

    const result = await engine.validatePdf(pdfBytes, {
        profile: PadesProfileType.B_LTA,
        strictnessLevel: 4,
        cache: new InMemoryValidationCache(),
        fetcher: new DefaultFetcher(),
        eventCallback: (event) => {
            console.log(`[${event.category}] ${event.message}`);
        },
    });

    if (result.overallStatus === "VALID") {
        console.log("✓ Timestamp is valid and compliant");
        console.log(`  - Profile: ${result.profile}`);
        console.log(`  - Strictness: ${result.strictnessLevel}`);
        console.log(`  - Certificate chain: ${result.certificateChain?.nodes.length} certs`);
        console.log(`  - Revocation info: ${result.revocationInfo.length} entries`);
    } else {
        console.log("✗ Validation failed");
        for (const error of result.errors) {
            console.log(`  - Error: ${error}`);
        }
        for (const warning of result.warnings) {
            console.log(`  - Warning: ${warning}`);
        }
    }

    return result;
}
```
