/**
 * Advanced subpath: things most callers won't need.
 *
 * Importing `pdf-rfc3161/advanced` lets a tree-shaking bundler drop the
 * validation-session / fetchers / circuit-breaker code from the main
 * entry when those features aren't used. Saves ~10-15 KB for callers
 * who only sign + verify.
 */

export {
    ValidationSession,
    type CertificateToValidate,
    type ValidationResult,
    type RevocationDataFetcher,
    type ValidationCache,
    type ValidationSessionOptions,
    DefaultFetcher,
    MockFetcher,
    InMemoryValidationCache,
} from "./pki/index.js";

export {
    CircuitBreaker,
    CircuitBreakerMap,
    CircuitState,
    CircuitBreakerError,
} from "./utils/circuit-breaker.js";
