// Lower-level building blocks for callers who need PDF/PKI plumbing beyond
// the headline API. Imported via `import { ... } from "pdf-rfc3161/internals"`.
// The top-level entry stays focused on the common signing/verification flow.
//
// Audit H2: `reset*Circuits()` are intentionally NOT re-exported here. They
// mutate module-level singleton state shared across the hosting process; a
// hostile plugin in the same import graph could call them to defeat the
// rate-limiting / circuit-breaker protections meant to absorb outages or
// abuse against revocation responders. Test packages that genuinely need to
// reset breaker state import directly from the per-client source files
// (`packages/core/src/pki/cert-client.ts` etc.). They are deliberately not
// part of the supported public surface.

export { addDSS, addVRI, addVRIEnhanced, extractLTVData, completeLTVData, getDSSInfo } from "./pdf/ltv.js";
export { embedTimestampToken, extractBytesToHash } from "./pdf/embed.js";
export { preparePdfForTimestamp, type PreparedPDF } from "./pdf/prepare.js";
export { getOCSPURI, createOCSPRequest, parseOCSPResponse } from "./pki/ocsp-utils.js";
export { getCaIssuers, findIssuer } from "./pki/cert-utils.js";
export { fetchCertificate, getCertCircuitState } from "./pki/cert-client.js";
export { getCRLDistributionPoints } from "./pki/crl-utils.js";
export { fetchCRL, parseCRLInfo, getCRLCircuitState } from "./pki/crl-client.js";
export { fetchOCSPResponse, getOCSPCircuitState } from "./pki/ocsp-client.js";

// Lazy crypto bootstrap. Most callers can ignore this -- `createTimestampRequest`
// awaits it automatically. The sync `createTimestampRequestFromHash` does not
// poll for crypto, so callers in environments with lazy-initialised
// `globalThis.crypto` may want to invoke this once at startup. See the JSDoc
// on `createTimestampRequestFromHash` in `tsa/request.ts` for context.
export { ensureWebCrypto } from "./utils/web-crypto.js";
