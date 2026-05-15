import { describe, it, expect } from "vitest";

// Audit L8: smoke tests that the package's published subpath exports
// (`pdf-rfc3161/advanced`, `pdf-rfc3161/internals`, `pdf-rfc3161/rfcs/rfc5544`,
// `pdf-rfc3161/rfcs/rfc8933`) resolve correctly. Catches future drift
// between:
//   - vitest.config.ts `alias` entries (used for in-repo test resolution)
//   - packages/core/package.json `exports` map (used by published consumers)
// If those two get out of sync, only consumers of the published tarball
// would notice -- the in-repo test suite would silently still pass.

import * as advanced from "pdf-rfc3161/advanced";
import * as internals from "pdf-rfc3161/internals";
import * as rfc5544 from "pdf-rfc3161/rfcs/rfc5544";
import * as rfc8933 from "pdf-rfc3161/rfcs/rfc8933";

describe("subpath imports (audit L8)", () => {
    describe("pdf-rfc3161/advanced", () => {
        it("exports DefaultFetcher", () => {
            expect(typeof advanced.DefaultFetcher).toBe("function");
        });

        it("exports MockFetcher", () => {
            expect(typeof advanced.MockFetcher).toBe("function");
        });

        it("exports CircuitState enum", () => {
            expect(advanced.CircuitState).toBeDefined();
            expect(typeof advanced.CircuitState).toBe("object");
        });

        it("exports ValidationSession", () => {
            expect(typeof advanced.ValidationSession).toBe("function");
        });
    });

    describe("pdf-rfc3161/internals", () => {
        it("exports getDSSInfo", () => {
            expect(typeof internals.getDSSInfo).toBe("function");
        });

        it("exports addDSS", () => {
            expect(typeof internals.addDSS).toBe("function");
        });

        it("exports extractLTVData", () => {
            expect(typeof internals.extractLTVData).toBe("function");
        });

        it("exports embedTimestampToken", () => {
            expect(typeof internals.embedTimestampToken).toBe("function");
        });

        it("exports ensureWebCrypto (added in 0.2.0 / Task 2.13)", () => {
            expect(typeof internals.ensureWebCrypto).toBe("function");
        });

        // Audit H2 regression check: circuit-breaker resets must NOT
        // appear on /internals (they mutate process-shared singleton state).
        it("does NOT export resetCertCircuits / resetCRLCircuits / resetOCSPCircuits", () => {
            expect("resetCertCircuits" in internals).toBe(false);
            expect("resetCRLCircuits" in internals).toBe(false);
            expect("resetOCSPCircuits" in internals).toBe(false);
        });
    });

    describe("pdf-rfc3161/rfcs/rfc5544", () => {
        it("exports createTimeStampedData", () => {
            expect(typeof rfc5544.createTimeStampedData).toBe("function");
        });

        it("exports parseTimeStampedData", () => {
            expect(typeof rfc5544.parseTimeStampedData).toBe("function");
        });
    });

    describe("pdf-rfc3161/rfcs/rfc8933", () => {
        it("exports validateRFC8933Compliance", () => {
            expect(typeof rfc8933.validateRFC8933Compliance).toBe("function");
        });
    });
});
