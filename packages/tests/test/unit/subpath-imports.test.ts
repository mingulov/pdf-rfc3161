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
import * as pdf from "../../../core/src/pdf/index.js";
// Direct source imports for identity pins: each subpath must re-export
// the real implementation, not just any same-named function.
import { CircuitState as CircuitStateSource } from "../../../core/src/utils/circuit-breaker.js";
import { ValidationSession as ValidationSessionSource } from "../../../core/src/pki/validation-session.js";
import {
    DefaultFetcher as DefaultFetcherSource,
    MockFetcher as MockFetcherSource,
} from "../../../core/src/pki/index.js";
import {
    addDSS as addDSSSource,
    addVRIForSignature as addVRIForSignatureSource,
    extractLTVData as extractLTVDataSource,
    getDSSInfo as getDSSInfoSource,
} from "../../../core/src/pdf/ltv.js";
import { ensureWebCrypto as ensureWebCryptoSource } from "../../../core/src/utils/web-crypto.js";
import {
    createTimeStampedData as createTimeStampedDataSource,
    parseTimeStampedData as parseTimeStampedDataSource,
} from "../../../core/src/rfcs/rfc5544.js";
import { validateRFC8933Compliance as validateRFC8933ComplianceSource } from "../../../core/src/rfcs/rfc8933.js";

describe("subpath imports (audit L8)", () => {
    describe("pdf-rfc3161/advanced", () => {
        it("exports DefaultFetcher", () => {
            expect(advanced.DefaultFetcher).toBe(DefaultFetcherSource);
        });

        it("exports MockFetcher", () => {
            expect(advanced.MockFetcher).toBe(MockFetcherSource);
        });

        it("exports CircuitState enum", () => {
            expect(advanced.CircuitState).toBe(CircuitStateSource);
            expect(advanced.CircuitState).toMatchObject({
                CLOSED: "CLOSED",
                OPEN: "OPEN",
                HALF_OPEN: "HALF_OPEN",
            });
        });

        it("exports ValidationSession", () => {
            expect(advanced.ValidationSession).toBe(ValidationSessionSource);
        });
    });

    describe("pdf-rfc3161/internals", () => {
        it("exports getDSSInfo", () => {
            expect(internals.getDSSInfo).toBe(getDSSInfoSource);
        });

        it("exports addDSS", () => {
            expect(internals.addDSS).toBe(addDSSSource);
        });

        it("exports addVRIForSignature without widening the root API", async () => {
            const root = await import("pdf-rfc3161");
            type Root = typeof root;
            const rootExportsVRI: "addVRIForSignature" extends keyof Root ? true : false = false;

            expect(internals.addVRIForSignature).toBe(addVRIForSignatureSource);
            expect(pdf.addVRIForSignature).toBe(addVRIForSignatureSource);
            expect(rootExportsVRI).toBe(false);
            expect("addVRIForSignature" in root).toBe(false);
        });

        it("exports extractLTVData", () => {
            expect(internals.extractLTVData).toBe(extractLTVDataSource);
        });

        it("does not export the unsafe raw PDF embed primitive", () => {
            type Internals = typeof internals;
            const rawEmbedIsPublished: "embedTimestampToken" extends keyof Internals
                ? true
                : false = false;

            expect(rawEmbedIsPublished).toBe(false);
            expect("embedTimestampToken" in internals).toBe(false);
        });

        it("exports ensureWebCrypto (added in 0.2.0 / Task 2.13)", () => {
            expect(internals.ensureWebCrypto).toBe(ensureWebCryptoSource);
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
            expect(rfc5544.createTimeStampedData).toBe(createTimeStampedDataSource);
        });

        it("exports parseTimeStampedData", () => {
            expect(rfc5544.parseTimeStampedData).toBe(parseTimeStampedDataSource);
        });
    });

    describe("pdf-rfc3161/rfcs/rfc8933", () => {
        it("exports validateRFC8933Compliance", () => {
            expect(rfc8933.validateRFC8933Compliance).toBe(validateRFC8933ComplianceSource);
        });
    });
});
