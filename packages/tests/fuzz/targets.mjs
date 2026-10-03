// T16 pilot: shared Jazzer.js target table. One row per plan checkbox target.
// coreFile/functions drive the coverage-reaches-function proof in replay.mjs.
export const TARGETS = [
    {
        name: "response",
        module: "fuzz-response",
        corpus: "response",
        sync: true,
        coreFile: "core/src/tsa/response.js",
        functions: ["parseTimestampResponse"],
    },
    {
        name: "token",
        module: "fuzz-token",
        corpus: "token",
        sync: true,
        coreFile: "core/src/tsa/token-validation.js",
        functions: ["parseTimestampToken"],
    },
    {
        name: "ocsp",
        module: "fuzz-ocsp",
        corpus: "ocsp",
        sync: true,
        coreFile: "core/src/pki/ocsp-utils.js",
        functions: ["parseOCSPResponse"],
    },
    {
        name: "extract",
        module: "fuzz-extract",
        corpus: "extract",
        sync: false,
        coreFile: "core/src/pdf/extract.js",
        functions: ["extractTimestamps"],
    },
    {
        name: "der",
        module: "fuzz-der",
        corpus: "der",
        sync: true,
        coreFile: "core/src/pki/der-utils.js",
        functions: ["parseCanonicalDERSequenceTree", "parseCanonicalDERValue"],
    },
    {
        name: "rfc5544",
        module: "fuzz-rfc5544",
        corpus: "rfc5544",
        sync: true,
        coreFile: "core/src/rfcs/rfc5544.js",
        functions: ["parseTimeStampedData"],
    },
];

// Contract budgets, shared by replay and exploration.
export const INPUT_TIMEOUT_MS = 2000;
export const INPUT_TIMEOUT_S = 2;
export const RSS_LIMIT_MB = 1024;
export const MAX_LEN = 65536;
export const EXPLORE_SECONDS = 60;
// Outer process bound per target run. Replay of a few small seeds takes
// seconds; exploration is capped by libFuzzer well inside this. The
// value is a hang backstop, not a cost estimate.
export const OUTER_TIMEOUT_S = 300;
