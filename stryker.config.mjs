// T17 mutation pilot: Stryker configuration, run from the repository root.
//
// STATUS: DEFERRED TOOL (2026-10-03). Do NOT schedule this config in CI:
// @stryker-mutator/vitest-runner@10.0.0 builds space-joined
// testNamePattern filters, which never match Vitest 5.0.2 fullTestName
// (joined with ' > '), so every filtered mutant run executes 0 tests
// and falsely reports Survived. Proven by mutant 262 (line-1001 EKU criticality flip,
// covered by the killing test, Survived with testsCompleted 0) against the
// manual-seed kill proof in task-T17-report.md. Re-entry condition: a
// vitest-runner release that selects mutant-run tests correctly under
// Vitest 5; then re-verify with the dry run plus the controlled seed before
// adding the scheduled workflow.
//
//   corepack pnpm mutation:dry-run  # bridge compatibility probe (no mutants)
//   corepack pnpm mutation           # pilot run: 2 workers, ~15 min budget
//
// Stryker copies the repo (minus node_modules/.git, which it symlinks or
// skips) into .stryker-tmp and runs the Vitest mutation config there, so all
// paths below are root-relative and sandbox-safe. Locked plugin versions live
// in the root devDependencies (never an unpinned initializer in CI).
//
// Pilot mutate scope (plan: verdict transitions, identity/cache keys,
// validity windows, bounds):
//   - pki-utils.ts: validity windows (isCertValidAtTime, validityOk) and
//     identity keys (certIdHashAlgorithmForOid)
//   - fetchers/memory-cache.ts: revocation cache keys and bounds
//   - token-validation.ts hasTimestampingEKU only (line range): the EKU
//     verdict transition; the rest of the 1000+ line file stays out of scope
//     so the pilot fits the 15-minute complete-run budget.
/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
export default {
    plugins: ["@stryker-mutator/vitest-runner", "@stryker-mutator/typescript-checker"],
    mutate: [
        "packages/core/src/pki/pki-utils.ts",
        "packages/core/src/pki/fetchers/memory-cache.ts",
        "packages/core/src/tsa/token-validation.ts:995-1021",
    ],
    // Suite allowlist, mirrored by the include list in
    // packages/tests/vitest.mutation.config.ts. Suites importing
    // assertCliDistIsFresh are excluded (their source-hash guard fails on
    // mutated core builds): cli-async-entry, cli-build-manifest,
    // cli.integration, cli-pades-safety.
    testFiles: [
        "packages/tests/test/unit/eku-check.test.ts",
        "packages/tests/test/unit/cert-validity.test.ts",
        "packages/tests/test/unit/pki-utils.test.ts",
        "packages/tests/test/unit/validation-cache.test.ts",
    ],
    testRunner: "vitest",
    vitest: {
        configFile: "packages/tests/vitest.mutation.config.ts",
        dir: "packages/tests",
        related: false,
    },
    checkers: ["typescript"],
    // Dedicated checker project: core sources only, noEmit. Test files are
    // not mutated, so they stay out of the checker program.
    tsconfigFile: "tsconfig.mutation.json",
    concurrency: 2,
    coverageAnalysis: "perTest",
    reporters: ["progress", "clear-text", "html", "json"],
    htmlReporter: {
        fileName: "reports/mutation/mutation.html",
    },
    jsonReporter: {
        fileName: "reports/mutation/mutation-report.json",
    },
    // Report-only pilot: never fail on score. Any nonzero exit therefore
    // signals an infrastructure failure, not kills.
    thresholds: {
        high: 80,
        low: 60,
        break: null,
    },
    dryRunTimeoutMinutes: 5,
    tempDirName: ".stryker-tmp",
    cleanTempDir: true,
    // Keep the sandbox lean: demo app, fuzz build/work outputs, coverage,
    // prior reports and the local-only pades oracle rootfs (30M of system
    // symlinks, which the sandbox file copy cannot reproduce) are never
    // needed to run the pilot suites.
    ignorePatterns: [
        "packages/demo/**",
        "packages/tests/fuzz/build/**",
        "packages/tests/fuzz/work/**",
        "packages/tests/coverage/**",
        "packages/tests/.pades-oracles/**",
        "packages/core/dist/**",
        "packages/cli/dist/**",
        "packages/demo/dist/**",
        "reports/**",
        ".review-tmp/**",
    ],
};
