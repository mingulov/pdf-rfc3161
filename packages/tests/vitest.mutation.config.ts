import { defineConfig } from "vitest/config";
import { readFileSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// T17 mutation pilot: dedicated Vitest config used ONLY by the Stryker
// vitest-runner (see root stryker.config.mjs). It mirrors the aliases and
// setup of vitest.config.ts but restricts execution to the pilot
// source-suite allowlist and disables coverage thresholds (a per-mutant
// coverage gate would fail every mutant run).
//
// Excluded by construction (never add them here): every suite importing
// assertCliDistIsFresh, whose source-hash guard invalidates mutated core
// builds:
//   - test/unit/cli-async-entry.test.ts
//   - test/unit/cli-build-manifest.test.ts
//   - test/integration/cli.integration.test.ts
//   - test/integration/cli-pades-safety.test.ts
// The whole test/integration directory stays out for the same reason: those
// suites spawn packages/cli/dist, which Stryker does not rebuild per mutant.

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPackageJson = JSON.parse(
    readFileSync(join(__dirname, "../cli/package.json"), "utf-8")
);

const coreSrc = resolve(__dirname, "../core/src");

export default defineConfig({
    // Stryker runs Vitest from the sandbox root, not from this directory:
    // without an explicit root the include/setupFiles globs below resolve
    // against the wrong directory and zero tests are found.
    root: __dirname,
    test: {
        globals: true,
        environment: "node",
        // Pilot allowlist: suites covering the stryker.config.mjs mutate
        // scope (validity windows, identity keys, cache keys, EKU verdict).
        include: [
            "test/unit/eku-check.test.ts",
            "test/unit/cert-validity.test.ts",
            "test/unit/pki-utils.test.ts",
            "test/unit/validation-cache.test.ts",
        ],
        setupFiles: ["./test/setup.ts"],
        alias: {
            "pdf-rfc3161/internals": resolve(coreSrc, "internals.ts"),
            "pdf-rfc3161/advanced": resolve(coreSrc, "advanced.ts"),
            "pdf-rfc3161/rfcs/rfc5544": resolve(coreSrc, "rfcs/rfc5544.ts"),
            "pdf-rfc3161/rfcs/rfc8933": resolve(coreSrc, "rfcs/rfc8933.ts"),
            "pdf-rfc3161": resolve(coreSrc, "index.ts"),
        },
        testTimeout: 30000,
    },
    define: {
        VERSION: JSON.stringify(cliPackageJson.version),
    },
});
