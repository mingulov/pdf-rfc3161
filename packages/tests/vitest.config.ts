import { defineConfig } from "vitest/config";
import { readFileSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPackageJson = JSON.parse(
    readFileSync(join(__dirname, "../cli/package.json"), "utf-8")
);

const coreSrc = resolve(__dirname, "../core/src");

export default defineConfig({
    test: {
        globals: true,
        environment: "node",
        include: ["test/**/*.test.ts"],
        setupFiles: ["./test/setup.ts"],
        alias: {
            "pdf-rfc3161/internals": resolve(coreSrc, "internals.ts"),
            "pdf-rfc3161/advanced": resolve(coreSrc, "advanced.ts"),
            "pdf-rfc3161/rfcs/rfc5544": resolve(coreSrc, "rfcs/rfc5544.ts"),
            "pdf-rfc3161/rfcs/rfc8933": resolve(coreSrc, "rfcs/rfc8933.ts"),
            "pdf-rfc3161": resolve(coreSrc, "index.ts"),
        },
        coverage: {
            provider: "v8",
            include: [`${coreSrc}/**/*.ts`],
            exclude: [
                `${coreSrc}/**/*.d.ts`,
                `${coreSrc}/**/*.test.ts`,
                // This module contains TypeScript interfaces only; V8 cannot remap it as JavaScript.
                `${coreSrc}/pki/validation-types.ts`,
            ],
            all: true,
            allowExternal: true,
            reporter: ["text", "html", "lcov"],
            reportsDirectory: "./coverage",
            // T13 floors: fail when coverage drops below the freshly
            // measured post-T12 baseline. Baseline 2026-10-03, vitest
            // 5.0.2 + @vitest/coverage-v8 5.0.2 on Node 24.21.0, suite
            // 2100 passed / 51 skipped / 2 todo: statements 90.25
            // (5418/6003), branches 85.39 (3882/4546), functions 96.72
            // (621/642), lines 92.24 (5055/5480); validation-session
            // lines 90.72 (225/248) / branches 87.64 (149/170); main
            // index branches 93.87 (46/49). Glob keys are matched
            // against paths relative to this directory. Later work
            // must keep the suite above these floors (R7): raise them
            // when coverage improves, never lower them to fit a drop.
            // T19: the one-call code (and its 46/49 branches) moved
            // from index.ts to timestamp-pdf.ts (audit S1); the
            // per-file floor follows the code at the same value.
            // index.ts is now a branchless barrel and needs no pin.
            thresholds: {
                statements: 90.25,
                branches: 85.39,
                functions: 96.72,
                lines: 92.24,
                "../core/src/pki/validation-session.ts": {
                    lines: 90.72,
                    branches: 87.64,
                },
                "../core/src/timestamp-pdf.ts": {
                    branches: 93.87,
                },
            },
        },
        testTimeout: 30000, // TSA requests can be slow
    },
    define: {
        VERSION: JSON.stringify(cliPackageJson.version),
    },
});
