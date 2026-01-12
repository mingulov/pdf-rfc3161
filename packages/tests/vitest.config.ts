import { defineConfig } from "vitest/config";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPackageJson = JSON.parse(
    readFileSync(join(__dirname, "../cli/package.json"), "utf-8")
);

export default defineConfig({
    test: {
        globals: true,
        environment: "node",
        include: ["test/**/*.test.ts"],
        alias: {
            "pdf-rfc3161": "../core/src/index.ts",
        },
        coverage: {
            provider: "v8",
            include: ["../core/src/**/*.ts"],
            exclude: ["../core/src/**/*.d.ts"],
        },
        testTimeout: 30000, // TSA requests can be slow
    },
    define: {
        VERSION: JSON.stringify(cliPackageJson.version),
    },
});
