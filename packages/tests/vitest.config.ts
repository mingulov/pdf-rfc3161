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
            ],
            all: true,
            allowExternal: true,
            reporter: ["text", "html", "lcov"],
            reportsDirectory: "./coverage",
        },
        testTimeout: 30000, // TSA requests can be slow
    },
    define: {
        VERSION: JSON.stringify(cliPackageJson.version),
    },
});
