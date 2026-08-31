import { defineConfig } from "tsup";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { writeCliBuildManifest } from "./scripts/build-manifest";

const packageJson = JSON.parse(readFileSync(join(__dirname, "package.json"), "utf-8"));
const repositoryRoot = resolve(__dirname, "../..");

export default defineConfig({
    entry: ["src/cli.ts"],
    format: ["cjs"],
    dts: false,
    clean: true,
    sourcemap: false,
    target: "es2022",
    minify: false,
    splitting: false,
    treeshake: true,
    banner: {
        js: "#!/usr/bin/env node",
    },
    define: {
        VERSION: JSON.stringify(packageJson.version),
    },
    // Record the sources this bundle was built from. The CLI test suites spawn
    // dist/cli.cjs and refuse to run against a stale one; see
    // scripts/build-manifest.ts.
    onSuccess: async () => {
        writeCliBuildManifest(repositoryRoot);
    },
});
