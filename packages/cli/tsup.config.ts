import { defineConfig } from "tsup";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const packageJson = JSON.parse(readFileSync(join(__dirname, "package.json"), "utf-8"));

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
});
