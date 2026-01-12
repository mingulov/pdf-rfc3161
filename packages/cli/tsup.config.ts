import { defineConfig } from "tsup";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const packageJson = JSON.parse(readFileSync(join(__dirname, "package.json"), "utf-8"));

export default defineConfig({
    entry: ["src/cli.ts"],
    format: ["cjs", "esm"],
    dts: false,
    clean: true,
    sourcemap: true,
    target: "es2022",
    minify: false,
    splitting: false,
    treeshake: true,
    shims: true,
    noExternal: ["commander"],
    banner: {
        js: "#!/usr/bin/env node",
    },
    define: {
        VERSION: JSON.stringify(packageJson.version),
    },
});
