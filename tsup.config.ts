import { defineConfig } from "tsup";

export default defineConfig([
    // Library build
    {
        entry: ["src/index.ts"],
        format: ["esm", "cjs"],
        dts: true,
        clean: true,
        sourcemap: true,
        target: "es2022",
        minify: false,
        splitting: false,
        treeshake: true,
    },
    // CLI build
    {
        entry: ["src/cli/cli.ts"],
        format: ["cjs"],
        dts: false,
        clean: false,
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
    },
]);
