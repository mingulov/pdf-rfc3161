import { defineConfig } from "tsup";

export default defineConfig({
    entry: {
        index: "src/index.ts",
        advanced: "src/advanced.ts",
        internals: "src/internals.ts",
        "rfcs/rfc5544": "src/rfcs/rfc5544.ts",
        "rfcs/rfc8933": "src/rfcs/rfc8933.ts",
    },
    format: ["esm", "cjs"],
    dts: true,
    clean: true,
    sourcemap: true,
    target: "es2022",
    minify: false,
    splitting: false,
    treeshake: true,
});
