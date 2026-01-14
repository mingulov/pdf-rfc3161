import { defineConfig } from "tsup";

export default defineConfig({
    entry: {
        index: "src/index.ts",
        validation: "src/validation/index.ts",
    },
    format: ["esm", "cjs"],
    dts: {
        entry: {
            index: "src/index.ts",
            validation: "src/validation/index.ts",
        },
    },
    clean: true,
    sourcemap: true,
    target: "es2022",
    minify: false,
    splitting: false,
    treeshake: true,
});
