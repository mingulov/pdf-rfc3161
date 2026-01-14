import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import fs from "fs";

const versionInfo = () => {
    return {
        name: "version-info",
        config: () => {
            let version = "0.0.0";
            try {
                const pkg = JSON.parse(
                    fs.readFileSync(path.resolve(__dirname, "../core/package.json"), "utf-8")
                );
                version = pkg.version || "0.0.0";
            } catch {
                console.warn("Could not read package.json for version");
            }
            const gitHash =
                process.env.GITHUB_SHA?.substring(0, 7) ||
                process.env.GIT_COMMIT_SHA?.substring(0, 7) ||
                process.env.GIT_HASH ||
                "unknown";
            return {
                define: {
                    "import.meta.env.PDF_RFC3161_VERSION": JSON.stringify(version),
                    "import.meta.env.PDF_RFC3161_GIT_HASH": JSON.stringify(gitHash),
                },
            };
        },
    };
};

// https://vite.dev/config/
export default defineConfig({
    base: "./",
    plugins: [react(), versionInfo()],
    resolve: {
        alias: {
            "pdf-rfc3161": path.resolve(__dirname, "../core/src/index.ts"),
        },
    },
    server: {
        fs: {
            allow: [".."],
        },
        watch: {
            ignored: [
                "**/test-results/**",
                "**/test.pdf",
                "**/*.tsq",
                "**/*.tsr",
                "**/timestamped-*.pdf",
            ],
        },
    },
    build: {
        target: "esnext", // Use modern JS for smaller bundles (since we support modern browsers)
        minify: "terser", // Better minification than default 'esbuild'
        terserOptions: {
            compress: {
                drop_console: false,
                drop_debugger: true,
            },
            format: {
                comments: false,
            },
        },
        sourcemap: false,
        rollupOptions: {
            output: {
                manualChunks(id) {
                    // Check if the file is inside the parent src directory (the library)
                    // We normalize paths to ensure cross-platform compatibility
                    const libPath = path.resolve(__dirname, "../core/src");
                    if (id.startsWith(libPath)) {
                        return "pdf-rfc3161";
                    }
                    if (id.includes("pdf-lib-incremental-save")) {
                        return "pdf-lib-incremental-save";
                    }
                },
            },
        },
    },
});
