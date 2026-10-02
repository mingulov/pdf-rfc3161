import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PDFDocument } from "pdf-lib-incremental-save";
import { CLI_DIST_PATH, assertCliDistIsFresh } from "../utils/cli-dist.js";

// This suite spawns the built CLI bundle, so it refuses to run against a
// stale or missing packages/cli/dist/cli.cjs.
assertCliDistIsFresh();

const NODE = process.execPath;
const UNHANDLED_MARKER = /unhandled|uncaught/i;

async function writeMinimalPdf(directory: string): Promise<string> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const bytes = await document.save();
    const file = join(directory, "input.pdf");
    writeFileSync(file, bytes);
    return file;
}

function withTempDirectory<T>(callback: (directory: string) => T): T {
    const directory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-cli-entry-"));
    try {
        return callback(directory);
    } finally {
        rmSync(directory, { recursive: true, force: true });
    }
}

async function withTempDirectoryAsync<T>(
    callback: (directory: string) => Promise<T>
): Promise<T> {
    const directory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-cli-entry-"));
    try {
        return await callback(directory);
    } finally {
        rmSync(directory, { recursive: true, force: true });
    }
}

describe("CLI async entry (R5)", () => {
    it("completes a real async verify command with exit 0", async () => {
        await withTempDirectoryAsync(async (directory: string) => {
            const file = await writeMinimalPdf(directory);
            const spawned = spawnSync(NODE, [CLI_DIST_PATH, "verify", file], {
                encoding: "utf8",
                timeout: 15000,
            });

            expect(spawned.error).toBeUndefined();
            expect(spawned.status).toBe(0);
            expect(spawned.stdout).toContain("No RFC 3161 timestamps found in this PDF.");
            expect(spawned.stderr).not.toMatch(UNHANDLED_MARKER);
        });
    });

    it("reports a caught async failure with exit 1 and no unhandled rejection", () => {
        withTempDirectory((directory: string) => {
            const missing = join(directory, "missing.pdf");
            const spawned = spawnSync(NODE, [CLI_DIST_PATH, "verify", missing], {
                encoding: "utf8",
                timeout: 15000,
            });

            expect(spawned.error).toBeUndefined();
            expect(spawned.status).toBe(1);
            expect(spawned.stderr).toContain("ENOENT");
            expect(spawned.stderr).not.toMatch(UNHANDLED_MARKER);
        });
    });

    it("routes an action rejection escaping existing catches to a clean failure", () => {
        withTempDirectory((directory: string) => {
            const missing = join(directory, "missing.pdf");
            // The harness intercepts process.exit with a throw, which turns
            // the action's own catch-and-exit into a rejection that escapes
            // every existing catch. The entry must still report it cleanly
            // (exit 1, clean stderr) instead of crashing unhandled.
            const harness = join(directory, "harness.cjs");
            writeFileSync(
                harness,
                [
                    "const dist = process.argv[2];",
                    "const target = process.argv[3];",
                    "process.argv = ['node', dist, 'verify', target];",
                    "delete process.env.CLI_TEST_MODE;",
                    "process.exit = (code) => { throw new Error(`exit-intercepted:${String(code)}`); };",
                    "process.on('unhandledRejection', () => { console.error('HARNESS-UNHANDLED-REJECTION'); });",
                    "require(dist);",
                    "",
                ].join("\n")
            );
            const spawned = spawnSync(NODE, [harness, CLI_DIST_PATH, missing], {
                encoding: "utf8",
                timeout: 15000,
            });

            expect(spawned.error).toBeUndefined();
            expect(spawned.status).toBe(1);
            expect(spawned.stderr).toContain("ENOENT");
            expect(spawned.stderr).not.toContain("HARNESS-UNHANDLED-REJECTION");
            expect(spawned.stderr).not.toMatch(UNHANDLED_MARKER);
        });
    });
});
