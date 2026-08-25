import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const TEST_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const TESTS_DIRECTORY = resolve(TEST_DIRECTORY, "../..");
const CONFORMANCE_SCRIPT = join(TESTS_DIRECTORY, "scripts", "offline-pades-conformance.ts");
const TSX_CLI = resolve(TESTS_DIRECTORY, "../../node_modules/tsx/dist/cli.mjs");
const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
    const directory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-conformance-options-"));
    temporaryDirectories.push(directory);
    return directory;
}

function runScript(args: string[]): SpawnSyncReturns<string> {
    return spawnSync(process.execPath, [TSX_CLI, CONFORMANCE_SCRIPT, ...args], {
        cwd: TESTS_DIRECTORY,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
    });
}

function commandOutput(result: SpawnSyncReturns<string>): string {
    return [result.stdout, result.stderr]
        .filter((value): value is string => typeof value === "string" && value.length > 0)
        .join("\n");
}

afterEach(() => {
    for (const directory of temporaryDirectories.splice(0)) {
        rmSync(directory, { force: true, recursive: true });
    }
});

describe("offline interoperability artifact options", () => {
    it("shows output-retention help without starting the validation tools", () => {
        const result = runScript(["--help"]);

        expect(result.error).toBeUndefined();
        expect(result.status).toBe(0);
        expect(commandOutput(result)).toContain("Usage:");
        expect(commandOutput(result)).toContain("--output-dir");
    });

    it("rejects an existing output directory before starting the validation tools", () => {
        const existingDirectory = temporaryDirectory();
        const result = runScript(["--output-dir", existingDirectory]);

        expect(result.error).toBeUndefined();
        expect(result.status).toBe(2);
        expect(commandOutput(result)).toContain("Output directory must not already exist");
    });
});
