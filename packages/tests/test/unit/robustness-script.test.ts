import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const TEST_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const TESTS_DIRECTORY = resolve(TEST_DIRECTORY, "../..");
const ROBUSTNESS_SCRIPT = join(TESTS_DIRECTORY, "scripts", "test-robustness.ts");
const TSX_CLI = resolve(TESTS_DIRECTORY, "../../node_modules/tsx/dist/cli.mjs");
const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
    const directory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-robustness-script-"));
    temporaryDirectories.push(directory);
    return directory;
}

function runWithCorpus(corpusDirectory: string): SpawnSyncReturns<string> {
    return spawnSync(process.execPath, [TSX_CLI, ROBUSTNESS_SCRIPT], {
        cwd: TESTS_DIRECTORY,
        encoding: "utf8",
        env: {
            ...process.env,
            ROBUSTNESS_CORPUS_DIR: corpusDirectory,
        },
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

describe("robustness script corpus setup", () => {
    it("fails with setup guidance when the configured corpus is missing", () => {
        const missingCorpus = join(temporaryDirectory(), "missing-corpus");
        const result = runWithCorpus(missingCorpus);

        expect(result.error).toBeUndefined();
        expect(result.status).toBe(1);
        expect(commandOutput(result)).toContain("Robustness corpus is missing");
        expect(commandOutput(result)).toContain(missingCorpus);
        expect(commandOutput(result)).toContain("fetch-corpus.ts");
    });

    it("fails with setup guidance when the configured corpus has no PDF files", () => {
        const emptyCorpus = join(temporaryDirectory(), "empty-corpus");
        mkdirSync(emptyCorpus);
        const result = runWithCorpus(emptyCorpus);

        expect(result.error).toBeUndefined();
        expect(result.status).toBe(1);
        expect(commandOutput(result)).toContain("Robustness corpus is empty");
        expect(commandOutput(result)).toContain(emptyCorpus);
        expect(commandOutput(result)).toContain("fetch-corpus.ts");
    });

    it("fails instead of passing when every corpus PDF is skipped", () => {
        const skippedCorpus = join(temporaryDirectory(), "skipped-corpus");
        mkdirSync(skippedCorpus);
        writeFileSync(
            join(skippedCorpus, "encrypted.pdf"),
            new Uint8Array([0x25, 0x50, 0x44, 0x46])
        );

        const result = runWithCorpus(skippedCorpus);

        expect(result.error).toBeUndefined();
        expect(result.status).toBe(1);
        expect(commandOutput(result)).toContain("zero executable PDF files");
        expect(commandOutput(result)).toContain("skip filters");
    });
});
