import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PDFDocument } from "pdf-lib-incremental-save";
import { afterEach, describe, expect, it } from "vitest";
import { createRFC3161TokenFixtureFromRequest } from "../fixtures/rfc3161-token.js";

const TEST_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const SCRIPTS_DIRECTORY = resolve(TEST_DIRECTORY, "../../scripts");
const MANUAL_VALIDATION_DOCUMENT = resolve(
    TEST_DIRECTORY,
    "../../../../docs/manual-acrobat-validation.md"
);
const GENERATE_SCRIPT = join(SCRIPTS_DIRECTORY, "generate-check-files.cjs");
const VERIFY_SCRIPT = join(SCRIPTS_DIRECTORY, "verify-signature.cjs");
const temporaryDirectories: string[] = [];
const moduleRequire = createRequire(import.meta.url);

interface GeneratedFile {
    outputPath: string;
    pdf: Uint8Array;
}

interface GeneratorModule {
    writeGeneratedFiles(
        generated: GeneratedFile[],
        fileSystem?: {
            openSync(path: string, flags: string): number;
            writeFileSync(fileDescriptor: number, pdf: Uint8Array): void;
            closeSync(fileDescriptor: number): void;
            unlinkSync(path: string): void;
        }
    ): void;
}

function runScript(script: string, args: string[]): SpawnSyncReturns<string> {
    return spawnSync(process.execPath, [script, ...args], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
    });
}

function commandOutput(result: SpawnSyncReturns<string>): string {
    return [result.stdout, result.stderr]
        .filter((value): value is string => typeof value === "string" && value.length > 0)
        .join("\n");
}

function temporaryDirectory(): string {
    const directory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-manual-script-"));
    temporaryDirectories.push(directory);
    return directory;
}

function loadBuiltPackage(): typeof import("pdf-rfc3161") {
    const resolvedPackage = moduleRequire.resolve("pdf-rfc3161");
    expect(resolvedPackage).toBe(resolve(TEST_DIRECTORY, "../../../core/dist/index.cjs"));
    return moduleRequire("pdf-rfc3161") as typeof import("pdf-rfc3161");
}

async function createScriptFixturePdfs(directory: string): Promise<{
    unsignedPath: string;
    validPath: string;
    tamperedPath: string;
}> {
    const document = await PDFDocument.create();
    const page = document.addPage([200, 200]);
    page.drawText("Built public package script fixture", { x: 20, y: 100, size: 12 });
    const unsignedPdf = await document.save();
    const unsignedPath = join(directory, "unsigned.pdf");
    writeFileSync(unsignedPath, unsignedPdf);

    const library = loadBuiltPackage();
    const session = new library.TimestampSession(unsignedPdf, {
        enableLTV: false,
        hashAlgorithm: "SHA-256",
        prepareOptions: { signatureSize: 16384 },
    });
    const request = await session.createTimestampRequest();
    const response = await createRFC3161TokenFixtureFromRequest(request);
    const validPdf = await session.embedTimestampToken(response.response);
    const validPath = join(directory, "valid.pdf");
    writeFileSync(validPath, validPdf);

    const [timestamp] = await library.extractTimestamps(validPdf);
    if (!timestamp) throw new Error("Built public package did not extract its timestamp");
    const tamperedPdf = new Uint8Array(validPdf);
    const ranges = [
        [timestamp.byteRange[0], timestamp.byteRange[1]],
        [timestamp.byteRange[2], timestamp.byteRange[3]],
    ] as const;
    let changed = false;
    for (const [offset, length] of ranges) {
        for (let index = offset; index < offset + length; index += 1) {
            if (tamperedPdf[index] === 0x0a) {
                tamperedPdf[index] = 0x0d;
                changed = true;
                break;
            }
        }
        if (changed) break;
    }
    if (!changed) throw new Error("Fixture PDF has no covered newline to tamper");
    const tamperedPath = join(directory, "tampered.pdf");
    writeFileSync(tamperedPath, tamperedPdf);

    return { unsignedPath, validPath, tamperedPath };
}

afterEach(() => {
    for (const directory of temporaryDirectories.splice(0)) {
        rmSync(directory, { force: true, recursive: true });
    }
});

describe("manual validation scripts", () => {
    it("keeps the documented PowerShell paths and cleanup separators compatible", () => {
        const document = readFileSync(MANUAL_VALIDATION_DOCUMENT, "utf8");

        expect(document).not.toContain("Split-Path -LiteralPath $artifactDirectory -Parent");
        expect(document).toContain(
            "$artifactParent = [System.IO.Path]::GetDirectoryName($artifactDirectory)"
        );
        expect(document).not.toContain(
            '$trimmedArtifactDirectory = $resolvedArtifactDirectory.TrimEnd([char[]]@("\\\\", "/"))'
        );
        expect(document).not.toContain(
            '$trimmedFilesystemRoot = $filesystemRoot.TrimEnd([char[]]@("\\\\", "/"))'
        );
        expect(document).toContain("[System.IO.Path]::DirectorySeparatorChar");
        expect(document).toContain("[System.IO.Path]::AltDirectorySeparatorChar");
    });

    it("shows generator help without loading a built package", () => {
        const result = runScript(GENERATE_SCRIPT, ["--help"]);

        expect(result.error).toBeUndefined();
        expect(result.status).toBe(0);
        expect(commandOutput(result)).toContain("Usage:");
        expect(commandOutput(result)).toContain("--output-dir");
        expect(commandOutput(result)).toContain("--tsa-url");
    });

    it("rejects a missing TSA URL before creating the requested output directory", () => {
        const outputDirectory = join(temporaryDirectory(), "requested-output");
        const result = runScript(GENERATE_SCRIPT, ["--output-dir", outputDirectory]);

        expect(result.error).toBeUndefined();
        expect(result.status).toBe(2);
        expect(commandOutput(result)).toContain("--tsa-url is required");
        expect(existsSync(outputDirectory)).toBe(false);
    });

    it("rejects duplicate generator options instead of guessing which value to use", () => {
        const result = runScript(GENERATE_SCRIPT, [
            "--output-dir",
            "first",
            "--output-dir",
            "second",
            "--tsa-url",
            "https://tsa.example.test",
        ]);

        expect(result.error).toBeUndefined();
        expect(result.status).toBe(2);
        expect(commandOutput(result)).toContain("--output-dir may only be provided once");
    });

    it("preflights an existing generator output without overwriting or contacting a TSA", () => {
        const outputDirectory = temporaryDirectory();
        const existingOutput = join(outputDirectory, "final-test-no-ltv.pdf");
        writeFileSync(existingOutput, "keep this file");

        const result = runScript(GENERATE_SCRIPT, [
            "--output-dir",
            outputDirectory,
            "--tsa-url",
            "https://tsa.example.test",
        ]);

        expect(result.error).toBeUndefined();
        expect(result.status).toBe(1);
        expect(commandOutput(result)).toContain("Refusing to overwrite existing output file");
        expect(readFileSync(existingOutput, "utf8")).toBe("keep this file");
        expect(existsSync(join(outputDirectory, "final-test-ltv.pdf"))).toBe(false);
    });

    it("rolls back only files it created when a later generator write fails", () => {
        const outputDirectory = temporaryDirectory();
        const retainedFile = join(outputDirectory, "retain.txt");
        const createdFile = join(outputDirectory, "created.pdf");
        const blockedPath = join(outputDirectory, "blocked.pdf");
        writeFileSync(retainedFile, "do not remove");
        mkdirSync(blockedPath);
        const generator = moduleRequire(GENERATE_SCRIPT) as GeneratorModule;

        expect(() => {
            generator.writeGeneratedFiles([
                { outputPath: createdFile, pdf: new Uint8Array([1]) },
                { outputPath: blockedPath, pdf: new Uint8Array([2]) },
            ]);
        }).toThrow();

        expect(existsSync(createdFile)).toBe(false);
        expect(existsSync(blockedPath)).toBe(true);
        expect(readFileSync(retainedFile, "utf8")).toBe("do not remove");
    });

    it("rolls back the current output after a simulated partial ENOSPC write", () => {
        const outputDirectory = temporaryDirectory();
        const partialPath = join(outputDirectory, "partial.pdf");
        const retainedFile = join(outputDirectory, "retain.txt");
        writeFileSync(retainedFile, "do not remove");
        const generator = moduleRequire(GENERATE_SCRIPT) as GeneratorModule;
        let sawPartialFile = false;
        const partialWriteFilesystem = {
            openSync: (path: string, flags: string): number => {
                return moduleRequire("node:fs").openSync(path, flags);
            },
            writeFileSync: (fileDescriptor: number): void => {
                moduleRequire("node:fs").writeFileSync(fileDescriptor, new Uint8Array([0x01]));
                sawPartialFile = existsSync(partialPath);
                const error = new Error("simulated disk full") as NodeJS.ErrnoException;
                error.code = "ENOSPC";
                throw error;
            },
            closeSync: (fileDescriptor: number): void => {
                moduleRequire("node:fs").closeSync(fileDescriptor);
            },
            unlinkSync: (path: string): void => {
                moduleRequire("node:fs").unlinkSync(path);
            },
        };

        expect(() => {
            generator.writeGeneratedFiles(
                [{ outputPath: partialPath, pdf: new Uint8Array([0x01, 0x02]) }],
                partialWriteFilesystem
            );
        }).toThrow("simulated disk full");

        expect(sawPartialFile).toBe(true);
        expect(existsSync(partialPath)).toBe(false);
        expect(readFileSync(retainedFile, "utf8")).toBe("do not remove");
    });

    it("shows verifier help without interpreting --help as a PDF path", () => {
        const result = runScript(VERIFY_SCRIPT, ["--help"]);

        expect(result.error).toBeUndefined();
        expect(result.status).toBe(0);
        expect(commandOutput(result)).toContain("Usage:");
        expect(commandOutput(result)).toContain("<pdf-path>");
    });

    it("requires one or more verifier PDF paths instead of using a hardcoded fallback", () => {
        const result = runScript(VERIFY_SCRIPT, []);

        expect(result.error).toBeUndefined();
        expect(result.status).toBe(2);
        expect(commandOutput(result)).toContain("At least one PDF path is required");
    });

    it("rejects option-like verifier arguments instead of opening them as files", () => {
        const result = runScript(VERIFY_SCRIPT, ["--not-an-option"]);

        expect(result.error).toBeUndefined();
        expect(result.status).toBe(2);
        expect(commandOutput(result)).toContain("Unknown option: --not-an-option");
    });

    it("reports unsigned, valid, and covered-range-tampered PDFs through the built public package", async () => {
        const fixtures = await createScriptFixturePdfs(temporaryDirectory());

        const unsigned = runScript(VERIFY_SCRIPT, [fixtures.unsignedPath]);
        expect(unsigned.error).toBeUndefined();
        expect(unsigned.status).toBe(1);
        expect(commandOutput(unsigned)).toContain("No RFC 3161 document timestamps found");

        const valid = runScript(VERIFY_SCRIPT, [fixtures.validPath]);
        expect(valid.error).toBeUndefined();
        expect(valid.status).toBe(0);
        expect(commandOutput(valid)).toContain("cryptographic consistency PASS");
        expect(commandOutput(valid)).toContain("Trust policy / H3: NOT EVALUATED");

        const tampered = runScript(VERIFY_SCRIPT, [fixtures.tamperedPath]);
        expect(tampered.error).toBeUndefined();
        expect(tampered.status).toBe(1);
        expect(commandOutput(tampered)).toContain("cryptographic consistency FAIL");
    });
});
