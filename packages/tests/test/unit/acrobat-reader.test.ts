import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { extractTimestamps, timestampPdf } from "pdf-rfc3161";
import { afterEach, describe, expect, it, vi } from "vitest";
import { makeInput, stubTsaFetch } from "../utils/timestamp-fixtures.js";
import {
    ACROBAT_ORACLE_SPAWN_TIMEOUT_MS,
    type AcrobatCaseExpectation,
    assertAcrobatCase,
    parseOracleOutput,
} from "../utils/acrobat-verdict.js";

const TEST_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const TESTS_ROOT = resolve(TEST_DIRECTORY, "../..");
const ORACLE_SCRIPT = join(TESTS_ROOT, "scripts", "acrobat-reader-oracle.ps1");

const ACROBAT_ENABLED =
    process.platform === "win32" && process.env.ACROBAT_READER_TESTS === "true";

const temporaryDirectories: string[] = [];

afterEach(() => {
    vi.unstubAllGlobals();
    for (const directory of temporaryDirectories.splice(0)) {
        rmSync(directory, { force: true, recursive: true });
    }
});

function makeCaseDirectory(): string {
    const directory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-acrobat-"));
    temporaryDirectories.push(directory);
    return directory;
}

function writeCasePdf(directory: string, name: string, pdf: Uint8Array): string {
    const path = join(directory, `${name}.pdf`);
    writeFileSync(path, pdf);
    return path;
}

async function makeTimestampedPdf(enableLTV: boolean): Promise<Uint8Array> {
    stubTsaFetch();
    const result = await timestampPdf({
        pdf: await makeInput(true),
        tsa: { url: "https://timestamp.example.test", retry: 0 },
        enableLTV,
    });
    return result.pdf;
}

async function makeTamperedCopy(pdf: Uint8Array): Promise<Uint8Array> {
    const [timestamp] = await extractTimestamps(pdf);
    if (!timestamp) throw new Error("No document timestamp found for tamper case");
    const [firstOffset, firstLength, secondOffset, secondLength] = timestamp.byteRange;
    const bytes = new Uint8Array(pdf);
    const ranges: [number, number][] = [
        [firstOffset, firstLength],
        [secondOffset, secondLength],
    ];
    for (const [offset, length] of ranges) {
        for (let index = offset; index < offset + length; index += 1) {
            if (bytes[index] === 0x20) {
                bytes[index] = 0x09;
                return bytes;
            }
        }
    }
    throw new Error("No covered ASCII space was available for the tamper case");
}

function runOracle(manifestPath: string): string {
    if (!existsSync(ORACLE_SCRIPT)) {
        throw new Error(`Acrobat oracle script is missing: ${ORACLE_SCRIPT}`);
    }
    const result = spawnSync(
        "powershell.exe",
        ["-NoLogo", "-NoProfile", "-NonInteractive", "-File", ORACLE_SCRIPT, manifestPath],
        { encoding: "utf8", timeout: ACROBAT_ORACLE_SPAWN_TIMEOUT_MS }
    );
    if (result.error) throw result.error;
    if (result.status !== 0) {
        throw new Error(
            [`acrobat oracle exited with ${String(result.status)}`, result.stdout, result.stderr]
                .filter((value) => value.length > 0)
                .join("\n")
        );
    }
    return result.stdout;
}

describe("acrobat oracle verdict contract", () => {
    const WIRE_REPORT = {
        oracle: "acrobat-reader-oracle",
        version: 1,
        reader: { product: "Acrobat Reader", version: "24.005.20320" },
        results: [
            {
                name: "unsigned",
                fields: [],
            },
            {
                name: "basic",
                fields: [
                    {
                        name: "Timestamp1",
                        fieldType: "signature",
                        validate: 3,
                        status: 3,
                        docValidity: 4,
                    },
                ],
            },
        ],
    };

    it("parses a well-formed oracle report", () => {
        const report = parseOracleOutput(JSON.stringify(WIRE_REPORT));
        expect(report.results).toHaveLength(2);
        expect(report.reader.version).toBe("24.005.20320");
        expect(report.results[1]?.fields[0]?.details).toEqual({ status: 3, docValidity: 4 });
    });

    it("rejects malformed oracle output", () => {
        expect(() => parseOracleOutput("not json")).toThrow(/acrobat oracle/i);
    });

    it("rejects a report with zero checked cases", () => {
        const empty = { ...WIRE_REPORT, results: [] };
        expect(() => parseOracleOutput(JSON.stringify(empty))).toThrow(/zero/i);
    });

    it("reads a null fields array as an empty field list", () => {
        const nulled = {
            ...WIRE_REPORT,
            results: [{ name: "unsigned", fields: null }],
        };
        const report = parseOracleOutput(JSON.stringify(nulled));
        expect(report.results[0]?.fields).toEqual([]);
    });

    it("accepts an unsigned case with no signature fields", () => {
        const report = parseOracleOutput(JSON.stringify(WIRE_REPORT));
        const unsigned = report.results[0];
        if (!unsigned) throw new Error("Test setup lost the unsigned case");
        const expectation: AcrobatCaseExpectation = { signed: false };
        expect(() => assertAcrobatCase(unsigned, expectation)).not.toThrow();
    });

    it("rejects an unsigned case that reports signature fields", () => {
        const report = parseOracleOutput(JSON.stringify(WIRE_REPORT));
        const basic = report.results[1];
        if (!basic) throw new Error("Test setup lost the basic case");
        const expectation: AcrobatCaseExpectation = { signed: false };
        expect(() => assertAcrobatCase(basic, expectation)).toThrow(/unsigned/i);
    });

    it("accepts a signed case with the expected validate code", () => {
        const report = parseOracleOutput(JSON.stringify(WIRE_REPORT));
        const basic = report.results[1];
        if (!basic) throw new Error("Test setup lost the basic case");
        const expectation: AcrobatCaseExpectation = { signed: true, validate: 3 };
        expect(() => assertAcrobatCase(basic, expectation)).not.toThrow();
    });

    it("rejects a signed case with an unexpected validate code", () => {
        const report = parseOracleOutput(JSON.stringify(WIRE_REPORT));
        const basic = report.results[1];
        if (!basic) throw new Error("Test setup lost the basic case");
        const expectation: AcrobatCaseExpectation = { signed: true, validate: 4 };
        expect(() => assertAcrobatCase(basic, expectation)).toThrow(/validate/i);
    });

    it("rejects a signed case with zero signature fields", () => {
        const report = parseOracleOutput(JSON.stringify(WIRE_REPORT));
        const unsigned = report.results[0];
        if (!unsigned) throw new Error("Test setup lost the unsigned case");
        const expectation: AcrobatCaseExpectation = { signed: true, validate: 3 };
        expect(() => assertAcrobatCase(unsigned, expectation)).toThrow(/no signature field/i);
    });
});

describe.runIf(ACROBAT_ENABLED)("Adobe Acrobat Reader oracle", () => {
    it(
        "classifies unsigned, timestamped, LTV, and tampered PDFs",
        { timeout: ACROBAT_ORACLE_SPAWN_TIMEOUT_MS + 30_000 },
        async () => {
            const directory = makeCaseDirectory();
            const unsignedPdf = await makeInput(true);
            const basicPdf = await makeTimestampedPdf(false);
            const ltvPdf = await makeTimestampedPdf(true);
            const tamperedPdf = await makeTamperedCopy(basicPdf);

            const cases: { name: string; pdf: string }[] = [
                { name: "unsigned", pdf: writeCasePdf(directory, "unsigned", unsignedPdf) },
                { name: "basic", pdf: writeCasePdf(directory, "basic", basicPdf) },
                { name: "ltv", pdf: writeCasePdf(directory, "ltv", ltvPdf) },
                { name: "tampered", pdf: writeCasePdf(directory, "tampered", tamperedPdf) },
            ];
            const manifestPath = join(directory, "manifest.json");
            writeFileSync(manifestPath, JSON.stringify({ cases }, undefined, 2));

            const report = parseOracleOutput(runOracle(manifestPath));

            const expectations: Record<string, AcrobatCaseExpectation> = {
                unsigned: { signed: false },
                basic: { signed: true, validate: 3 },
                ltv: { signed: true, validate: 3 },
                tampered: { signed: true, validate: 2 },
            };
            expect(report.results.map((result) => result.name).sort()).toEqual(
                Object.keys(expectations).sort()
            );
            for (const result of report.results) {
                const expectation = expectations[result.name];
                if (!expectation) throw new Error(`Oracle returned unknown case ${result.name}`);
                assertAcrobatCase(result, expectation);
            }
        }
    );
});
