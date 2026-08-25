import assert from "node:assert/strict";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { PDFDocument } from "pdf-lib-incremental-save";
import { TimestampSession } from "pdf-rfc3161";
import { createLocalTsa, TSA_POLICY } from "./local-tsa-fixture";
import {
    activatePadesOracleEnvironment,
    assertPadesOracleTools,
    PADES_ORACLE_POLICY,
} from "./pades-oracles.js";

const PYHANKO_VALID_JSON = '{"timestampCount":1,"intact":true,"trusted":true}';
const PINNED_ORACLE_INSTALLATION_GUIDANCE =
    "Run pnpm --filter pdf-rfc3161-tests run install:pades-oracles.";

class UsageError extends Error {}

interface ConformanceOptions {
    outputDirectory?: string;
}

function printHelp(stream: NodeJS.WriteStream = process.stdout): void {
    stream.write("Usage:\n");
    stream.write(
        "  tsx packages/tests/scripts/offline-pades-conformance.ts [--output-dir <absolute-new-directory>]\n\n"
    );
    stream.write("Run the local-root offline PAdES interoperability gate.\n\n");
    stream.write("Options:\n");
    stream.write("  --output-dir <directory>  Retain artifacts in a new absolute directory\n");
    stream.write("  -h, --help                Show this help and exit\n\n");
    stream.write("Without --output-dir, temporary artifacts are removed after the run.\n");
    stream.write(
        "A retained directory includes a disposable local root and private keys; do not share it.\n"
    );
}

function requiredValue(argv: string[], index: number, option: string): string {
    const value = argv[index + 1];
    if (value === undefined || value.length === 0 || value.startsWith("-")) {
        throw new UsageError(`${option} requires a value`);
    }
    return value;
}

function parseArguments(argv: string[]): ConformanceOptions & { help: boolean } {
    if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) {
        return { help: true };
    }

    let outputDirectory: string | undefined;
    for (let index = 0; index < argv.length; index += 1) {
        const argument = argv[index];
        if (argument === undefined) {
            throw new UsageError("Missing command-line argument");
        }
        if (argument === "--output-dir") {
            if (outputDirectory !== undefined) {
                throw new UsageError("--output-dir may only be provided once");
            }
            const value = requiredValue(argv, index, argument);
            if (!isAbsolute(value)) {
                throw new UsageError("--output-dir must be an absolute path");
            }
            outputDirectory = resolve(value);
            index += 1;
            continue;
        }
        if (argument === "--help" || argument === "-h") {
            throw new UsageError("--help must be used on its own");
        }
        if (argument.startsWith("-")) {
            throw new UsageError(`Unknown option: ${argument}`);
        }
        throw new UsageError(`Unexpected positional argument: ${argument}`);
    }
    return { help: false, ...(outputDirectory !== undefined && { outputDirectory }) };
}

function createRetainedOutputDirectory(outputDirectory: string): string {
    if (existsSync(outputDirectory)) {
        throw new UsageError(`Output directory must not already exist: ${outputDirectory}`);
    }
    const parentDirectory = dirname(outputDirectory);
    if (!existsSync(parentDirectory)) {
        throw new UsageError(`Output directory parent does not exist: ${parentDirectory}`);
    }
    try {
        mkdirSync(outputDirectory);
    } catch (error: unknown) {
        if (error instanceof Error && "code" in error && error.code === "EEXIST") {
            throw new UsageError(`Output directory must not already exist: ${outputDirectory}`);
        }
        throw error;
    }
    return outputDirectory;
}

interface PyhankoSummary {
    timestampCount: number;
    intact: boolean;
    trusted: boolean;
}

interface StructuralAssertion {
    byteRange: [number, number, number, number];
    covered: Uint8Array;
}

type QpdfValue = null | boolean | number | string | QpdfValue[] | QpdfDictionary;

interface QpdfDictionary {
    [key: string]: QpdfValue;
}

interface QpdfModel {
    objects: Map<string, QpdfDictionary>;
    trailer: QpdfDictionary;
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asQpdfDictionary(value: unknown, description: string): QpdfDictionary {
    if (!isRecord(value)) {
        throw new Error(`${description} must be a qpdf dictionary`);
    }
    return value as QpdfDictionary;
}

function commandFailure(result: SpawnSyncReturns<string>): string {
    return [result.stdout, result.stderr]
        .filter((value): value is string => typeof value === "string" && value.length > 0)
        .join("\n");
}

function run(command: string, args: string[], installGuidance: string): SpawnSyncReturns<string> {
    const result = spawnSync(command, args, { encoding: "utf8" });
    if (result.error) {
        const errno = result.error as NodeJS.ErrnoException;
        if (errno.code === "ENOENT") {
            throw new Error(
                `${command} is required for offline PAdES interoperability checks. ${installGuidance}`
            );
        }
        throw new Error(`${command} could not be started: ${result.error.message}`);
    }
    return result;
}

function assertSuccess(
    command: string,
    args: string[],
    installGuidance: string
): SpawnSyncReturns<string> {
    const result = run(command, args, installGuidance);
    assert.equal(result.status, 0, commandFailure(result));
    return result;
}

function requirePinnedPython(python: string): void {
    const version = assertSuccess(
        python,
        ["--version"],
        `Install Python ${PADES_ORACLE_POLICY.pythonVersion} and set PYTHON to its executable.`
    );
    const output = version.stdout.length > 0 ? version.stdout : version.stderr;
    assert.equal(
        output.trim(),
        `Python ${PADES_ORACLE_POLICY.pythonVersion}`,
        `Expected Python ${PADES_ORACLE_POLICY.pythonVersion}, got ${output.trim()}`
    );
}

function qpdfReferenceKey(value: QpdfValue | undefined): string | undefined {
    if (typeof value !== "string") return undefined;
    const pieces = value.split(" ");
    if (pieces.length !== 3 || pieces[2] !== "R") return undefined;
    const objectNumber = Number(pieces[0]);
    const generation = Number(pieces[1]);
    if (
        !Number.isSafeInteger(objectNumber) ||
        !Number.isSafeInteger(generation) ||
        objectNumber < 1 ||
        generation < 0
    ) {
        return undefined;
    }
    return `obj:${objectNumber.toString()} ${generation.toString()} R`;
}

function resolveQpdfReference(
    objects: Map<string, QpdfDictionary>,
    value: QpdfValue | undefined,
    description: string
): QpdfDictionary {
    const key = qpdfReferenceKey(value);
    if (!key) throw new Error(`${description} must be an indirect qpdf reference`);
    const resolved = objects.get(key);
    if (!resolved) throw new Error(`${description} refers to missing qpdf object ${key}`);
    return resolved;
}

function qpdfEntryDictionary(entry: unknown, description: string): QpdfDictionary {
    const qpdfEntry = asQpdfDictionary(entry, description);
    const value = qpdfEntry.value;
    if (value !== undefined) {
        return asQpdfDictionary(value, `${description} value`);
    }

    const stream = asQpdfDictionary(qpdfEntry.stream, `${description} stream`);
    return asQpdfDictionary(stream.dict, `${description} stream dictionary`);
}

function parseQpdfJson(text: string): QpdfModel {
    const parsed: unknown = JSON.parse(text);
    if (!isRecord(parsed)) throw new Error("qpdf JSON root must be an object");
    const qpdf = parsed.qpdf;
    if (!Array.isArray(qpdf) || qpdf.length < 2) {
        throw new Error("qpdf JSON is missing the object table");
    }
    const objectTable = asQpdfDictionary(qpdf[1], "qpdf object table");
    const objects = new Map<string, QpdfDictionary>();
    let trailer: QpdfDictionary | undefined;

    for (const [objectId, entry] of Object.entries(objectTable)) {
        const value = qpdfEntryDictionary(entry, `qpdf entry ${objectId}`);
        if (objectId === "trailer") {
            trailer = value;
        } else {
            objects.set(objectId, value);
        }
    }

    if (!trailer) throw new Error("qpdf JSON is missing the trailer");
    return { objects, trailer };
}

function byteRangeFromQpdf(value: QpdfValue | undefined): [number, number, number, number] {
    if (!Array.isArray(value) || value.length !== 4) {
        throw new Error("DocTimeStamp /ByteRange must be an array of four numbers");
    }
    const values: number[] = [];
    for (const item of value) {
        if (typeof item !== "number" || !Number.isSafeInteger(item) || item < 0) {
            throw new Error("DocTimeStamp /ByteRange must contain non-negative safe integers");
        }
        values.push(item);
    }
    const firstStart = values[0];
    const firstLength = values[1];
    const secondStart = values[2];
    const secondLength = values[3];
    if (
        firstStart === undefined ||
        firstLength === undefined ||
        secondStart === undefined ||
        secondLength === undefined
    ) {
        throw new Error("DocTimeStamp /ByteRange is incomplete");
    }
    return [firstStart, firstLength, secondStart, secondLength];
}

function assertByteRange(pdf: Uint8Array, byteRange: [number, number, number, number]): Uint8Array {
    const [firstStart, firstLength, secondStart, secondLength] = byteRange;
    assert.equal(firstStart, 0, "DocTimeStamp /ByteRange must begin at byte zero");
    assert.ok(firstLength > 0, "DocTimeStamp first ByteRange length must be positive");
    assert.ok(secondStart > firstLength, "DocTimeStamp /Contents hole must be non-empty");
    assert.ok(secondLength > 0, "DocTimeStamp second ByteRange length must be positive");
    assert.ok(
        secondStart + secondLength <= pdf.length,
        "DocTimeStamp ByteRange exceeds PDF length"
    );

    const contents = pdf.slice(firstLength, secondStart);
    assert.equal(contents[0], 0x3c, "DocTimeStamp ByteRange hole must start at /Contents <");
    assert.equal(
        contents[contents.length - 1],
        0x3e,
        "DocTimeStamp ByteRange hole must end at /Contents >"
    );
    for (let index = 1; index < contents.length - 1; index++) {
        const byte = contents[index];
        const isHex =
            byte !== undefined &&
            ((byte >= 0x30 && byte <= 0x39) ||
                (byte >= 0x41 && byte <= 0x46) ||
                (byte >= 0x61 && byte <= 0x66));
        assert.ok(isHex, "DocTimeStamp /Contents hole must contain hexadecimal bytes only");
    }

    const covered = new Uint8Array(firstLength + secondLength);
    covered.set(pdf.slice(firstStart, firstStart + firstLength));
    covered.set(pdf.slice(secondStart, secondStart + secondLength), firstLength);
    return covered;
}

function assertQpdfStructure(pdf: Uint8Array, qpdfJson: string): StructuralAssertion {
    const { objects, trailer } = parseQpdfJson(qpdfJson);
    const timestampEntries = Array.from(objects.entries()).filter(
        ([, value]) => value["/Type"] === "/DocTimeStamp"
    );
    assert.equal(timestampEntries.length, 1, "qpdf must find exactly one /Type /DocTimeStamp");
    const timestampEntry = timestampEntries[0];
    if (!timestampEntry) throw new Error("qpdf omitted the DocTimeStamp object");
    const [timestampRef, timestamp] = timestampEntry;

    assert.equal(timestamp["/SubFilter"], "/ETSI.RFC3161");
    assert.ok(
        timestamp["/V"] === undefined || timestamp["/V"] === 0,
        "DocTimeStamp /V must be absent or zero"
    );
    const byteRange = byteRangeFromQpdf(timestamp["/ByteRange"]);
    const covered = assertByteRange(pdf, byteRange);

    const signatureFields = Array.from(objects.values()).filter((value) => value["/FT"] === "/Sig");
    assert.ok(signatureFields.length > 0, "qpdf must find a /FT /Sig field");
    assert.ok(
        signatureFields.some((field) => qpdfReferenceKey(field["/V"]) === timestampRef),
        "The /FT /Sig field must refer to the DocTimeStamp value dictionary"
    );

    const catalog = resolveQpdfReference(objects, trailer["/Root"], "qpdf trailer /Root");
    assert.equal(catalog["/Type"], "/Catalog");
    assert.equal(catalog["/VRI"], undefined, "Catalog must not contain /VRI");

    const dss = resolveQpdfReference(objects, catalog["/DSS"], "Catalog /DSS");
    assert.equal(dss["/Type"], "/DSS");
    assert.equal(
        dss["/VRI"],
        undefined,
        "Automatic timestamp LTV data must not create an opt-in /DSS /VRI entry"
    );
    const certificates = dss["/Certs"];
    assert.ok(
        Array.isArray(certificates) && certificates.length > 0,
        "/DSS must contain TSA certs"
    );

    return { byteRange, covered };
}

function tamperCoveredByte(pdf: Uint8Array, firstRangeLength: number): Uint8Array {
    const tampered = new Uint8Array(pdf);
    let indexToChange: number | undefined;
    for (let index = 16; index < firstRangeLength; index++) {
        if (tampered[index] === 0x0a) {
            indexToChange = index;
            break;
        }
    }
    if (indexToChange === undefined) {
        throw new Error("Could not locate a covered PDF whitespace byte to tamper");
    }
    tampered[indexToChange] = 0x0d;
    return tampered;
}

function parsePyhankoSummary(output: string): PyhankoSummary {
    const parsed: unknown = JSON.parse(output);
    if (!isRecord(parsed)) throw new Error("pyHanko verifier did not return a JSON object");
    const timestampCount = parsed.timestampCount;
    const intact = parsed.intact;
    const trusted = parsed.trusted;
    if (
        typeof timestampCount !== "number" ||
        typeof intact !== "boolean" ||
        typeof trusted !== "boolean"
    ) {
        throw new Error("pyHanko verifier JSON is missing timestampCount, intact, or trusted");
    }
    return { timestampCount, intact, trusted };
}

async function runConformance(options: ConformanceOptions): Promise<void> {
    const python = process.env.PYTHON ?? "python";
    const workingDirectory =
        options.outputDirectory === undefined
            ? mkdtempSync(join(tmpdir(), "pdf-rfc3161-pades-"))
            : createRetainedOutputDirectory(options.outputDirectory);
    const retainArtifacts = options.outputDirectory !== undefined;

    try {
        activatePadesOracleEnvironment();
        assertPadesOracleTools();
        requirePinnedPython(python);

        const { rootCert, config } = createLocalTsa(workingDirectory);
        const requestPath = join(workingDirectory, "request.tsq");
        const responsePath = join(workingDirectory, "response.tsr");
        const timestampedPdfPath = join(workingDirectory, "timestamped.pdf");
        const coveredPath = join(workingDirectory, "covered.bin");
        const tamperedPdfPath = join(workingDirectory, "tampered.pdf");
        const tamperedCoveredPath = join(workingDirectory, "tampered-covered.bin");
        const wrongDataPath = join(workingDirectory, "wrong-data.bin");
        const verifierPath = join(process.cwd(), "scripts", "verify-pades.py");

        const document = await PDFDocument.create();
        const page = document.addPage([200, 200]);
        page.drawText("Offline PAdES interoperability", { x: 20, y: 100, size: 14 });
        const originalPdf = await document.save();

        const session = new TimestampSession(originalPdf, {
            enableLTV: true,
            prepareOptions: { signatureSize: 16384 },
        });
        const request = await session.createTimestampRequest({
            hashAlgorithm: "SHA-256",
            policy: TSA_POLICY,
            requestCertificate: true,
        });
        writeFileSync(requestPath, request);

        const response = assertSuccess(
            "openssl",
            ["ts", "-reply", "-queryfile", requestPath, "-config", config, "-out", responsePath],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        );
        assert.equal(response.status, 0, response.stderr);
        const responseBytes = new Uint8Array(readFileSync(responsePath));

        const wrongSession = new TimestampSession(originalPdf, {
            enableLTV: true,
            prepareOptions: { signatureSize: 16384 },
        });
        await wrongSession.createTimestampRequest({
            hashAlgorithm: "SHA-256",
            policy: TSA_POLICY,
            requestCertificate: true,
        });
        let wrongTokenRejected = false;
        try {
            await wrongSession.embedTimestampToken(responseBytes);
        } catch {
            wrongTokenRejected = true;
        }
        assert.equal(
            wrongTokenRejected,
            true,
            "Session must reject a response for a different request"
        );

        const timestampedPdf = await session.embedTimestampToken(responseBytes);
        writeFileSync(timestampedPdfPath, timestampedPdf);

        const qpdf = run(
            "qpdf",
            ["--check", timestampedPdfPath],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        );
        assert.equal(qpdf.status, 0, qpdf.stderr);
        const qpdfJson = assertSuccess(
            "qpdf",
            ["--json", timestampedPdfPath],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        ).stdout;
        assert.match(qpdfJson, /DocTimeStamp/);
        assert.match(qpdfJson, /ETSI\.RFC3161/);
        const structural = assertQpdfStructure(timestampedPdf, qpdfJson);
        writeFileSync(coveredPath, structural.covered);

        const pyhanko = run(
            python,
            [verifierPath, timestampedPdfPath, rootCert],
            "Install hash-locked pyHanko 0.36.2 with uv pip install --system --require-hashes -r packages/tests/python/requirements.lock."
        );
        assert.equal(pyhanko.status, 0, pyhanko.stderr);
        assert.equal(
            pyhanko.stdout.trimEnd(),
            PYHANKO_VALID_JSON,
            "pyHanko verifier must use its JSON-only stdout contract"
        );
        const pyhankoSummary = parsePyhankoSummary(pyhanko.stdout);
        assert.equal(pyhankoSummary.timestampCount, 1);
        assert.equal(pyhankoSummary.intact, true);
        assert.equal(pyhankoSummary.trusted, true);

        const opensslQueryVerify = run(
            "openssl",
            ["ts", "-verify", "-queryfile", requestPath, "-in", responsePath, "-CAfile", rootCert],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        );
        assert.equal(opensslQueryVerify.status, 0, opensslQueryVerify.stderr);
        const opensslVerify = run(
            "openssl",
            ["ts", "-verify", "-data", coveredPath, "-in", responsePath, "-CAfile", rootCert],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        );
        assert.equal(opensslVerify.status, 0, opensslVerify.stderr);

        const tamperedPdf = tamperCoveredByte(timestampedPdf, structural.byteRange[1]);
        writeFileSync(tamperedPdfPath, tamperedPdf);
        const tamperedCovered = assertByteRange(tamperedPdf, structural.byteRange);
        writeFileSync(tamperedCoveredPath, tamperedCovered);

        const tamperedPyhanko = run(
            python,
            [verifierPath, tamperedPdfPath, rootCert],
            "Install hash-locked pyHanko 0.36.2 with uv pip install --system --require-hashes -r packages/tests/python/requirements.lock."
        );
        assert.notEqual(tamperedPyhanko.status, 0, tamperedPyhanko.stderr);
        const tamperedOpenSsl = run(
            "openssl",
            [
                "ts",
                "-verify",
                "-data",
                tamperedCoveredPath,
                "-in",
                responsePath,
                "-CAfile",
                rootCert,
            ],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        );
        assert.notEqual(tamperedOpenSsl.status, 0, tamperedOpenSsl.stderr);

        const wrongData = new Uint8Array(structural.covered);
        const firstByte = wrongData[0];
        if (firstByte === undefined) throw new Error("Covered data must not be empty");
        wrongData[0] = firstByte ^ 0x01;
        writeFileSync(wrongDataPath, wrongData);
        const wrongDataOpenSsl = run(
            "openssl",
            ["ts", "-verify", "-data", wrongDataPath, "-in", responsePath, "-CAfile", rootCert],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        );
        assert.notEqual(wrongDataOpenSsl.status, 0, wrongDataOpenSsl.stderr);

        process.stdout.write("Offline PAdES interoperability checks passed.\n");
        if (retainArtifacts) {
            process.stdout.write(`Retained local validation artifacts in ${workingDirectory}\n`);
        }
    } finally {
        if (!retainArtifacts) {
            rmSync(workingDirectory, { recursive: true, force: true });
        }
    }
}

async function main(): Promise<void> {
    const options = parseArguments(process.argv.slice(2));
    if (options.help) {
        printHelp();
        return;
    }
    await runConformance(options);
}

void main().catch((error: unknown) => {
    if (error instanceof UsageError) {
        process.stderr.write(`Error: ${error.message}\n\n`);
        printHelp(process.stderr);
        process.exitCode = 2;
        return;
    }
    console.error(error instanceof Error ? (error.stack ?? error.message) : String(error));
    process.exitCode = 1;
});
