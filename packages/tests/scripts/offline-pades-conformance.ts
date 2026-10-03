import assert from "node:assert/strict";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { PDFDocument } from "pdf-lib-incremental-save";
import {
    CertificateStatus,
    SimpleTrustStore,
    TimestampSession,
    extractTimestamps,
    verifyPdfTimestamps,
    verifyTimestamp,
    type ExtractedTimestamp,
    type HashAlgorithm,
    type TimestampInfo,
} from "pdf-rfc3161";
import { MockFetcher, ValidationSession } from "pdf-rfc3161/advanced";
import type { RevocationDataFetcher } from "pdf-rfc3161/advanced";
import {
    addVRIForSignature,
    parseCRLInfo,
    parseOCSPResponse,
} from "pdf-rfc3161/internals";
import {
    extractSignatures,
    verify as verifyWithVerifiedBy,
    type VerifyElement,
} from "verifiedby";
import {
    HISTORICAL_TSP_METADATA,
    HISTORICAL_TSP_PDF_BASE64,
    HISTORICAL_TSP_REQUEST_BASE64,
    HISTORICAL_TSP_RESPONSE_BASE64,
    HISTORICAL_TSP_ROOT_BASE64,
    HISTORICAL_TSP_TSA_BASE64,
    decodeHistoricalTsp,
} from "../test/fixtures/historical-tsp-interop.js";
import {
    OPENSSL_INTEROP_CA_BASE64,
    OPENSSL_INTEROP_EMPTY_CRL_BASE64,
    OPENSSL_INTEROP_LEAF_BASE64,
    OPENSSL_INTEROP_REVOKED_CRL_BASE64,
    decodeInteropDer,
} from "../test/fixtures/openssl-crl-interop.js";
import {
    createSignedCRL,
    createTestCA,
    createTestLeaf,
    crlNumberExtension,
    deltaCrlIndicatorExtension,
    issuingDistributionPointExtension,
} from "../test/fixtures/signed-revocation-material.js";
import { createLocalTsa, createUnrelatedTrustAnchor, TSA_POLICY } from "./local-tsa-fixture";
import {
    activatePadesOracleEnvironment,
    assertPadesOracleTools,
    PADES_ORACLE_POLICY,
} from "./pades-oracles.js";

const PINNED_ORACLE_INSTALLATION_GUIDANCE =
    "Run pnpm --filter pdf-rfc3161-tests run install:pades-oracles.";
const PYHANKO_INSTALL_GUIDANCE =
    "Install hash-locked pyHanko with uv pip install --system --require-hashes -r packages/tests/python/requirements.lock.";
const EXPECTED_PYHANKO_VERSION = "0.37.0";
const EXPECTED_CERTVALIDATOR_VERSION = "0.32.0";
const EXPECTED_VERIFIEDBY_VERSION = "0.1.0";
const ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OCSP_URL = "http://ocsp.example.com/";
const CRL_URL = "http://crl.example.com/tsa.crl";
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const SIGNATURE_SIZE = 16384;

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
    stream.write(
        "It also carries conformance-report.json: engine versions, per-case verdicts,\n"
    );
    stream.write("artifact hashes, and recorded oracle limitations.\n");
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
interface PyhankoTimestampVerdict {
    index: number;
    intact: boolean;
    trusted: boolean;
}

interface PyhankoSummary {
    timestampCount: number;
    intact: boolean;
    trusted: boolean;
    timestamps: PyhankoTimestampVerdict[];
}

interface SignatureCoverage {
    objectId: string;
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

interface EngineVersions {
    openssl: string;
    qpdf: string;
    python: string;
    pyhanko: string;
    certvalidator: string;
    verifiedby: string;
}

interface LedgerEntry {
    section: string;
    oracle: string;
    name: string;
    expected: string;
    actual: string;
}

interface ConformanceArtifact {
    file: string;
    sha256: string;
    bytes: number;
    role: string;
}

class ConformanceLedger {
    entries: LedgerEntry[] = [];
    artifacts: ConformanceArtifact[] = [];
    caseCounts = new Map<string, number>();

    record(
        section: string,
        oracle: string,
        name: string,
        expected: string,
        actual: string
    ): void {
        this.entries.push({ section, oracle, name, expected, actual });
        for (const key of [`section:${section}`, `oracle:${oracle}`, "total"]) {
            this.caseCounts.set(key, (this.caseCounts.get(key) ?? 0) + 1);
        }
    }

    artifact(workdir: string, path: string, role: string): void {
        const bytes = new Uint8Array(readFileSync(path));
        this.artifacts.push({
            file: path.startsWith(`${workdir}/`) ? path.slice(workdir.length + 1) : path,
            sha256: sha256Hex(bytes),
            bytes: bytes.length,
            role,
        });
    }

    count(key: string): number {
        return this.caseCounts.get(key) ?? 0;
    }
}

interface SectionContext {
    workdir: string;
    python: string;
    verifierPath: string;
    ledger: ConformanceLedger;
}

function sha256Hex(bytes: Uint8Array): string {
    return createHash("sha256").update(bytes).digest("hex");
}

function pemToDer(pem: string): Uint8Array {
    const base64 = pem
        .replace(/-----[^-]{1,64}-----/g, "")
        .replace(/\s{1,1024}/g, "");
    return new Uint8Array(Buffer.from(base64, "base64"));
}

function readPemDer(path: string): Uint8Array {
    return pemToDer(readFileSync(path, "utf8"));
}

function pkijsCertificateFromDer(der: Uint8Array): pkijs.Certificate {
    const parsed = asn1js.fromBER(der.slice().buffer);
    if (parsed.offset === -1) throw new Error("Certificate bytes are not DER");
    return new pkijs.Certificate({ schema: parsed.result });
}

/**
 * Length of one definite-length DER TLV at the start of `bytes`. PDF
 * /Contents reserves fixed-width hex, so only the bytes inside this TLV
 * are the embedded token; anything after it must be zero padding.
 */
function derTlvLength(bytes: Uint8Array): number {
    if (bytes.length < 2) throw new Error("DER value is truncated");
    const firstLength = bytes[1];
    if (firstLength === undefined) throw new Error("DER value is truncated");
    if (firstLength < 0x80) return 2 + firstLength;
    const lengthBytes = firstLength & 0x7f;
    if (lengthBytes === 0 || lengthBytes > 4) {
        throw new Error("DER length is indefinite or oversized");
    }
    if (bytes.length < 2 + lengthBytes) throw new Error("DER value is truncated");
    let length = 0;
    for (let index = 0; index < lengthBytes; index++) {
        const byte = bytes[2 + index];
        if (byte === undefined) throw new Error("DER value is truncated");
        length = length * 256 + byte;
    }
    return 2 + lengthBytes + length;
}

function stripZeroPadding(padded: Uint8Array, description: string): Uint8Array {
    const contentLength = derTlvLength(padded);
    if (contentLength > padded.length) {
        throw new Error(`${description} DER length exceeds its container`);
    }
    for (let index = contentLength; index < padded.length; index++) {
        assert.equal(padded[index], 0, `${description} padding must be zero bytes`);
    }
    return padded.slice(0, contentLength);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
    if (left.length !== right.length) return false;
    for (let index = 0; index < left.length; index++) {
        if (left[index] !== right[index]) return false;
    }
    return true;
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

function requirePinnedPython(python: string): string {
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
    return output.trim();
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

function qpdfObjectNumber(objectId: string): number {
    const match = /^obj:([0-9]{1,10}) [0-9]{1,10} R$/.exec(objectId);
    if (!match?.[1]) throw new Error(`Unexpected qpdf object id ${objectId}`);
    return Number(match[1]);
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
/**
 * Verifies EVERY DocTimeStamp in the file (never exactly-one) and
 * extracts each covered range independently. Signatures come back in
 * file order (oldest first): hole-start order must agree with qpdf
 * object-number order, and verifiedby's independent extraction must
 * report the same ranges.
 */
function assertQpdfMultiStructure(
    pdf: Uint8Array,
    qpdfJson: string,
    expectedCount: number,
    options: { expectVri: boolean } = { expectVri: false }
): SignatureCoverage[] {
    const { objects, trailer } = parseQpdfJson(qpdfJson);
    const timestampEntries = Array.from(objects.entries()).filter(
        ([, value]) => value["/Type"] === "/DocTimeStamp"
    );
    assert.equal(
        timestampEntries.length,
        expectedCount,
        `qpdf must find ${expectedCount.toString()} /Type /DocTimeStamp entries`
    );

    const coverages: SignatureCoverage[] = timestampEntries.map(([objectId, timestamp]) => {
        assert.equal(timestamp["/SubFilter"], "/ETSI.RFC3161", `${objectId} SubFilter`);
        assert.ok(
            timestamp["/V"] === undefined || timestamp["/V"] === 0,
            `${objectId} /V must be absent or zero`
        );
        const byteRange = byteRangeFromQpdf(timestamp["/ByteRange"]);
        return { objectId, byteRange, covered: assertByteRange(pdf, byteRange) };
    });
    coverages.sort((left, right) => left.byteRange[1] - right.byteRange[1]);
    const objectOrder = [...coverages].sort(
        (left, right) => qpdfObjectNumber(left.objectId) - qpdfObjectNumber(right.objectId)
    );
    assert.deepEqual(
        coverages.map((coverage) => coverage.objectId),
        objectOrder.map((coverage) => coverage.objectId),
        "hole-start order must agree with qpdf object-number order"
    );

    const signatureFields = Array.from(objects.values()).filter((value) => value["/FT"] === "/Sig");
    assert.ok(signatureFields.length >= expectedCount, "qpdf must find every /FT /Sig field");
    for (const coverage of coverages) {
        assert.ok(
            signatureFields.some((field) => qpdfReferenceKey(field["/V"]) === coverage.objectId),
            `A /FT /Sig field must refer to ${coverage.objectId}`
        );
    }

    const catalog = resolveQpdfReference(objects, trailer["/Root"], "qpdf trailer /Root");
    assert.equal(catalog["/Type"], "/Catalog");
    if (!options.expectVri) {
        assert.equal(catalog["/VRI"], undefined, "Catalog must not contain /VRI");
    }

    const dss = resolveQpdfReference(objects, catalog["/DSS"], "Catalog /DSS");
    assert.equal(dss["/Type"], "/DSS");
    if (!options.expectVri) {
        assert.equal(
            dss["/VRI"],
            undefined,
            "Automatic timestamp LTV data must not create an opt-in /DSS /VRI entry"
        );
    }
    const certificates = dss["/Certs"];
    assert.ok(
        Array.isArray(certificates) && certificates.length > 0,
        "/DSS must contain TSA certs"
    );

    return coverages;
}

function runBytes(
    command: string,
    args: string[],
    installGuidance: string
): { status: number | null; stdout: Uint8Array; stderr: string } {
    const result = spawnSync(command, args);
    if (result.error) {
        const errno = result.error as NodeJS.ErrnoException;
        if (errno.code === "ENOENT") {
            throw new Error(
                `${command} is required for offline PAdES interoperability checks. ${installGuidance}`
            );
        }
        throw new Error(`${command} could not be started: ${result.error.message}`);
    }
    return {
        status: result.status,
        stdout: new Uint8Array(result.stdout as Buffer),
        stderr: (result.stderr as Buffer).toString("utf8"),
    };
}

function inIntervals(offset: number, intervals: [number, number][]): boolean {
    return intervals.some(([start, end]) => offset >= start && offset < end);
}

function coverageIntervals(byteRange: [number, number, number, number]): [number, number][] {
    return [
        [byteRange[0], byteRange[0] + byteRange[1]],
        [byteRange[2], byteRange[2] + byteRange[3]],
    ];
}

/**
 * Flips one covered PDF-whitespace byte (0x0a to 0x0d) inside `target`
 * but outside every `exclude` range, so the file still parses while its
 * digest changes. Returns the tampered copy and the flipped offset.
 */
function tamperCoveredWhitespace(
    pdf: Uint8Array,
    target: [number, number, number, number],
    exclude: [number, number, number, number][] = []
): { tampered: Uint8Array; offset: number } {
    const excluded = exclude.flatMap((range) => coverageIntervals(range));
    for (const [start, end] of coverageIntervals(target)) {
        for (let offset = Math.max(start, 16); offset < Math.min(end, pdf.length); offset++) {
            if (pdf[offset] === 0x0a && !inIntervals(offset, excluded)) {
                const tampered = new Uint8Array(pdf);
                tampered[offset] = 0x0d;
                return { tampered, offset };
            }
        }
    }
    throw new Error("Could not locate a tamperable covered PDF whitespace byte");
}

function issueTsReply(requestPath: string, config: string, responsePath: string): void {
    assertSuccess(
        "openssl",
        ["ts", "-reply", "-queryfile", requestPath, "-config", config, "-out", responsePath],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
}

function extractRawToken(responsePath: string, tokenPath: string): void {
    assertSuccess(
        "openssl",
        ["ts", "-reply", "-in", responsePath, "-token_out", "-out", tokenPath],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
}

/** Reads the multi-line `Message data` hexdump from `openssl ts -text` as hex. */
function opensslTextMessageData(text: string, expectedHexLength: number): string {
    const lines = text.split("\n");
    const start = lines.findIndex((line) => line.trim() === "Message data:");
    if (start === -1) throw new Error("openssl text output is missing Message data");
    const bytes: string[] = [];
    for (let index = start + 1; index < lines.length; index++) {
        const line = lines[index] ?? "";
        const dump = /^\s*[0-9a-fA-F]{4} - (.*)$/.exec(line);
        if (!dump?.[1]) break;
        // eslint-disable-next-line security/detect-unsafe-regex -- bounded {1,32} over disjoint hex/space classes on short oracle lines
        const hex = /^((?:[0-9a-fA-F]{2} ?){1,32})/.exec(dump[1].replace(/-/g, " "));
        if (!hex?.[1]) break;
        bytes.push(hex[1].replace(/[^0-9a-fA-F]/g, "").toUpperCase());
    }
    const joined = bytes.join("");
    if (joined.length === 0) throw new Error("openssl Message data block is empty");
    assert.equal(
        joined.length,
        expectedHexLength,
        "openssl Message data length must match the digest size"
    );
    return joined;
}

/** Reads one `Label: value` line from `openssl ts -query/-reply -text`. */
function opensslTextField(text: string, label: string): string {
    const line = text
        .split("\n")
        .map((candidate) => candidate.trim())
        .find((candidate) => candidate.startsWith(`${label}:`));
    if (line === undefined) throw new Error(`openssl text output is missing ${label}`);
    const value = line.slice(label.length + 1).trim();
    if (value.length === 0) throw new Error(`openssl text field ${label} is empty`);
    return value;
}

function parseIso8601Epoch(value: string, description: string): number {
    const match = /^([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/.exec(
        value.trim()
    );
    if (!match?.[1]) throw new Error(`${description} has an unexpected date format: ${value}`);
    const parts = match.slice(1, 7).map((part) => Number(part));
    if (parts.some((part) => !Number.isSafeInteger(part))) {
        throw new Error(`${description} has a non-numeric date: ${value}`);
    }
    const [year, month, day, hour, minute, second] = parts as [
        number,
        number,
        number,
        number,
        number,
        number,
    ];
    return Math.floor(Date.UTC(year, month - 1, day, hour, minute, second) / 1000);
}

function certValidityEpochs(certPath: string): { notBefore: number; notAfter: number } {
    const output = assertSuccess(
        "openssl",
        ["x509", "-in", certPath, "-noout", "-startdate", "-enddate", "-dateopt", "iso_8601"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    ).stdout;
    const lines = output.split("\n");
    const startLine = lines.find((line) => line.startsWith("notBefore="));
    const endLine = lines.find((line) => line.startsWith("notAfter="));
    if (startLine === undefined || endLine === undefined) {
        throw new Error(`Could not read validity dates from ${certPath}`);
    }
    return {
        notBefore: parseIso8601Epoch(startLine.slice("notBefore=".length), "notBefore"),
        notAfter: parseIso8601Epoch(endLine.slice("notAfter=".length), "notAfter"),
    };
}

function certSerialHex(certPath: string): string {
    const output = assertSuccess(
        "openssl",
        ["x509", "-in", certPath, "-noout", "-serial"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    ).stdout.trim();
    const match = /^serial=([0-9A-Fa-f]{1,128})$/.exec(output);
    if (!match?.[1]) throw new Error(`Could not read the serial of ${certPath}`);
    return match[1].toUpperCase();
}

/** Appends extra certificates to a token's unsigned CMS certificate bag. */
function poisonTokenBag(rawToken: Uint8Array, extra: readonly pkijs.Certificate[]): Uint8Array {
    const parsed = asn1js.fromBER(rawToken.slice().buffer);
    if (parsed.offset === -1) throw new Error("Token bytes are not DER");
    const contentInfo = new pkijs.ContentInfo({ schema: parsed.result });
    const signedData = new pkijs.SignedData({ schema: contentInfo.content });
    if (signedData.certificates === undefined) {
        throw new Error("Token has no certificate bag to poison");
    }
    signedData.certificates.push(...extra);
    return new Uint8Array(
        new pkijs.ContentInfo({
            contentType: ID_SIGNED_DATA,
            content: signedData.toSchema(),
        })
            .toSchema()
            .toBER(false)
    );
}

/** Rewraps a token into its TimeStampResp for the embed flow. */
function rewrapResponse(response: Uint8Array, token: Uint8Array): Uint8Array {
    const responseSchema = asn1js.fromBER(response.slice().buffer);
    if (responseSchema.offset === -1) throw new Error("Response bytes are not DER");
    const timeStampResp = new pkijs.TimeStampResp({ schema: responseSchema.result });
    const tokenSchema = asn1js.fromBER(token.slice().buffer);
    if (tokenSchema.offset === -1) throw new Error("Token bytes are not DER");
    timeStampResp.timeStampToken = new pkijs.ContentInfo({ schema: tokenSchema.result });
    return new Uint8Array(timeStampResp.toSchema().toBER(false));
}

/** Extracts the raw TSTInfo bytes from a token's SignedData eContent. */
function tstInfoBytes(rawToken: Uint8Array): Uint8Array {
    const parsed = asn1js.fromBER(rawToken.slice().buffer);
    if (parsed.offset === -1) throw new Error("Token bytes are not DER");
    const contentInfo = new pkijs.ContentInfo({ schema: parsed.result });
    const signedData = new pkijs.SignedData({ schema: contentInfo.content });
    const eContent = signedData.encapContentInfo.eContent;
    if (eContent === undefined) {
        throw new Error("Token eContent is not an OCTET STRING");
    }
    if (eContent.idBlock.tagClass !== 1 || eContent.idBlock.tagNumber !== 4) {
        throw new Error("Token eContent is not an OCTET STRING");
    }
    return new Uint8Array(eContent.valueBlock.valueHexView.slice());
}
function parsePyhankoSummary(output: string): PyhankoSummary {
    const parsed: unknown = JSON.parse(output);
    if (!isRecord(parsed)) throw new Error("pyHanko verifier did not return a JSON object");
    const timestampCount = parsed.timestampCount;
    const intact = parsed.intact;
    const trusted = parsed.trusted;
    const timestamps = parsed.timestamps;
    if (
        typeof timestampCount !== "number" ||
        typeof intact !== "boolean" ||
        typeof trusted !== "boolean" ||
        !Array.isArray(timestamps)
    ) {
        throw new Error("pyHanko verifier JSON is missing timestampCount, intact, or trusted");
    }
    const verdicts: PyhankoTimestampVerdict[] = timestamps.map((entry: unknown) => {
        if (!isRecord(entry)) throw new Error("pyHanko per-timestamp entry is not an object");
        if (
            typeof entry.index !== "number" ||
            typeof entry.intact !== "boolean" ||
            typeof entry.trusted !== "boolean"
        ) {
            throw new Error("pyHanko per-timestamp entry is malformed");
        }
        return { index: entry.index, intact: entry.intact, trusted: entry.trusted };
    });
    if (verdicts.length !== timestampCount) {
        throw new Error("pyHanko timestampCount disagrees with its verdict list");
    }
    return { timestampCount, intact, trusted, timestamps: verdicts };
}

function runPyhanko(
    ctx: SectionContext,
    pdfPath: string,
    rootCert: string,
    extraArgs: string[] = []
): { status: number | null; summary: PyhankoSummary; stderr: string } {
    const result = run(
        ctx.python,
        [ctx.verifierPath, pdfPath, rootCert, ...extraArgs],
        PYHANKO_INSTALL_GUIDANCE
    );
    const stdout = result.stdout.trim();
    if (stdout.length === 0) {
        throw new Error(`pyHanko verifier printed no JSON: ${commandFailure(result)}`);
    }
    return {
        status: result.status,
        summary: parsePyhankoSummary(stdout),
        stderr: result.stderr,
    };
}

function pyhankoVersions(python: string, verifierPath: string): { pyhanko: string; certvalidator: string } {
    const result = assertSuccess(
        python,
        [verifierPath, "--version"],
        PYHANKO_INSTALL_GUIDANCE
    );
    const parsed: unknown = JSON.parse(result.stdout.trim());
    if (!isRecord(parsed)) throw new Error("pyHanko --version did not return a JSON object");
    if (parsed.pyhanko !== EXPECTED_PYHANKO_VERSION) {
        throw new Error(
            `Expected pyHanko ${EXPECTED_PYHANKO_VERSION}, got ${String(parsed.pyhanko)}`
        );
    }
    if (parsed.certvalidator !== EXPECTED_CERTVALIDATOR_VERSION) {
        throw new Error(
            `Expected pyhanko-certvalidator ${EXPECTED_CERTVALIDATOR_VERSION}, got ${String(parsed.certvalidator)}`
        );
    }
    return {
        pyhanko: EXPECTED_PYHANKO_VERSION,
        certvalidator: EXPECTED_CERTVALIDATOR_VERSION,
    };
}

function verifiedbyVersion(): string {
    const entryPath = fileURLToPath(import.meta.resolve("verifiedby"));
    const normalized = entryPath.replace(/\\/g, "/");
    if (!normalized.endsWith("/verifiedby/src/verify-core.mjs")) {
        throw new Error(`Unexpected verifiedby entry point: ${entryPath}`);
    }
    const packagePath = join(dirname(dirname(entryPath)), "package.json");
    const pkg: unknown = JSON.parse(readFileSync(packagePath, "utf8"));
    if (!isRecord(pkg) || pkg.version !== EXPECTED_VERIFIEDBY_VERSION) {
        throw new Error(
            `Expected verifiedby ${EXPECTED_VERIFIEDBY_VERSION}, got ${isRecord(pkg) ? String(pkg.version) : "unknown"}`
        );
    }
    return EXPECTED_VERIFIEDBY_VERSION;
}

function collectEngineVersions(ctx: SectionContext): EngineVersions {
    const openssl = assertSuccess(
        "openssl",
        ["version"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    ).stdout.trim();
    assert.ok(
        openssl.startsWith(`OpenSSL ${PADES_ORACLE_POLICY.openssl.commandVersion} `),
        `Unexpected pinned OpenSSL banner: ${openssl}`
    );
    const qpdfFirstLine = assertSuccess(
        "qpdf",
        ["--version"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    )
        .stdout.trim()
        .split("\n")[0];
    assert.equal(
        qpdfFirstLine,
        `qpdf version ${PADES_ORACLE_POLICY.qpdf.commandVersion}`,
        "Unexpected pinned qpdf banner"
    );
    const python = requirePinnedPython(ctx.python);
    const { pyhanko, certvalidator } = pyhankoVersions(ctx.python, ctx.verifierPath);
    return {
        openssl,
        qpdf: qpdfFirstLine,
        python,
        pyhanko,
        certvalidator,
        verifiedby: verifiedbyVersion(),
    };
}

interface VerifiedElementExpectation {
    documentMatches: boolean;
    anchored: boolean;
    hashAlg?: string;
}

function assertVerifiedByElement(
    element: VerifyElement | undefined,
    expected: VerifiedElementExpectation,
    description: string
): void {
    assert.ok(element !== undefined, `${description} is missing`);
    assert.equal(element.kind, "doctimestamp", `${description} kind`);
    assert.equal(element.supported, true, `${description} supported`);
    assert.equal(element.documentMatches, expected.documentMatches, `${description} documentMatches`);
    assert.equal(element.signatureValid, true, `${description} signatureValid`);
    assert.equal(element.attrsCommit, true, `${description} attrsCommit`);
    assert.equal(element.chainValid, true, `${description} chainValid`);
    assert.equal(element.withinValidity, true, `${description} withinValidity`);
    // `authentic` covers CMS authenticity only (signatureValid &&
    // attrsCommit && chainValid && withinValidity); documentMatches is
    // the covered-byte tamper signal.
    assert.equal(element.authentic, true, `${description} authentic`);
    assert.equal(element.anchored, expected.anchored, `${description} anchored`);
    assert.equal(element.time?.trusted, true, `${description} time.trusted`);
    if (expected.hashAlg !== undefined) {
        assert.equal(element.hashAlg, expected.hashAlg, `${description} hashAlg`);
    }
    if (expected.documentMatches) {
        assert.equal(element.imprint, element.computed, `${description} imprint equals computed`);
    } else {
        assert.notEqual(
            element.imprint,
            element.computed,
            `${description} tamper must split imprint from computed`
        );
    }
}

function writeArtifact(ctx: SectionContext, name: string, bytes: Uint8Array, role: string): string {
    const path = join(ctx.workdir, name);
    writeFileSync(path, bytes);
    ctx.ledger.artifact(ctx.workdir, path, role);
    return path;
}

async function createOnePagePdf(label: string): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    const page = document.addPage([200, 200]);
    page.drawText(label, { x: 20, y: 100, size: 14 });
    return document.save();
}

interface StampedCase {
    request: Uint8Array;
    response: Uint8Array;
    pdf: Uint8Array;
    requestPath: string;
    responsePath: string;
    pdfPath: string;
}

/** Runs one TimestampSession against a local TSA directory and retains every artifact. */
async function stampWithLocalTsa(
    ctx: SectionContext,
    tag: string,
    inputPdf: Uint8Array,
    tsaConfig: string,
    hashAlgorithm: HashAlgorithm
): Promise<StampedCase> {
    const session = new TimestampSession(inputPdf, {
        enableLTV: true,
        prepareOptions: { signatureSize: SIGNATURE_SIZE },
    });
    const request = await session.createTimestampRequest({
        hashAlgorithm,
        policy: TSA_POLICY,
        requestCertificate: true,
    });
    const requestPath = writeArtifact(ctx, `${tag}.tsq`, request, "original TimeStampReq");
    const responsePath = join(ctx.workdir, `${tag}.tsr`);
    issueTsReply(requestPath, tsaConfig, responsePath);
    const response = new Uint8Array(readFileSync(responsePath));
    ctx.ledger.artifact(ctx.workdir, responsePath, "TimeStampResp for retained TimeStampReq");
    const pdf = await session.embedTimestampToken(response);
    const pdfPath = writeArtifact(ctx, `${tag}.pdf`, pdf, "signed PDF");
    return { request, response, pdf, requestPath, responsePath, pdfPath };
}
interface SingleSignatureExpectation {
    tag: string;
    stamped: StampedCase;
    rootCert: string;
    rootDer: Uint8Array;
    hashAlgorithm: HashAlgorithm;
    opensslHashName: string;
}

/**
 * Qualifies one single-signature PDF with every engine: qpdf structure
 * plus an independently extracted covered range, OpenSSL ts against the
 * original TSQ / covered bytes / raw token, TSQ/TSR -text agreement,
 * pyHanko, verifiedby (unanchored and anchored), C05 token byte equality,
 * library extraction/verification, and tamper plus wrong-data negatives.
 */
async function verifySingleSignatureCase(
    ctx: SectionContext,
    section: string,
    expected: SingleSignatureExpectation
): Promise<void> {
    const { tag, stamped, rootCert, rootDer, hashAlgorithm, opensslHashName } = expected;
    const { ledger } = ctx;

    const qpdfCheck = run("qpdf", ["--check", stamped.pdfPath], PINNED_ORACLE_INSTALLATION_GUIDANCE);
    assert.equal(qpdfCheck.status, 0, qpdfCheck.stderr);
    ledger.record(section, "qpdf", `${tag} --check`, "status 0", "status 0");
    const qpdfJson = assertSuccess(
        "qpdf",
        ["--json", stamped.pdfPath],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    ).stdout;
    assert.match(qpdfJson, /DocTimeStamp/);
    assert.match(qpdfJson, /ETSI\.RFC3161/);
    const [coverage] = assertQpdfMultiStructure(stamped.pdf, qpdfJson, 1);
    if (!coverage) throw new Error(`${tag} is missing its DocTimeStamp coverage`);
    ledger.record(section, "qpdf", `${tag} structure`, "1 ETSI.RFC3161 range", "1 ETSI.RFC3161 range");
    const coveredPath = writeArtifact(ctx, `${tag}-covered.bin`, coverage.covered, "covered bytes");

    const queryVerify = run(
        "openssl",
        ["ts", "-verify", "-queryfile", stamped.requestPath, "-in", stamped.responsePath, "-CAfile", rootCert],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.equal(queryVerify.status, 0, commandFailure(queryVerify));
    ledger.record(section, "openssl-ts", `${tag} TSR against original TSQ`, "Verification: OK", "Verification: OK");

    const queryText = assertSuccess(
        "openssl",
        ["ts", "-query", "-in", stamped.requestPath, "-text"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    ).stdout;
    const replyText = assertSuccess(
        "openssl",
        ["ts", "-reply", "-in", stamped.responsePath, "-text"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    ).stdout;
    assert.equal(opensslTextField(replyText, "Policy OID"), TSA_POLICY);
    assert.equal(
        opensslTextField(replyText, "Policy OID"),
        opensslTextField(queryText, "Policy OID")
    );
    assert.equal(
        opensslTextField(replyText, "Nonce"),
        opensslTextField(queryText, "Nonce"),
        "TSR nonce must equal the original TSQ nonce"
    );
    const digestHexLength =
        hashAlgorithm === "SHA-256" ? 64 : hashAlgorithm === "SHA-384" ? 96 : 128;
    assert.equal(
        opensslTextMessageData(replyText, digestHexLength),
        opensslTextMessageData(queryText, digestHexLength),
        "TSR imprint must equal the original TSQ imprint"
    );
    assert.ok(
        opensslTextField(queryText, "Hash Algorithm").toLowerCase().includes(opensslHashName),
        `TSQ hash algorithm must be ${opensslHashName}`
    );
    ledger.record(section, "openssl-ts", `${tag} TSQ/TSR text agreement`, "policy+nonce+imprint equal", "policy+nonce+imprint equal");

    const dataVerify = run(
        "openssl",
        ["ts", "-verify", "-data", coveredPath, "-in", stamped.responsePath, "-CAfile", rootCert],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.equal(dataVerify.status, 0, commandFailure(dataVerify));
    ledger.record(section, "openssl-ts", `${tag} TSR against covered bytes`, "Verification: OK", "Verification: OK");

    const tokenPath = join(ctx.workdir, `${tag}-token.der`);
    extractRawToken(stamped.responsePath, tokenPath);
    ledger.artifact(ctx.workdir, tokenPath, "raw ContentInfo token");
    const rawToken = new Uint8Array(readFileSync(tokenPath));
    const tokenVerify = run(
        "openssl",
        ["ts", "-verify", "-data", coveredPath, "-in", tokenPath, "-token_in", "-CAfile", rootCert],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.equal(tokenVerify.status, 0, commandFailure(tokenVerify));
    ledger.record(section, "openssl-ts", `${tag} raw token (-token_in)`, "Verification: OK", "Verification: OK");

    const pyhanko = runPyhanko(ctx, stamped.pdfPath, rootCert);
    assert.equal(pyhanko.status, 0, pyhanko.stderr);
    assert.equal(pyhanko.summary.timestampCount, 1);
    assert.equal(pyhanko.summary.intact, true);
    assert.equal(pyhanko.summary.trusted, true);
    assert.deepEqual(
        pyhanko.summary.timestamps,
        [{ index: 0, intact: true, trusted: true }],
        "pyHanko per-timestamp verdicts"
    );
    ledger.record(section, "pyhanko", `${tag} verdicts`, "1 intact+trusted", "1 intact+trusted");

    const verifiedBy = await verifyWithVerifiedBy(stamped.pdf);
    assert.equal(verifiedBy.status, "verified-untrusted-root");
    assert.equal(verifiedBy.documentMatches, true);
    assert.equal(verifiedBy.timestampCount, 1);
    assert.equal(verifiedBy.genTimeTrusted, true);
    assert.deepEqual(verifiedBy.byteRange, coverage.byteRange, "outermost range equals the signature range");
    assertVerifiedByElement(verifiedBy.elements[0], { documentMatches: true, anchored: false, hashAlg: hashAlgorithm }, `${tag} element 0`);
    assert.notEqual(
        verifiedBy.elements[0]?.trailingKind,
        "page-content",
        "validation append must not classify as page content"
    );
    ledger.record(section, "verifiedby", `${tag} unanchored matrix`, "6/6 element checks", "6/6 element checks");

    const anchored = await verifyWithVerifiedBy(stamped.pdf, [rootDer]);
    assert.equal(anchored.status, "verified");
    assertVerifiedByElement(anchored.elements[0], { documentMatches: true, anchored: true, hashAlg: hashAlgorithm }, `${tag} anchored element 0`);
    ledger.record(section, "verifiedby", `${tag} anchored matrix`, "verified+anchored", "verified+anchored");

    const extractedSigs = extractSignatures(stamped.pdf);
    assert.equal(extractedSigs.length, 1, "independent extraction finds one signature");
    assert.deepEqual(
        Array.from(extractedSigs[0]?.byteRange ?? []),
        coverage.byteRange,
        "verifiedby and qpdf covered ranges agree"
    );
    const embeddedToken = stripZeroPadding(
        extractedSigs[0]?.token ?? new Uint8Array(),
        `${tag} embedded token`
    );
    assert.ok(bytesEqual(embeddedToken, rawToken), "C05: embedded bytes equal the accepted token");
    ledger.record(section, "verifiedby", `${tag} C05 token equality`, `${rawToken.length.toString()} bytes equal`, `${embeddedToken.length.toString()} bytes equal`);

    const extracted = await extractTimestamps(stamped.pdf);
    assert.equal(extracted.length, 1);
    assert.ok(bytesEqual(extracted[0]?.token ?? new Uint8Array(), rawToken), "library token equals the raw token");
    const contentsValue = extracted[0]?.contentsValueBytes ?? new Uint8Array();
    assert.ok(
        bytesEqual(contentsValue.slice(0, rawToken.length), rawToken),
        "contents head equals the raw token"
    );
    for (let index = rawToken.length; index < contentsValue.length; index++) {
        assert.equal(contentsValue[index], 0, "contents tail is zero padding");
    }
    ledger.record(section, "library", `${tag} extract+C05`, "token+zero padding", "token+zero padding");

    const store = new SimpleTrustStore();
    store.addCertificate(pkijsCertificateFromDer(rootDer));
    const verified = await verifyPdfTimestamps(stamped.pdf, {
        trustStore: store,
        strictESSValidation: true,
    });
    assert.equal(verified.length, 1);
    assert.equal(verified[0]?.verified, true, verified[0]?.verificationError ?? "verification failed");
    const genTimeVerified = await verifyPdfTimestamps(stamped.pdf, {
        trustStore: store,
        strictESSValidation: true,
        chainValidationTime: "genTime",
    });
    assert.equal(genTimeVerified[0]?.verified, true);
    ledger.record(section, "library", `${tag} verify current+genTime`, "verified true", "verified true");

    const tampered = tamperCoveredWhitespace(stamped.pdf, coverage.byteRange);
    const tamperedPath = writeArtifact(ctx, `${tag}-tampered.pdf`, tampered.tampered, "covered-byte tamper control");
    const tamperedCovered = new Uint8Array(tampered.tampered);
    const tamperedCoveredBytes = new Uint8Array(coverage.covered.length);
    tamperedCoveredBytes.set(tamperedCovered.slice(0, coverage.byteRange[1]));
    tamperedCoveredBytes.set(
        tamperedCovered.slice(coverage.byteRange[2], coverage.byteRange[2] + coverage.byteRange[3]),
        coverage.byteRange[1]
    );
    const tamperedCoveredPath = writeArtifact(ctx, `${tag}-tampered-covered.bin`, tamperedCoveredBytes, "tampered covered bytes");
    const tamperedOpenSsl = run(
        "openssl",
        ["ts", "-verify", "-data", tamperedCoveredPath, "-in", stamped.responsePath, "-CAfile", rootCert],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.notEqual(tamperedOpenSsl.status, 0, "openssl must reject the tampered range");
    ledger.record(section, "openssl-ts", `${tag} tamper rejection`, "status != 0", `status ${String(tamperedOpenSsl.status)}`);
    const tamperedPyhanko = runPyhanko(ctx, tamperedPath, rootCert);
    assert.notEqual(tamperedPyhanko.status, 0, "pyHanko must reject the tampered file");
    assert.deepEqual(
        tamperedPyhanko.summary.timestamps,
        [{ index: 0, intact: false, trusted: false }],
        "pyHanko tamper verdicts"
    );
    ledger.record(section, "pyhanko", `${tag} tamper rejection`, "index 0 broken", "index 0 broken");
    const tamperedVerifiedBy = await verifyWithVerifiedBy(tampered.tampered);
    assert.equal(tamperedVerifiedBy.status, "mismatch");
    assertVerifiedByElement(tamperedVerifiedBy.elements[0], { documentMatches: false, anchored: false, hashAlg: hashAlgorithm }, `${tag} tampered element 0`);
    ledger.record(section, "verifiedby", `${tag} tamper rejection`, "mismatch+doc false", "mismatch+doc false");
    const tamperedLibrary = await verifyPdfTimestamps(tampered.tampered, {
        trustStore: store,
        strictESSValidation: true,
    });
    assert.equal(tamperedLibrary[0]?.verified, false);
    ledger.record(section, "library", `${tag} tamper rejection`, "verified false", "verified false");

    const wrongData = new Uint8Array(coverage.covered);
    const firstByte = wrongData[0];
    if (firstByte === undefined) throw new Error("Covered data must not be empty");
    wrongData[0] = firstByte ^ 0x01;
    const wrongDataPath = writeArtifact(ctx, `${tag}-wrong-data.bin`, wrongData, "wrong-data control");
    const wrongDataOpenSsl = run(
        "openssl",
        ["ts", "-verify", "-data", wrongDataPath, "-in", stamped.responsePath, "-CAfile", rootCert],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.notEqual(wrongDataOpenSsl.status, 0, "openssl must reject wrong data");
    ledger.record(section, "openssl-ts", `${tag} wrong-data rejection`, "status != 0", `status ${String(wrongDataOpenSsl.status)}`);
}

async function sectionHashBreadth(
    ctx: SectionContext,
    tsaConfig: string,
    rootCert: string,
    rootDer: Uint8Array
): Promise<void> {
    const section = "hash-breadth";
    const cases: { tag: string; hash: HashAlgorithm; opensslName: string }[] = [
        { tag: "hash-sha256", hash: "SHA-256", opensslName: "sha256" },
        { tag: "hash-sha384", hash: "SHA-384", opensslName: "sha384" },
        { tag: "hash-sha512", hash: "SHA-512", opensslName: "sha512" },
    ];
    for (const { tag, hash, opensslName } of cases) {
        const input = await createOnePagePdf(`Offline PAdES ${tag}`);
        const stamped = await stampWithLocalTsa(ctx, tag, input, tsaConfig, hash);
        await verifySingleSignatureCase(ctx, section, {
            tag,
            stamped,
            rootCert,
            rootDer,
            hashAlgorithm: hash,
            opensslHashName: opensslName,
        });
    }

    const ecDir = join(ctx.workdir, "tsa-ec");
    mkdirSync(ecDir, { recursive: true });
    const ecTsa = createLocalTsa(ecDir, { keyType: "EC" });
    const ecRootDer = readPemDer(ecTsa.rootCert);
    const ecInput = await createOnePagePdf("Offline PAdES ec-sha256");
    const ecStamped = await stampWithLocalTsa(ctx, "hash-ec-sha256", ecInput, ecTsa.config, "SHA-256");
    const ecKeyText = assertSuccess(
        "openssl",
        ["x509", "-in", ecTsa.tsaCert, "-noout", "-text"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    ).stdout;
    assert.ok(ecKeyText.includes("ASN1 OID: prime256v1"), "EC TSA signer must use P-256");
    await verifySingleSignatureCase(ctx, section, {
        tag: "hash-ec-sha256",
        stamped: ecStamped,
        rootCert: ecTsa.rootCert,
        rootDer: ecRootDer,
        hashAlgorithm: "SHA-256",
        opensslHashName: "sha256",
    });
    ctx.ledger.record(section, "openssl-ts", "ec signer curve", "prime256v1", "prime256v1");
}
async function sectionMultiSignature(
    ctx: SectionContext,
    tsaConfig: string,
    rootCert: string,
    rootDer: Uint8Array
): Promise<void> {
    const section = "multi-signature";
    const { ledger } = ctx;
    const input = await createOnePagePdf("Offline PAdES multi-signature");
    const rev1 = await stampWithLocalTsa(ctx, "multi-r1", input, tsaConfig, "SHA-256");
    const rev2 = await stampWithLocalTsa(ctx, "multi-r2", rev1.pdf, tsaConfig, "SHA-384");

    assert.ok(
        bytesEqual(rev2.pdf.slice(0, rev1.pdf.length), rev1.pdf),
        "the second revision must preserve the first revision's bytes exactly"
    );
    ledger.record(section, "library", "revision prefix preservation", "rev2 starts with rev1", "rev2 starts with rev1");

    const qpdfJson = assertSuccess(
        "qpdf",
        ["--json", rev2.pdfPath],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    ).stdout;
    const coverages = assertQpdfMultiStructure(rev2.pdf, qpdfJson, 2);
    const [first, second] = coverages;
    if (!first || !second) throw new Error("multi-signature coverages are missing");
    ledger.record(section, "qpdf", "two-signature structure", "2 ETSI.RFC3161 ranges", "2 ETSI.RFC3161 ranges");

    const extractedSigs = extractSignatures(rev2.pdf);
    assert.equal(extractedSigs.length, 2, "independent extraction finds two signatures");
    for (const [index, coverage] of coverages.entries()) {
        assert.deepEqual(
            Array.from(extractedSigs[index]?.byteRange ?? []),
            coverage.byteRange,
            `signature ${index.toString()} ranges agree across extractors`
        );
    }
    ledger.record(section, "verifiedby", "range agreement", "2/2 ranges agree", "2/2 ranges agree");

    const responses = [rev1, rev2];
    const rawTokens: Uint8Array[] = [];
    for (const [index, coverage] of coverages.entries()) {
        const stamped = responses[index];
        if (!stamped) throw new Error(`response ${index.toString()} is missing`);
        const coveredPath = writeArtifact(
            ctx,
            `multi-covered-${index.toString()}.bin`,
            coverage.covered,
            `revision ${index.toString()} covered bytes`
        );
        const queryVerify = run(
            "openssl",
            ["ts", "-verify", "-queryfile", stamped.requestPath, "-in", stamped.responsePath, "-CAfile", rootCert],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        );
        assert.equal(queryVerify.status, 0, commandFailure(queryVerify));
        ledger.record(section, "openssl-ts", `revision ${index.toString()} TSR vs TSQ`, "Verification: OK", "Verification: OK");
        const dataVerify = run(
            "openssl",
            ["ts", "-verify", "-data", coveredPath, "-in", stamped.responsePath, "-CAfile", rootCert],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        );
        assert.equal(dataVerify.status, 0, commandFailure(dataVerify));
        ledger.record(section, "openssl-ts", `revision ${index.toString()} TSR vs covered range`, "Verification: OK", "Verification: OK");
        const tokenPath = join(ctx.workdir, `multi-token-${index.toString()}.der`);
        extractRawToken(stamped.responsePath, tokenPath);
        ledger.artifact(ctx.workdir, tokenPath, `revision ${index.toString()} raw token`);
        const rawToken = new Uint8Array(readFileSync(tokenPath));
        const tokenVerify = run(
            "openssl",
            ["ts", "-verify", "-data", coveredPath, "-in", tokenPath, "-token_in", "-CAfile", rootCert],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        );
        assert.equal(tokenVerify.status, 0, commandFailure(tokenVerify));
        ledger.record(section, "openssl-ts", `revision ${index.toString()} raw token`, "Verification: OK", "Verification: OK");

        const embedded = stripZeroPadding(
            extractedSigs[index]?.token ?? new Uint8Array(),
            `revision ${index.toString()} embedded token`
        );
        assert.ok(bytesEqual(embedded, rawToken), `C05: revision ${index.toString()} bytes equal`);
        ledger.record(section, "verifiedby", `revision ${index.toString()} C05 equality`, "bytes equal", "bytes equal");
        rawTokens.push(rawToken);
    }

    const pyhanko = runPyhanko(ctx, rev2.pdfPath, rootCert);
    assert.equal(pyhanko.status, 0, pyhanko.stderr);
    assert.equal(pyhanko.summary.timestampCount, 2);
    assert.deepEqual(
        pyhanko.summary.timestamps,
        [
            { index: 0, intact: true, trusted: true },
            { index: 1, intact: true, trusted: true },
        ],
        "pyHanko per-revision verdicts"
    );
    ledger.record(section, "pyhanko", "per-revision verdicts", "2 intact+trusted", "2 intact+trusted");

    const hashes: HashAlgorithm[] = ["SHA-256", "SHA-384"];
    const verifiedBy = await verifyWithVerifiedBy(rev2.pdf);
    assert.equal(verifiedBy.status, "verified-untrusted-root");
    assert.equal(verifiedBy.timestampCount, 2);
    assert.equal(verifiedBy.documentMatches, true);
    assert.equal(verifiedBy.genTimeTrusted, true);
    assert.deepEqual(verifiedBy.byteRange, second.byteRange, "outermost range is the latest");
    for (const [index, hash] of hashes.entries()) {
        assertVerifiedByElement(
            verifiedBy.elements[index],
            { documentMatches: true, anchored: false, hashAlg: hash },
            `revision ${index.toString()}`
        );
    }
    assert.equal(verifiedBy.elements[0]?.trailingKind, "signature-update", "first trailing kind");
    assert.notEqual(
        verifiedBy.elements[1]?.trailingKind,
        "page-content",
        "latest trailing kind must not be page content"
    );
    const latestGenTime = verifiedBy.elements[1]?.time?.value?.getTime();
    const firstGenTime = verifiedBy.elements[0].time?.value?.getTime();
    assert.ok(
        latestGenTime !== undefined && firstGenTime !== undefined && latestGenTime >= firstGenTime,
        "latest covered time must not precede the first"
    );
    assert.equal(verifiedBy.genTime?.getTime(), latestGenTime, "top-level time selects the latest");
    ledger.record(section, "verifiedby", "unanchored matrix", "2x6 element checks + latest time", "2x6 element checks + latest time");

    const anchored = await verifyWithVerifiedBy(rev2.pdf, [rootDer]);
    assert.equal(anchored.status, "verified");
    for (const [index, hash] of hashes.entries()) {
        assertVerifiedByElement(
            anchored.elements[index],
            { documentMatches: true, anchored: true, hashAlg: hash },
            `anchored revision ${index.toString()}`
        );
    }
    ledger.record(section, "verifiedby", "anchored matrix", "verified + 2 anchored", "verified + 2 anchored");

    const store = new SimpleTrustStore();
    store.addCertificate(pkijsCertificateFromDer(rootDer));
    const extracted = await extractTimestamps(rev2.pdf);
    assert.equal(extracted.length, 2);
    for (const [index, rawToken] of rawTokens.entries()) {
        assert.ok(
            bytesEqual(extracted[index]?.token ?? new Uint8Array(), rawToken),
            `library revision ${index.toString()} token equals its raw token`
        );
    }
    const verified = await verifyPdfTimestamps(rev2.pdf, {
        trustStore: store,
        strictESSValidation: true,
    });
    assert.deepEqual(
        verified.map((entry) => entry.verified),
        [true, true],
        "library per-revision verification"
    );
    ledger.record(section, "library", "per-revision verify", "[true, true]", "[true, true]");

    // Tamper matrix: each revision separately, against every engine.
    const tamperRev1 = tamperCoveredWhitespace(rev2.pdf, first.byteRange);
    const tamperRev1Path = writeArtifact(ctx, "multi-tampered-r1.pdf", tamperRev1.tampered, "revision-1 tamper control");
    const tamperRev2Only = tamperCoveredWhitespace(rev2.pdf, second.byteRange, [first.byteRange]);
    const tamperRev2OnlyPath = writeArtifact(ctx, "multi-tampered-r2only.pdf", tamperRev2Only.tampered, "revision-2-only tamper control");

    const coverAt = (pdf: Uint8Array, coverage: SignatureCoverage): Uint8Array => {
        const out = new Uint8Array(coverage.covered.length);
        out.set(pdf.slice(0, coverage.byteRange[1]));
        out.set(
            pdf.slice(coverage.byteRange[2], coverage.byteRange[2] + coverage.byteRange[3]),
            coverage.byteRange[1]
        );
        return out;
    };
    const tamperCases = [
        { label: "rev1-region", pdf: tamperRev1.tampered, path: tamperRev1Path, expect: [false, false] as const },
        { label: "rev2-only", pdf: tamperRev2Only.tampered, path: tamperRev2OnlyPath, expect: [true, false] as const },
    ];
    for (const tamperCase of tamperCases) {
        for (const [index, coverage] of coverages.entries()) {
            const coveredPath = writeArtifact(
                ctx,
                `multi-tampered-${tamperCase.label}-covered-${index.toString()}.bin`,
                coverAt(tamperCase.pdf, coverage),
                "tampered covered bytes"
            );
            const stamped = responses[index];
            if (!stamped) throw new Error(`response ${index.toString()} is missing`);
            const result = run(
                "openssl",
                ["ts", "-verify", "-data", coveredPath, "-in", stamped.responsePath, "-CAfile", rootCert],
                PINNED_ORACLE_INSTALLATION_GUIDANCE
            );
            if (tamperCase.expect[index]) {
                assert.equal(result.status, 0, `openssl revision ${index.toString()} survives ${tamperCase.label} tamper`);
            } else {
                assert.notEqual(result.status, 0, `openssl revision ${index.toString()} rejects ${tamperCase.label} tamper`);
            }
        }
        ledger.record(
            section,
            "openssl-ts",
            `${tamperCase.label} tamper`,
            `[${tamperCase.expect.map((v) => (v ? "OK" : "FAIL")).join(", ")}]`,
            `[${tamperCase.expect.map((v) => (v ? "OK" : "FAIL")).join(", ")}]`
        );

        const tamperedPyhanko = runPyhanko(ctx, tamperCase.path, rootCert);
        assert.notEqual(tamperedPyhanko.status, 0, "pyHanko must reject the tampered file");
        assert.deepEqual(
            tamperedPyhanko.summary.timestamps,
            tamperCase.expect.map((intact, index) => ({ index, intact, trusted: intact })),
            `pyHanko ${tamperCase.label} verdicts`
        );
        ledger.record(section, "pyhanko", `${tamperCase.label} tamper`, "per-revision verdicts", "per-revision verdicts");

        const tamperedVerifiedBy = await verifyWithVerifiedBy(tamperCase.pdf);
        assert.equal(tamperedVerifiedBy.status, "mismatch");
        for (const [index, hash] of hashes.entries()) {
            assertVerifiedByElement(
                tamperedVerifiedBy.elements[index],
                { documentMatches: tamperCase.expect[index] ?? false, anchored: false, hashAlg: hash },
                `${tamperCase.label} revision ${index.toString()}`
            );
        }
        ledger.record(section, "verifiedby", `${tamperCase.label} tamper`, "mismatch + per-revision doc", "mismatch + per-revision doc");

        const tamperedLibrary = await verifyPdfTimestamps(tamperCase.pdf, {
            trustStore: store,
            strictESSValidation: true,
        });
        assert.deepEqual(
            tamperedLibrary.map((entry) => entry.verified),
            [...tamperCase.expect],
            `library ${tamperCase.label} verdicts`
        );
        ledger.record(section, "library", `${tamperCase.label} tamper`, "per-revision verdicts", "per-revision verdicts");
    }
}
async function sectionValidityBoundaries(ctx: SectionContext): Promise<void> {
    const section = "validity-boundaries";
    const { ledger } = ctx;
    const tsaDir = join(ctx.workdir, "tsa-boundary");
    mkdirSync(tsaDir, { recursive: true });
    const boundary = createLocalTsa(tsaDir, { rootDays: 30 });
    const rootDer = readPemDer(boundary.rootCert);
    const tsaEpochs = certValidityEpochs(boundary.tsaCert);
    const rootEpochs = certValidityEpochs(boundary.rootCert);
    assert.ok(
        rootEpochs.notAfter > tsaEpochs.notAfter,
        "the boundary root must outlive the signer so the signer drives the notAfter edge"
    );

    const input = await createOnePagePdf("Offline PAdES validity boundaries");
    const stamped = await stampWithLocalTsa(ctx, "boundary", input, boundary.config, "SHA-256");
    const extracted = await extractTimestamps(stamped.pdf);
    assert.equal(extracted.length, 1);
    const token = extracted[0]?.token;
    if (!token) throw new Error("boundary token is missing");
    const extractedFirst = extracted[0];
    if (!extractedFirst) throw new Error("boundary timestamp is missing");

    const probes = [
        { label: "nb-1", epoch: tsaEpochs.notBefore - 1, openssl: false, library: false },
        { label: "nb", epoch: tsaEpochs.notBefore, openssl: true, library: true },
        { label: "nb+1", epoch: tsaEpochs.notBefore + 1, openssl: true, library: true },
        { label: "na-1", epoch: tsaEpochs.notAfter - 1, openssl: true, library: true },
        // Single-instant divergence, pinned deliberately: OpenSSL treats
        // notAfter as exclusive while the library and pyHanko treat it as
        // inclusive (RFC 5280's reading). See the T15 report.
        { label: "na", epoch: tsaEpochs.notAfter, openssl: false, library: true },
        { label: "na+1", epoch: tsaEpochs.notAfter + 1, openssl: false, library: false },
    ];
    for (const probe of probes) {
        const tsResult = run(
            "openssl",
            [
                "ts",
                "-verify",
                "-queryfile",
                stamped.requestPath,
                "-in",
                stamped.responsePath,
                "-CAfile",
                boundary.rootCert,
                "-attime",
                probe.epoch.toString(),
            ],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        );
        assert.equal(
            tsResult.status === 0,
            probe.openssl,
            `openssl ts -attime ${probe.label} must ${probe.openssl ? "verify" : "fail"}`
        );
        ledger.record(
            section,
            "openssl-ts",
            `attime ${probe.label} (${probe.epoch.toString()})`,
            probe.openssl ? "Verification: OK" : "Verification: FAILED",
            tsResult.status === 0 ? "Verification: OK" : "Verification: FAILED"
        );

        const chainResult = run(
            "openssl",
            [
                "verify",
                "-CAfile",
                boundary.rootCert,
                "-attime",
                probe.epoch.toString(),
                boundary.tsaCert,
            ],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        );
        assert.equal(
            chainResult.status === 0,
            probe.openssl,
            `openssl chain -attime ${probe.label} must ${probe.openssl ? "verify" : "fail"}`
        );
        ledger.record(
            section,
            "openssl-verify",
            `chain attime ${probe.label}`,
            probe.openssl ? "OK" : "FAIL",
            chainResult.status === 0 ? "OK" : "FAIL"
        );

        const store = new SimpleTrustStore();
        store.addCertificate(pkijsCertificateFromDer(rootDer));
        const libraryResult = await verifyTimestamp(
            { ...extractedFirst },
            {
                trustStore: store,
                strictESSValidation: true,
                chainValidationTime: new Date(probe.epoch * 1000),
            }
        );
        assert.equal(
            libraryResult.verified,
            probe.library,
            `library chainValidationTime ${probe.label} must verify=${probe.library.toString()}`
        );
        ledger.record(
            section,
            "library",
            `chainValidationTime ${probe.label}`,
            probe.library ? "verified true" : "verified false",
            libraryResult.verified ? "verified true" : "verified false"
        );

        const moment = new Date(probe.epoch * 1000).toISOString();
        const pyhanko = runPyhanko(ctx, stamped.pdfPath, boundary.rootCert, [
            "--moment",
            moment,
            "--tolerance",
            "0",
        ]);
        const trusted = pyhanko.summary.timestampCount === 1 && pyhanko.summary.trusted;
        assert.equal(
            trusted,
            probe.library,
            `pyHanko moment ${probe.label} must be trusted=${probe.library.toString()}`
        );
        ledger.record(
            section,
            "pyhanko",
            `moment ${probe.label}`,
            probe.library ? "trusted" : "untrusted",
            trusted ? "trusted" : "untrusted"
        );
    }

    const store = new SimpleTrustStore();
    store.addCertificate(pkijsCertificateFromDer(rootDer));
    const genTimeResult = await verifyTimestamp(
        { ...extractedFirst },
        { trustStore: store, strictESSValidation: true, chainValidationTime: "genTime" }
    );
    assert.equal(genTimeResult.verified, true, "genTime validation must verify");
    ledger.record(section, "library", "chainValidationTime genTime", "verified true", "verified true");
}

async function sectionTrustTargetAttack(
    ctx: SectionContext,
    tsaConfig: string,
    rootCert: string
): Promise<void> {
    const section = "trust-target";
    const { ledger } = ctx;
    const anchorDir = join(ctx.workdir, "unrelated-anchor");
    mkdirSync(anchorDir, { recursive: true });
    const anchor = createUnrelatedTrustAnchor(anchorDir);
    const anchorRootDer = readPemDer(anchor.rootCert);
    const intermediate = pkijsCertificateFromDer(readPemDer(anchor.intermediateCert));

    const input = await createOnePagePdf("Offline PAdES trust target");
    const stamped = await stampWithLocalTsa(ctx, "t01", input, tsaConfig, "SHA-256");
    const tokenPath = join(ctx.workdir, "t01-token.der");
    extractRawToken(stamped.responsePath, tokenPath);
    const rawToken = new Uint8Array(readFileSync(tokenPath));

    const poisoned = poisonTokenBag(rawToken, [intermediate]);
    writeArtifact(ctx, "t01-poisoned-token.der", poisoned, "T01 poisoned token");
    const poisonedResponse = rewrapResponse(stamped.response, poisoned);
    const poisonedResponsePath = writeArtifact(ctx, "t01-poisoned.tsr", poisonedResponse, "T01 poisoned response");

    const controlOpenssl = run(
        "openssl",
        ["ts", "-verify", "-queryfile", stamped.requestPath, "-in", poisonedResponsePath, "-CAfile", rootCert],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.equal(controlOpenssl.status, 0, "poisoned token must stay valid under its own root");
    ledger.record(section, "openssl-ts", "poisoned token under own root", "Verification: OK", "Verification: OK");

    const attackOpenssl = run(
        "openssl",
        ["ts", "-verify", "-queryfile", stamped.requestPath, "-in", poisonedResponsePath, "-CAfile", anchor.rootCert],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.notEqual(attackOpenssl.status, 0, "openssl must reject the untrusted signer");
    assert.match(commandFailure(attackOpenssl), /certificate verify error|self.signed/i);
    ledger.record(section, "openssl-ts", "T01 bag attack", "chain rejected", "chain rejected");

    const victimStore = new SimpleTrustStore();
    victimStore.addCertificate(pkijsCertificateFromDer(anchorRootDer));
    const attackToken: ExtractedTimestamp = {
        token: poisoned,
        contentsValueBytes: poisoned.slice(),
        info: {} as TimestampInfo,
        fieldName: "Timestamp",
        coversWholeDocument: true,
        verified: false,
        byteRange: [0, 0, 0, 0],
    };
    const attackLibrary = await verifyTimestamp(attackToken, {
        trustStore: victimStore,
        strictESSValidation: true,
    });
    assert.equal(attackLibrary.certificates?.length, 3, "poisoned bag carries three certs");
    assert.equal(attackLibrary.verified, false);
    assert.match(attackLibrary.verificationError ?? "", /not trusted/);
    ledger.record(section, "library", "T01 bag attack", "verified false /not trusted/", "verified false /not trusted/");

    const controlLibrary = await verifyTimestamp(
        { ...attackToken, token: poisoned.slice(), contentsValueBytes: poisoned.slice() },
        { strictESSValidation: true }
    );
    assert.equal(controlLibrary.verified, true, "poisoned token is otherwise valid");
    ledger.record(section, "library", "T01 no-trust control", "verified true", "verified true");

    const poisonSession = new TimestampSession(input, {
        enableLTV: true,
        prepareOptions: { signatureSize: SIGNATURE_SIZE },
    });
    const poisonRequest = await poisonSession.createTimestampRequest({
        hashAlgorithm: "SHA-256",
        policy: TSA_POLICY,
        requestCertificate: true,
    });
    const poisonRequestPath = writeArtifact(ctx, "t01-pdf.tsq", poisonRequest, "T01 PDF request");
    const poisonResponsePath = join(ctx.workdir, "t01-pdf.tsr");
    issueTsReply(poisonRequestPath, tsaConfig, poisonResponsePath);
    ctx.ledger.artifact(ctx.workdir, poisonResponsePath, "T01 PDF response");
    const poisonResponse = new Uint8Array(readFileSync(poisonResponsePath));
    const poisonTokenPath = join(ctx.workdir, "t01-pdf-token.der");
    extractRawToken(poisonResponsePath, poisonTokenPath);
    const pdfPoisoned = poisonTokenBag(new Uint8Array(readFileSync(poisonTokenPath)), [intermediate]);
    const pdfPoisonedResponse = rewrapResponse(poisonResponse, pdfPoisoned);
    const signedPdf = await poisonSession.embedTimestampToken(pdfPoisonedResponse);
    const signedPath = writeArtifact(ctx, "t01-poisoned.pdf", signedPdf, "T01 poisoned PDF");
    const pdfResults = await verifyPdfTimestamps(signedPdf, {
        trustStore: victimStore,
        strictESSValidation: true,
    });
    assert.equal(pdfResults.length, 1);
    assert.equal(pdfResults[0]?.verified, false);
    assert.match(pdfResults[0].verificationError ?? "", /not trusted/);
    ledger.record(section, "library", "T01 poisoned PDF", "verified false /not trusted/", "verified false /not trusted/");

    const qpdfJson = assertSuccess(
        "qpdf",
        ["--json", signedPath],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    ).stdout;
    const [coverage] = assertQpdfMultiStructure(signedPdf, qpdfJson, 1);
    if (!coverage) throw new Error("T01 PDF coverage is missing");
    const embedded = stripZeroPadding(
        extractSignatures(signedPdf)[0]?.token ?? new Uint8Array(),
        "T01 embedded token"
    );
    assert.ok(bytesEqual(embedded, pdfPoisoned), "C05: poisoned bytes embed exactly");
    const embeddedPath = writeArtifact(ctx, "t01-embedded-token.der", embedded, "T01 embedded token");
    const embeddedCoveredPath = writeArtifact(ctx, "t01-embedded-covered.bin", coverage.covered, "T01 embedded covered bytes");
    const embeddedAttack = run(
        "openssl",
        ["ts", "-verify", "-data", embeddedCoveredPath, "-in", embeddedPath, "-token_in", "-CAfile", anchor.rootCert],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.notEqual(embeddedAttack.status, 0, "openssl rejects the embedded poisoned token");
    ledger.record(section, "openssl-ts", "T01 embedded attack", "chain rejected", "chain rejected");

    const embeddedControl = run(
        "openssl",
        ["ts", "-verify", "-data", embeddedCoveredPath, "-in", embeddedPath, "-token_in", "-CAfile", rootCert],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.equal(embeddedControl.status, 0, "embedded poisoned token stays valid under its own root");
    ledger.record(section, "openssl-ts", "T01 embedded control", "Verification: OK", "Verification: OK");
}
function tsTextNonce(requestPath: string): string {
    const text = assertSuccess(
        "openssl",
        ["ts", "-query", "-in", requestPath, "-text"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    ).stdout;
    return opensslTextField(text, "Nonce");
}

async function sectionResignedBinding(
    ctx: SectionContext,
    tsaConfig: string,
    tsaCert: string,
    tsaKey: string,
    rootCert: string
): Promise<void> {
    const section = "resigned-binding";
    const { ledger } = ctx;

    const inputA = await createOnePagePdf("Offline PAdES binding A");
    const inputB = await createOnePagePdf("Offline PAdES binding B");
    const sessionA = new TimestampSession(inputA, {
        enableLTV: true,
        prepareOptions: { signatureSize: SIGNATURE_SIZE },
    });
    const sessionB = new TimestampSession(inputB, {
        enableLTV: true,
        prepareOptions: { signatureSize: SIGNATURE_SIZE },
    });
    const requestA = await sessionA.createTimestampRequest({
        hashAlgorithm: "SHA-256",
        policy: TSA_POLICY,
        requestCertificate: true,
    });
    const requestB = await sessionB.createTimestampRequest({
        hashAlgorithm: "SHA-256",
        policy: TSA_POLICY,
        requestCertificate: true,
    });
    const requestAPath = writeArtifact(ctx, "bind-a.tsq", requestA, "binding request A");
    const requestBPath = writeArtifact(ctx, "bind-b.tsq", requestB, "binding request B");
    const responseAPath = join(ctx.workdir, "bind-a.tsr");
    const responseBPath = join(ctx.workdir, "bind-b.tsr");
    issueTsReply(requestAPath, tsaConfig, responseAPath);
    issueTsReply(requestBPath, tsaConfig, responseBPath);
    const responseA = new Uint8Array(readFileSync(responseAPath));
    const responseB = new Uint8Array(readFileSync(responseBPath));
    ledger.artifact(ctx.workdir, responseAPath, "binding response A");
    ledger.artifact(ctx.workdir, responseBPath, "binding response B");

    // Wrong digest: the TSA legitimately re-signed a different imprint.
    const digestMismatch = run(
        "openssl",
        ["ts", "-verify", "-queryfile", requestAPath, "-in", responseBPath, "-CAfile", rootCert],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.notEqual(digestMismatch.status, 0, "openssl must reject the wrong digest");
    assert.match(commandFailure(digestMismatch), /message imprint mismatch/i);
    ledger.record(section, "openssl-ts", "re-signed wrong digest", "message imprint mismatch", "message imprint mismatch");
    let digestRejected = false;
    try {
        await sessionA.embedTimestampToken(responseB);
    } catch {
        digestRejected = true;
    }
    assert.equal(digestRejected, true, "session A must reject response B");
    ledger.record(section, "library", "re-signed wrong digest", "embed throws", "embed throws");

    // Wrong nonce: the same digest re-requested under a distinct nonce.
    const requestASchema = asn1js.fromBER(requestA.slice().buffer);
    if (requestASchema.offset === -1) throw new Error("request A is not DER");
    const timeStampReq = new pkijs.TimeStampReq({ schema: requestASchema.result });
    const nonceValue = timeStampReq.nonce?.valueBlock.valueDec;
    if (timeStampReq.nonce === undefined || nonceValue === undefined) {
        throw new Error("request A carries no nonce");
    }
    timeStampReq.nonce = new asn1js.Integer({ value: nonceValue + 1 });
    const requestC = new Uint8Array(timeStampReq.toSchema().toBER(false));
    const requestCPath = writeArtifact(ctx, "bind-c.tsq", requestC, "re-nonced request C");
    assert.notEqual(tsTextNonce(requestAPath), tsTextNonce(requestCPath), "nonces must differ");
    const imprintA = opensslTextMessageData(
        assertSuccess(
            "openssl",
            ["ts", "-query", "-in", requestAPath, "-text"],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        ).stdout,
        64
    );
    const imprintC = opensslTextMessageData(
        assertSuccess(
            "openssl",
            ["ts", "-query", "-in", requestCPath, "-text"],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        ).stdout,
        64
    );
    assert.equal(imprintC, imprintA, "the re-nonce must preserve the digest");
    const responseCPath = join(ctx.workdir, "bind-c.tsr");
    issueTsReply(requestCPath, tsaConfig, responseCPath);
    const nonceMismatch = run(
        "openssl",
        ["ts", "-verify", "-queryfile", requestAPath, "-in", responseCPath, "-CAfile", rootCert],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.notEqual(nonceMismatch.status, 0, "openssl must reject the wrong nonce");
    assert.match(commandFailure(nonceMismatch), /nonce/i);
    ledger.record(section, "openssl-ts", "re-signed wrong nonce", "nonce mismatch", "nonce mismatch");
    const responseC = new Uint8Array(readFileSync(responseCPath));
    ledger.artifact(ctx.workdir, responseCPath, "binding response C");
    let nonceRejected = false;
    try {
        await sessionA.embedTimestampToken(responseC);
    } catch {
        nonceRejected = true;
    }
    assert.equal(nonceRejected, true, "session A must reject the re-nonced response");
    ledger.record(section, "library", "re-signed wrong nonce", "embed throws", "embed throws");

    // Wrong eContentType: TSTInfo bytes re-signed as a CMS data signature.
    const tokenAPath = join(ctx.workdir, "bind-a-token.der");
    extractRawToken(responseAPath, tokenAPath);
    const tstInfo = tstInfoBytes(new Uint8Array(readFileSync(tokenAPath)));
    const tstInfoPath = writeArtifact(ctx, "bind-tstinfo.bin", tstInfo, "raw TSTInfo bytes");
    const wrongEctPath = join(ctx.workdir, "bind-wrong-ect.der");
    assertSuccess(
        "openssl",
        [
            "cms",
            "-sign",
            "-in",
            tstInfoPath,
            "-inform",
            "DER",
            "-signer",
            tsaCert,
            "-inkey",
            tsaKey,
            "-outform",
            "DER",
            "-nodetach",
            "-binary",
            "-out",
            wrongEctPath,
        ],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    const wrongEct = new Uint8Array(readFileSync(wrongEctPath));
    ledger.artifact(ctx.workdir, wrongEctPath, "re-signed wrong-eContentType CMS");
    const cmsText = assertSuccess(
        "openssl",
        ["cms", "-in", wrongEctPath, "-inform", "DER", "-cmsout", "-print"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    ).stdout;
    assert.ok(
        cmsText.includes("1.2.840.113549.1.7.1") || cmsText.includes("id-data"),
        "re-signed CMS must carry eContentType id-data"
    );
    const ectOracle = run(
        "openssl",
        ["ts", "-verify", "-token_in", "-in", wrongEctPath, "-data", tstInfoPath, "-CAfile", rootCert],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.notEqual(ectOracle.status, 0, "openssl must reject the wrong eContentType");
    assert.match(commandFailure(ectOracle), /bad pkcs7 type|wrong content type/i);
    ledger.record(section, "openssl-ts", "re-signed wrong eContentType", "bad pkcs7 type", "bad pkcs7 type");

    const ectToken: ExtractedTimestamp = {
        token: wrongEct,
        contentsValueBytes: wrongEct.slice(),
        info: {} as TimestampInfo,
        fieldName: "Timestamp",
        coversWholeDocument: true,
        verified: false,
        byteRange: [0, 0, 0, 0],
    };
    const ectLibrary = await verifyTimestamp(ectToken, { strictESSValidation: true });
    assert.equal(ectLibrary.verified, false);
    assert.match(ectLibrary.verificationError ?? "", /id-ct-TSTInfo/);
    ledger.record(section, "library", "re-signed wrong eContentType", "verified false /id-ct-TSTInfo/", "verified false /id-ct-TSTInfo/");

    const ectResponse = rewrapResponse(responseA, wrongEct);
    let ectEmbedRejected = false;
    try {
        await sessionA.embedTimestampToken(ectResponse);
    } catch {
        ectEmbedRejected = true;
    }
    assert.equal(ectEmbedRejected, true, "embed must reject the wrong eContentType");
    ledger.record(section, "library", "wrong eContentType embed", "embed throws", "embed throws");
}
async function sectionTokenRigorHistorical(ctx: SectionContext): Promise<void> {
    const section = "token-rigor";
    const { ledger } = ctx;
    const request = decodeHistoricalTsp(HISTORICAL_TSP_REQUEST_BASE64);
    const response = decodeHistoricalTsp(HISTORICAL_TSP_RESPONSE_BASE64);
    const rootDer = decodeHistoricalTsp(HISTORICAL_TSP_ROOT_BASE64);
    const tsaDer = decodeHistoricalTsp(HISTORICAL_TSP_TSA_BASE64);
    const pdf = decodeHistoricalTsp(HISTORICAL_TSP_PDF_BASE64);
    const meta = HISTORICAL_TSP_METADATA;
    assert.equal(sha256Hex(request), meta.sha256.request, "historical TSQ integrity");
    assert.equal(sha256Hex(response), meta.sha256.response, "historical TSR integrity");
    assert.equal(sha256Hex(rootDer), meta.sha256.root, "historical root integrity");
    assert.equal(sha256Hex(tsaDer), meta.sha256.tsa, "historical TSA integrity");
    assert.equal(sha256Hex(pdf), meta.sha256.pdf, "historical PDF integrity");
    ledger.record(section, "library", "fixture self-integrity", "5/5 hashes match", "5/5 hashes match");

    const requestPath = writeArtifact(ctx, "historical.tsq", request, "historical TimeStampReq");
    const responsePath = writeArtifact(ctx, "historical.tsr", response, "historical TimeStampResp");
    const rootPath = writeArtifact(
        ctx,
        "historical-root.pem",
        new Uint8Array(Buffer.from(`-----BEGIN CERTIFICATE-----\n${HISTORICAL_TSP_ROOT_BASE64}\n-----END CERTIFICATE-----\n`)),
        "historical root PEM"
    );
    const pdfPath = writeArtifact(ctx, "historical.pdf", pdf, "historical signed PDF");

    const attimeCases = [
        { label: "genTime", epoch: meta.genTimeEpoch, expectOk: true },
        { label: "nb-1", epoch: meta.tsaNotBeforeEpoch - 1, expectOk: false },
        { label: "na", epoch: meta.tsaNotAfterEpoch, expectOk: false },
        { label: "na+1", epoch: meta.tsaNotAfterEpoch + 1, expectOk: false },
    ];
    for (const attime of attimeCases) {
        const result = run(
            "openssl",
            [
                "ts",
                "-verify",
                "-queryfile",
                requestPath,
                "-in",
                responsePath,
                "-CAfile",
                rootPath,
                "-attime",
                attime.epoch.toString(),
            ],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        );
        assert.equal(
            result.status === 0,
            attime.expectOk,
            `historical -attime ${attime.label} must ${attime.expectOk ? "verify" : "fail"}`
        );
        ledger.record(
            section,
            "openssl-ts",
            `historical -attime ${attime.label}`,
            attime.expectOk ? "Verification: OK" : "Verification: FAILED",
            result.status === 0 ? "Verification: OK" : "Verification: FAILED"
        );
    }

    const historicalTokenPath = join(ctx.workdir, "historical-token.der");
    extractRawToken(responsePath, historicalTokenPath);
    ledger.artifact(ctx.workdir, historicalTokenPath, "historical raw token");
    const historicalToken = new Uint8Array(readFileSync(historicalTokenPath));
    const historicalSig = extractSignatures(pdf)[0];
    if (!historicalSig) throw new Error("historical PDF is missing its signature");
    const historicalCovered = assertByteRange(pdf, historicalSig.byteRange);
    const historicalCoveredPath = writeArtifact(
        ctx,
        "historical-covered.bin",
        historicalCovered,
        "historical covered bytes"
    );
    const historicalTokenVerify = run(
        "openssl",
        [
            "ts",
            "-verify",
            "-data",
            historicalCoveredPath,
            "-in",
            historicalTokenPath,
            "-token_in",
            "-CAfile",
            rootPath,
            "-attime",
            meta.genTimeEpoch.toString(),
        ],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.equal(historicalTokenVerify.status, 0, commandFailure(historicalTokenVerify));
    assert.match(historicalTokenVerify.stdout, /Verification: OK/);
    ledger.record(
        section,
        "openssl-ts",
        "historical raw token (-token_in)",
        "Verification: OK",
        "Verification: OK"
    );

    const store = new SimpleTrustStore();
    store.addCertificate(pkijsCertificateFromDer(rootDer));
    const extracted = await extractTimestamps(pdf);
    assert.equal(extracted.length, 1);
    const extractedFirst = extracted[0];
    if (!extractedFirst) throw new Error("historical timestamp is missing");
    assert.ok(
        bytesEqual(extracted[0]?.token ?? new Uint8Array(), historicalToken),
        "historical embedded token equals the frozen raw token"
    );
    ledger.record(section, "library", "historical C05 equality", "bytes equal", "bytes equal");
    const genTimeLibrary = await verifyTimestamp(
        { ...extractedFirst },
        {
            trustStore: store,
            strictESSValidation: true,
            chainValidationTime: new Date(meta.genTimeEpoch * 1000),
        }
    );
    assert.equal(genTimeLibrary.verified, true, "historical genTime validation must verify");
    ledger.record(section, "library", "historical genTime", "verified true", "verified true");
    const expiredLibrary = await verifyTimestamp(
        { ...extractedFirst },
        {
            trustStore: store,
            strictESSValidation: true,
            chainValidationTime: new Date((meta.tsaNotAfterEpoch + 1) * 1000),
        }
    );
    assert.equal(expiredLibrary.verified, false, "historical na+1 validation must fail");
    ledger.record(section, "library", "historical na+1", "verified false", "verified false");

    const embedded = stripZeroPadding(
        extractSignatures(pdf)[0]?.token ?? new Uint8Array(),
        "historical embedded token"
    );
    assert.ok(bytesEqual(embedded, historicalToken), "verifiedby historical bytes equal the raw token");
    ledger.record(section, "verifiedby", "historical C05 equality", "bytes equal", "bytes equal");

    const historicalPyhanko = runPyhanko(ctx, pdfPath, rootPath, [
        "--moment",
        meta.genTimeIso,
        "--tolerance",
        "0",
    ]);
    assert.equal(historicalPyhanko.status, 0, historicalPyhanko.stderr);
    assert.deepEqual(
        historicalPyhanko.summary.timestamps,
        [{ index: 0, intact: true, trusted: true }],
        "pyHanko historical verdicts at genTime"
    );
    ledger.record(section, "pyhanko", "historical moment=genTime", "intact+trusted", "intact+trusted");
    const expiredPyhanko = runPyhanko(ctx, pdfPath, rootPath, [
        "--moment",
        new Date((meta.tsaNotAfterEpoch + 1) * 1000).toISOString(),
        "--tolerance",
        "0",
    ]);
    assert.equal(expiredPyhanko.summary.timestampCount, 1);
    assert.equal(expiredPyhanko.summary.intact, true);
    assert.equal(expiredPyhanko.summary.trusted, false);
    ledger.record(section, "pyhanko", "historical moment=na+1", "intact+untrusted", "intact+untrusted");
}
function opensslIndexDate(epochSeconds: number): string {
    const date = new Date(epochSeconds * 1000);
    const pad = (value: number): string => value.toString().padStart(2, "0");
    return (
        `${(date.getUTCFullYear() % 100).toString().padStart(2, "0")}${pad(date.getUTCMonth() + 1)}` +
        `${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`
    );
}

/** Answers the library's live OCSP requests with the pinned OpenSSL responder. */
class OpensslOcspResponder implements RevocationDataFetcher {
    private calls = 0;
    requests: Uint8Array[] = [];
    responses: Uint8Array[] = [];

    constructor(
        private readonly directory: string,
        private readonly indexPath: string,
        private readonly caCert: string,
        private readonly responderCert: string,
        private readonly responderKey: string
    ) {}

    async fetchOCSP(_url: string, request: Uint8Array): Promise<Uint8Array> {
        this.calls += 1;
        const requestPath = join(this.directory, `ocsp-lib-req-${this.calls.toString()}.der`);
        const responsePath = join(this.directory, `ocsp-lib-resp-${this.calls.toString()}.der`);
        writeFileSync(requestPath, request);
        assertSuccess(
            "openssl",
            [
                "ocsp",
                "-index",
                this.indexPath,
                "-CA",
                this.caCert,
                "-rsigner",
                this.responderCert,
                "-rkey",
                this.responderKey,
                "-reqin",
                requestPath,
                "-respout",
                responsePath,
                "-ndays",
                "7",
            ],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        );
        const response = new Uint8Array(readFileSync(responsePath));
        this.requests.push(request);
        this.responses.push(response);
        return Promise.resolve(response);
    }

    async fetchCRL(url: string): Promise<Uint8Array> {
        return Promise.reject(new Error(`OCSP-only responder has no CRL for ${url}`));
    }
}

function corruptFirstSignature256(response: Uint8Array): Uint8Array {
    const header = [0x03, 0x82, 0x01, 0x01, 0x00];
    const hits: number[] = [];
    for (let index = 0; index + header.length <= response.length; index++) {
        if (header.every((byte, offset) => response[index + offset] === byte)) {
            hits.push(index);
        }
    }
    assert.equal(
        hits.length,
        2,
        "the OCSP response must carry the response signature plus one embedded CA signature"
    );
    const first = hits[0];
    if (first === undefined) throw new Error("OCSP signature header is missing");
    const corrupted = new Uint8Array(response);
    const target = first + header.length + 200;
    const targetByte = corrupted[target];
    if (targetByte === undefined) throw new Error("OCSP signature is truncated");
    corrupted[target] = targetByte ^ 0xff;
    return corrupted;
}

function ocspNonceHex(textOutput: string, description: string): string | undefined {
    const lines = textOutput.split("\n");
    for (let index = 0; index < lines.length; index++) {
        if ((lines[index]?.trim() ?? "") === "OCSP Nonce:") {
            const value = (lines[index + 1] ?? "").trim().replace(/[^0-9A-Fa-f]/g, "");
            if (value.length === 0) throw new Error(`${description} carries an empty OCSP nonce`);
            return value.toUpperCase();
        }
    }
    return undefined;
}

function derToPem(der: Uint8Array, label: string): string {
    const base64 = Buffer.from(der).toString("base64");
    const lines: string[] = [];
    for (let index = 0; index < base64.length; index += 64) {
        lines.push(base64.slice(index, index + 64));
    }
    return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

async function validateWithSession(
    leaf: pkijs.Certificate,
    issuer: pkijs.Certificate,
    fetcher: RevocationDataFetcher,
    options: { includeOCSPNonce?: boolean } = {}
): Promise<{ status: string; errors: string[]; sources: string[] }> {
    const session = new ValidationSession({
        fetcher,
        checkDate: new Date(),
        clockSkewMs: CLOCK_SKEW_MS,
        ...(options.includeOCSPNonce !== undefined
            ? { includeOCSPNonce: options.includeOCSPNonce }
            : {}),
    });
    session.queueCertificate(leaf, { issuer });
    const [result] = await session.validateAll();
    if (!result) throw new Error("ValidationSession returned no result");
    return {
        status: result.revocationStatus,
        errors: [...result.errors],
        sources: [...result.sources],
    };
}

async function sectionRevocationOcsp(ctx: SectionContext): Promise<{
    tsaCert: pkijs.Certificate;
    rootCert: pkijs.Certificate;
    emptyCrlDer: Uint8Array;
    goodOcspDer: Uint8Array;
}> {
    const section = "revocation";
    const { ledger } = ctx;
    const tsaDir = join(ctx.workdir, "tsa-revocation");
    mkdirSync(tsaDir, { recursive: true });
    const tsa = createLocalTsa(tsaDir, { ocspUrl: OCSP_URL, crlUrl: CRL_URL });
    const tsaLeaf = pkijsCertificateFromDer(readPemDer(tsa.tsaCert));
    const rootCa = pkijsCertificateFromDer(readPemDer(tsa.rootCert));
    const serial = certSerialHex(tsa.tsaCert);
    const tsaEpochs = certValidityEpochs(tsa.tsaCert);
    const expiry = opensslIndexDate(tsaEpochs.notAfter);

    const writeIndex = (status: "V" | "R"): string => {
        const now = opensslIndexDate(Math.floor(Date.now() / 1000));
        const line =
            status === "V"
                ? `V\t${expiry}\t\t${serial}\tunknown\t/CN=Offline PAdES Test TSA\n`
                : `R\t${expiry}\t${now}\t${serial}\tunknown\t/CN=Offline PAdES Test TSA\n`;
        const indexPath = join(ctx.workdir, `ocsp-index-${status}.txt`);
        writeFileSync(indexPath, line);
        return indexPath;
    };

    // Omit mode: one artifact verified by BOTH engines end to end.
    const omitResponder = new OpensslOcspResponder(
        ctx.workdir,
        writeIndex("V"),
        tsa.rootCert,
        tsa.rootCert,
        tsa.rootKey
    );
    const omit = await validateWithSession(tsaLeaf, rootCa, omitResponder, {
        includeOCSPNonce: false,
    });
    assert.equal(omit.status, "good", omit.errors.join("\n"));
    assert.deepEqual(omit.sources, ["OCSP"]);
    const omitRequest = omitResponder.requests[0];
    const omitResponse = omitResponder.responses[0];
    if (!omitRequest || !omitResponse) throw new Error("omit-mode exchange is missing");
    writeArtifact(ctx, "ocsp-omit-req.der", omitRequest, "library OCSP request (omit)");
    const omitResponsePath = writeArtifact(ctx, "ocsp-omit-resp.der", omitResponse, "openssl OCSP response (omit)");
    const omitOracle = run(
        "openssl",
        ["ocsp", "-respin", omitResponsePath, "-issuer", tsa.rootCert, "-cert", tsa.tsaCert, "-CAfile", tsa.rootCert, "-text"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.equal(omitOracle.status, 0, commandFailure(omitOracle));
    assert.match(commandFailure(omitOracle), /Response verify OK/);
    assert.match(omitOracle.stdout, /Cert Status: good/);
    ledger.record(section, "openssl-ocsp", "omit-mode good", "verify OK + good", "verify OK + good");
    ledger.record(section, "library", "omit-mode good", "good", omit.status);
    const parsedOmit = parseOCSPResponse(omitResponse);
    assert.equal(parsedOmit.certStatus, CertificateStatus.GOOD);
    assert.ok(parsedOmit.thisUpdate instanceof Date && parsedOmit.nextUpdate !== undefined);
    ledger.record(section, "library", "omit-mode profile", "GOOD + updates", "GOOD + updates");

    // Strict mode: the pinned responder echoes the library's fresh nonce.
    const strictResponder = new OpensslOcspResponder(
        ctx.workdir,
        writeIndex("V"),
        tsa.rootCert,
        tsa.rootCert,
        tsa.rootKey
    );
    const strict = await validateWithSession(tsaLeaf, rootCa, strictResponder);
    assert.equal(strict.status, "good", strict.errors.join("\n"));
    const strictRequest = strictResponder.requests[0];
    const strictResponse = strictResponder.responses[0];
    if (!strictRequest || !strictResponse) throw new Error("strict-mode exchange is missing");
    const strictRequestPath = writeArtifact(ctx, "ocsp-strict-req.der", strictRequest, "library OCSP request (strict)");
    const strictResponsePath = writeArtifact(ctx, "ocsp-strict-resp.der", strictResponse, "openssl OCSP response (strict)");
    const strictReqText = assertSuccess(
        "openssl",
        ["ocsp", "-reqin", strictRequestPath, "-text"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    ).stdout;
    const strictRespText = assertSuccess(
        "openssl",
        ["ocsp", "-respin", strictResponsePath, "-text", "-noverify"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    ).stdout;
    const requestedNonce = ocspNonceHex(strictReqText, "library request");
    const echoedNonce = ocspNonceHex(strictRespText, "openssl response");
    assert.ok(requestedNonce !== undefined && requestedNonce.length > 0, "request carries a nonce");
    assert.equal(echoedNonce, requestedNonce, "responder must echo the request nonce");
    assert.match(strictRespText, /Cert Status: good/);
    ledger.record(section, "openssl-ocsp", "strict-mode echo", "nonce echoed + good", "nonce echoed + good");
    ledger.record(section, "library", "strict-mode good", "good", strict.status);
    // Pinned-tool limitation, evidenced: -respin cannot verify a
    // nonce-bearing response offline, even with the matching -reqin.
    const strictFull = run(
        "openssl",
        ["ocsp", "-respin", strictResponsePath, "-reqin", strictRequestPath, "-issuer", tsa.rootCert, "-cert", tsa.tsaCert, "-CAfile", tsa.rootCert],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.notEqual(strictFull.status, 0, "respin must fail on nonce-bearing responses");
    assert.match(commandFailure(strictFull), /Nonce Verify error/);
    ledger.record(section, "openssl-ocsp", "respin nonce limitation", "Nonce Verify error", "Nonce Verify error");

    // Revoked: the index marks the TSA serial revoked.
    const revokedResponder = new OpensslOcspResponder(
        ctx.workdir,
        writeIndex("R"),
        tsa.rootCert,
        tsa.rootCert,
        tsa.rootKey
    );
    const revoked = await validateWithSession(tsaLeaf, rootCa, revokedResponder, {
        includeOCSPNonce: false,
    });
    assert.equal(revoked.status, "revoked", revoked.errors.join("\n"));
    const revokedResponse = revokedResponder.responses[0];
    if (!revokedResponse) throw new Error("revoked exchange is missing");
    const revokedResponsePath = writeArtifact(ctx, "ocsp-revoked-resp.der", revokedResponse, "openssl OCSP response (revoked)");
    const revokedOracle = run(
        "openssl",
        ["ocsp", "-respin", revokedResponsePath, "-issuer", tsa.rootCert, "-cert", tsa.tsaCert, "-CAfile", tsa.rootCert, "-text"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.equal(revokedOracle.status, 0, commandFailure(revokedOracle));
    assert.match(commandFailure(revokedOracle), /Response verify OK/);
    assert.match(revokedOracle.stdout, /Cert Status: revoked/);
    ledger.record(section, "openssl-ocsp", "revoked", "verify OK + revoked", "verify OK + revoked");
    ledger.record(section, "library", "revoked", "revoked", revoked.status);

    // Tampered: a flipped signature byte breaks the oracle and stays
    // library-unknown. The RSA-2048 response carries exactly two 256-byte
    // BIT STRINGs (response signature first, embedded CA signature
    // second); the flip lands deep inside the first.
    const tampered = corruptFirstSignature256(omitResponse);
    const tamperedPath = writeArtifact(ctx, "ocsp-tampered-resp.der", tampered, "tampered OCSP response");
    const tamperedOracle = run(
        "openssl",
        ["ocsp", "-respin", tamperedPath, "-issuer", tsa.rootCert, "-cert", tsa.tsaCert, "-CAfile", tsa.rootCert],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.notEqual(tamperedOracle.status, 0, "oracle must reject the tampered response");
    ledger.record(section, "openssl-ocsp", "tampered rejection", "status != 0", `status ${String(tamperedOracle.status)}`);
    const tamperedFetcher = new MockFetcher();
    tamperedFetcher.setOCSPResponse(OCSP_URL, tampered);
    const tamperedLibrary = await validateWithSession(tsaLeaf, rootCa, tamperedFetcher, {
        includeOCSPNonce: false,
    });
    assert.equal(tamperedLibrary.status, "unknown");
    assert.match(tamperedLibrary.errors.join("\n"), /signature/i);
    ledger.record(section, "library", "tampered unknown", "unknown /signature/", "unknown /signature/");

    // CRL issuance for the same TSA chain, via `openssl ca -gencrl`.
    const caDir = join(ctx.workdir, "tsa-crl-ca");
    mkdirSync(caDir, { recursive: true });
    const crlIndex = join(caDir, "index.txt");
    writeFileSync(crlIndex, `V\t${expiry}\t\t${serial}\tunknown\t/CN=Offline PAdES Test TSA\n`);
    writeFileSync(join(caDir, "crlnumber"), "1000\n");
    writeFileSync(join(caDir, "serial"), "01\n");
    writeFileSync(
        join(caDir, "ca.cnf"),
        `[ ca ]\ndefault_ca = test_ca\n[ test_ca ]\ndir = ${caDir}\ndatabase = $dir/index.txt\n` +
            `new_certs_dir = $dir\ncertificate = ${tsa.rootCert}\nprivate_key = ${tsa.rootKey}\n` +
            `serial = $dir/serial\ncrlnumber = $dir/crlnumber\ndefault_md = sha256\ndefault_days = 2\n` +
            `default_crl_days = 7\npolicy = policy_any\n[ policy_any ]\ncommonName = supplied\n`
    );
    const emptyCrlPem = join(ctx.workdir, "tsa-empty.crl.pem");
    assertSuccess(
        "openssl",
        ["ca", "-gencrl", "-config", join(caDir, "ca.cnf"), "-out", emptyCrlPem],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    ledger.artifact(ctx.workdir, emptyCrlPem, "openssl CRL (empty)");
    const emptyCrlDerPath = join(ctx.workdir, "tsa-empty.crl.der");
    assertSuccess(
        "openssl",
        ["crl", "-in", emptyCrlPem, "-outform", "DER", "-out", emptyCrlDerPath],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    const emptyCrlDer = new Uint8Array(readFileSync(emptyCrlDerPath));
    ledger.artifact(ctx.workdir, emptyCrlDerPath, "openssl CRL DER (empty)");

    const emptyVerify = run(
        "openssl",
        ["crl", "-in", emptyCrlPem, "-CAfile", tsa.rootCert, "-verify", "-text", "-noout"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.equal(emptyVerify.status, 0, commandFailure(emptyVerify));
    assert.match(commandFailure(emptyVerify), /verify OK/);
    assert.match(emptyVerify.stdout, /No Revoked Certificates/);
    assert.match(emptyVerify.stdout, /X509v3 CRL Number/);
    ledger.record(section, "openssl-crl", "empty CRL profile", "verify OK + number", "verify OK + number");
    const emptyChain = run(
        "openssl",
        ["verify", "-crl_check", "-CRLfile", emptyCrlPem, "-CAfile", tsa.rootCert, tsa.tsaCert],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.equal(emptyChain.status, 0, commandFailure(emptyChain));
    assert.match(emptyChain.stdout, /: OK/);
    ledger.record(section, "openssl-verify", "chain + empty CRL", "OK", "OK");
    const emptyInfo = parseCRLInfo(emptyCrlDer);
    assert.equal(emptyInfo.parsed, true);
    assert.equal(emptyInfo.isDelta, false);
    const emptyFetcher = new MockFetcher();
    emptyFetcher.setCRLResponse(CRL_URL, emptyCrlDer);
    const emptyLibrary = await validateWithSession(tsaLeaf, rootCa, emptyFetcher);
    assert.equal(emptyLibrary.status, "good", emptyLibrary.errors.join("\n"));
    ledger.record(section, "library", "empty CRL good", "good", emptyLibrary.status);

    assertSuccess(
        "openssl",
        ["ca", "-revoke", tsa.tsaCert, "-crl_reason", "keyCompromise", "-config", join(caDir, "ca.cnf")],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    const revokedCrlPem = join(ctx.workdir, "tsa-revoked.crl.pem");
    assertSuccess(
        "openssl",
        ["ca", "-gencrl", "-config", join(caDir, "ca.cnf"), "-out", revokedCrlPem],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    ledger.artifact(ctx.workdir, revokedCrlPem, "openssl CRL (revoked)");
    const revokedCrlDerPath = join(ctx.workdir, "tsa-revoked.crl.der");
    assertSuccess(
        "openssl",
        ["crl", "-in", revokedCrlPem, "-outform", "DER", "-out", revokedCrlDerPath],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    const revokedCrlDer = new Uint8Array(readFileSync(revokedCrlDerPath));
    ledger.artifact(ctx.workdir, revokedCrlDerPath, "openssl CRL DER (revoked)");
    const revokedCrlResult = assertSuccess(
        "openssl",
        ["crl", "-in", revokedCrlPem, "-CAfile", tsa.rootCert, "-verify", "-text", "-noout"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    const revokedCrlText = revokedCrlResult.stdout;
    assert.match(commandFailure(revokedCrlResult), /verify OK/);
    assert.ok(revokedCrlText.includes(serial), "revoked CRL must list the TSA serial");
    const revokedChain = run(
        "openssl",
        ["verify", "-crl_check", "-CRLfile", revokedCrlPem, "-CAfile", tsa.rootCert, tsa.tsaCert],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.notEqual(revokedChain.status, 0, "chain check must report the revocation");
    assert.match(commandFailure(revokedChain), /certificate revoked/);
    ledger.record(section, "openssl-crl", "revoked CRL profile", "verify OK + serial listed", "verify OK + serial listed");
    ledger.record(section, "openssl-verify", "chain + revoked CRL", "certificate revoked", "certificate revoked");
    const revokedFetcher = new MockFetcher();
    revokedFetcher.setCRLResponse(CRL_URL, revokedCrlDer);
    const revokedCrlLibrary = await validateWithSession(tsaLeaf, rootCa, revokedFetcher);
    assert.equal(revokedCrlLibrary.status, "revoked", revokedCrlLibrary.errors.join("\n"));
    ledger.record(section, "library", "revoked CRL", "revoked", revokedCrlLibrary.status);

    return { tsaCert: tsaLeaf, rootCert: rootCa, emptyCrlDer, goodOcspDer: omitResponse };
}
async function sectionRevocationUnsupported(ctx: SectionContext): Promise<void> {
    const section = "revocation";
    const { ledger } = ctx;
    // Unsupported CRL shapes stay `unknown` until support is deliberately
    // added. The oracle proves the fixtures are well-formed, genuinely
    // signed delta/indirect CRLs; the library pins the unknown verdict.
    const ca = await createTestCA("T15 Unsupported CRL CA");
    const leaf = await createTestLeaf(ca, { crlUrls: [CRL_URL] });
    const now = new Date();
    now.setMilliseconds(0);
    const thisUpdate = new Date(now.getTime() - 3600_000);
    const nextUpdate = new Date(now.getTime() + 7 * 86400_000);
    const caDer = new Uint8Array(ca.cert.toSchema().toBER(false));
    const caPemPath = writeArtifact(
        ctx,
        "unsupported-ca.pem",
        new Uint8Array(Buffer.from(derToPem(caDer, "CERTIFICATE"))),
        "pkijs CA for unsupported CRLs"
    );

    const delta = await createSignedCRL(ca, {
        thisUpdate,
        nextUpdate,
        crlExtensions: [crlNumberExtension(2), deltaCrlIndicatorExtension(1)],
    });
    writeArtifact(ctx, "unsupported-delta.crl.der", delta, "delta CRL fixture");
    const deltaPemPath = join(ctx.workdir, "unsupported-delta.crl.pem");
    writeFileSync(deltaPemPath, derToPem(delta, "X509 CRL"));
    const deltaOracle = run(
        "openssl",
        ["crl", "-in", deltaPemPath, "-CAfile", caPemPath, "-verify", "-text", "-noout"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.equal(deltaOracle.status, 0, commandFailure(deltaOracle));
    assert.match(commandFailure(deltaOracle), /verify OK/);
    assert.match(deltaOracle.stdout, /X509v3 Delta CRL Indicator/);
    ledger.record(section, "openssl-crl", "delta CRL profile", "verify OK + delta indicator", "verify OK + delta indicator");
    const deltaInfo = parseCRLInfo(delta);
    assert.equal(deltaInfo.parsed, true);
    assert.equal(deltaInfo.isDelta, true);
    const deltaFetcher = new MockFetcher();
    deltaFetcher.setCRLResponse(CRL_URL, delta);
    const deltaLibrary = await validateWithSession(leaf.cert, ca.cert, deltaFetcher);
    assert.equal(deltaLibrary.status, "unknown");
    assert.match(deltaLibrary.errors.join("\n"), /delta/i);
    ledger.record(section, "library", "delta CRL unknown", "unknown /delta/", "unknown /delta/");

    const indirect = await createSignedCRL(ca, {
        thisUpdate,
        nextUpdate,
        crlExtensions: [
            crlNumberExtension(3),
            issuingDistributionPointExtension(
                new pkijs.IssuingDistributionPoint({ indirectCRL: true })
            ),
        ],
    });
    writeArtifact(ctx, "unsupported-indirect.crl.der", indirect, "indirect CRL fixture");
    const indirectPemPath = join(ctx.workdir, "unsupported-indirect.crl.pem");
    writeFileSync(indirectPemPath, derToPem(indirect, "X509 CRL"));
    const indirectOracle = run(
        "openssl",
        ["crl", "-in", indirectPemPath, "-CAfile", caPemPath, "-verify", "-text", "-noout"],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.equal(indirectOracle.status, 0, commandFailure(indirectOracle));
    assert.match(commandFailure(indirectOracle), /verify OK/);
    assert.match(indirectOracle.stdout, /Indirect CRL/);
    ledger.record(section, "openssl-crl", "indirect CRL profile", "verify OK + indirect", "verify OK + indirect");
    const indirectFetcher = new MockFetcher();
    indirectFetcher.setCRLResponse(CRL_URL, indirect);
    const indirectLibrary = await validateWithSession(leaf.cert, ca.cert, indirectFetcher);
    assert.equal(indirectLibrary.status, "unknown");
    assert.match(indirectLibrary.errors.join("\n"), /indirect/i);
    ledger.record(section, "library", "indirect CRL unknown", "unknown /indirect/", "unknown /indirect/");

    // Owned T07 interop blobs under the pinned oracle: third-party bytes
    // (OpenSSL 3.5.5) qualified by OpenSSL 3.0.13 plus the library.
    const interopCa = decodeInteropDer(OPENSSL_INTEROP_CA_BASE64);
    const interopLeaf = decodeInteropDer(OPENSSL_INTEROP_LEAF_BASE64);
    const interopEmpty = decodeInteropDer(OPENSSL_INTEROP_EMPTY_CRL_BASE64);
    const interopRevoked = decodeInteropDer(OPENSSL_INTEROP_REVOKED_CRL_BASE64);
    const interopCaPath = writeArtifact(ctx, "interop-ca.pem", new Uint8Array(Buffer.from(derToPem(interopCa, "CERTIFICATE"))), "interop CA");
    const interopLeafPath = writeArtifact(ctx, "interop-leaf.pem", new Uint8Array(Buffer.from(derToPem(interopLeaf, "CERTIFICATE"))), "interop leaf");
    const interopEmptyPath = writeArtifact(ctx, "interop-empty.crl.pem", new Uint8Array(Buffer.from(derToPem(interopEmpty, "X509 CRL"))), "interop CRL (empty)");
    const interopRevokedPath = writeArtifact(ctx, "interop-revoked.crl.pem", new Uint8Array(Buffer.from(derToPem(interopRevoked, "X509 CRL"))), "interop CRL (revoked)");
    for (const [label, path] of [["empty", interopEmptyPath], ["revoked", interopRevokedPath]] as [string, string][]) {
        const verifyCrl = run(
            "openssl",
            ["crl", "-in", path, "-CAfile", interopCaPath, "-verify"],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        );
        assert.equal(verifyCrl.status, 0, commandFailure(verifyCrl));
        assert.match(commandFailure(verifyCrl), /verify OK/);
        ledger.record(section, "openssl-crl", `interop ${label} CRL`, "verify OK", "verify OK");
    }
    const interopChainGood = run(
        "openssl",
        ["verify", "-crl_check", "-CRLfile", interopEmptyPath, "-CAfile", interopCaPath, interopLeafPath],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.equal(interopChainGood.status, 0, commandFailure(interopChainGood));
    ledger.record(section, "openssl-verify", "interop chain + empty CRL", "OK", "OK");
    const interopChainRevoked = run(
        "openssl",
        ["verify", "-crl_check", "-CRLfile", interopRevokedPath, "-CAfile", interopCaPath, interopLeafPath],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    );
    assert.notEqual(interopChainRevoked.status, 0, "interop revoked chain must fail");
    assert.match(commandFailure(interopChainRevoked), /certificate revoked/);
    ledger.record(section, "openssl-verify", "interop chain + revoked CRL", "certificate revoked", "certificate revoked");

    const interopLeafCert = pkijsCertificateFromDer(interopLeaf);
    const interopCaCert = pkijsCertificateFromDer(interopCa);
    const interopEmptyFetcher = new MockFetcher();
    interopEmptyFetcher.setCRLResponse("http://crl.example.com/t07.crl", interopEmpty);
    const interopEmptyLibrary = await validateWithSession(interopLeafCert, interopCaCert, interopEmptyFetcher);
    assert.equal(interopEmptyLibrary.status, "good", interopEmptyLibrary.errors.join("\n"));
    ledger.record(section, "library", "interop empty CRL", "good", interopEmptyLibrary.status);
    const interopRevokedFetcher = new MockFetcher();
    interopRevokedFetcher.setCRLResponse("http://crl.example.com/t07.crl", interopRevoked);
    const interopRevokedLibrary = await validateWithSession(interopLeafCert, interopCaCert, interopRevokedFetcher);
    assert.equal(interopRevokedLibrary.status, "revoked", interopRevokedLibrary.errors.join("\n"));
    ledger.record(section, "library", "interop revoked CRL", "revoked", interopRevokedLibrary.status);
}

async function sectionClosureC03(
    ctx: SectionContext,
    tsaConfig: string,
    rootCert: string,
    rootDer: Uint8Array,
    revocation: { emptyCrlDer: Uint8Array; goodOcspDer: Uint8Array; tsaCertDer: Uint8Array }
): Promise<void> {
    const section = "c03-closure";
    const { ledger } = ctx;
    const input = await createOnePagePdf("Offline PAdES C03 retention");
    const rev1 = await stampWithLocalTsa(ctx, "c03-r1", input, tsaConfig, "SHA-256");
    const firstExtracted = await extractTimestamps(rev1.pdf);
    assert.equal(firstExtracted.length, 1);
    const fieldName = firstExtracted[0]?.fieldName;
    if (!fieldName) throw new Error("C03 revision 1 field name is missing");

    const withVri = await addVRIForSignature(
        rev1.pdf,
        { fieldName },
        {
            validationData: {
                certificates: [revocation.tsaCertDer, rootDer],
                crls: [revocation.emptyCrlDer],
                ocspResponses: [revocation.goodOcspDer],
            },
        }
    );
    const withVriPath = writeArtifact(ctx, "c03-r1-vri.pdf", withVri, "C03 revision 1 with VRI");
    const vriJson = assertSuccess(
        "qpdf",
        ["--json", withVriPath],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    ).stdout;
    const vriCoverages = assertQpdfMultiStructure(withVri, vriJson, 1, { expectVri: true });
    if (!vriCoverages[0]) throw new Error("C03 VRI coverage is missing");
    const vriModel = parseQpdfJson(vriJson);
    const vriCatalog = resolveQpdfReference(vriModel.objects, vriModel.trailer["/Root"], "VRI trailer /Root");
    const vriDss = resolveQpdfReference(vriModel.objects, vriCatalog["/DSS"], "VRI catalog /DSS");
    const vriEntry = vriDss["/VRI"];
    if (!isRecord(vriEntry)) throw new Error("C03 revision must carry a /DSS /VRI dictionary");
    const vriKeys = Object.keys(vriEntry);
    assert.equal(vriKeys.length, 1, "exactly one VRI entry is expected");
    const vriSnapshot = JSON.stringify(vriEntry);
    const dssCertRefs = JSON.stringify(vriDss["/Certs"]);
    const dssOcspRefs = JSON.stringify(vriDss["/OCSPs"] ?? null);
    const dssCrlRefs = JSON.stringify(vriDss["/CRLs"] ?? null);
    ledger.record(section, "qpdf", "VRI entry created", "1 VRI entry + DSS refs", "1 VRI entry + DSS refs");

    const rev2 = await stampWithLocalTsa(ctx, "c03-r2", withVri, tsaConfig, "SHA-256");
    assert.ok(
        bytesEqual(rev2.pdf.slice(0, withVri.length), withVri),
        "C03: the second revision must preserve every earlier byte exactly"
    );
    ledger.record(section, "library", "C03 prefix preservation", "rev2 starts with rev1+vri", "rev2 starts with rev1+vri");

    const rev2Json = assertSuccess(
        "qpdf",
        ["--json", rev2.pdfPath],
        PINNED_ORACLE_INSTALLATION_GUIDANCE
    ).stdout;
    const rev2Coverages = assertQpdfMultiStructure(rev2.pdf, rev2Json, 2, { expectVri: true });
    assert.equal(rev2Coverages.length, 2);
    ledger.record(section, "qpdf", "C03 two-signature structure", "2 ranges", "2 ranges");
    const rev2Model = parseQpdfJson(rev2Json);
    const rev2Catalog = resolveQpdfReference(rev2Model.objects, rev2Model.trailer["/Root"], "rev2 trailer /Root");
    const rev2Dss = resolveQpdfReference(rev2Model.objects, rev2Catalog["/DSS"], "rev2 catalog /DSS");
    const rev2Vri = rev2Dss["/VRI"];
    if (!isRecord(rev2Vri)) throw new Error("C03 revision 2 must retain the /DSS /VRI dictionary");
    assert.equal(JSON.stringify(rev2Vri), vriSnapshot, "C03: the VRI entry must survive byte-identical as decoded objects");
    for (const [label, before, after] of [
        ["Certs", dssCertRefs, JSON.stringify(rev2Dss["/Certs"])],
        ["OCSPs", dssOcspRefs, JSON.stringify(rev2Dss["/OCSPs"] ?? null)],
        ["CRLs", dssCrlRefs, JSON.stringify(rev2Dss["/CRLs"] ?? null)],
    ] as [string, string, string][]) {
        const beforeRefs: unknown = JSON.parse(before);
        const afterRefs: unknown = JSON.parse(after);
        if (!Array.isArray(beforeRefs) || !Array.isArray(afterRefs)) continue;
        for (const ref of beforeRefs) {
            assert.ok(afterRefs.includes(ref), `C03: /DSS /${label} must retain ${String(ref)}`);
        }
    }
    ledger.record(section, "qpdf", "C03 DSS/VRI retention", "VRI identical + DSS refs retained", "VRI identical + DSS refs retained");

    // The VRI key is the signature-Contents key: SHA-1 over the
    // complete decoded, padded /Contents bytes of revision 1.
    const contentsKey = `/${createHash("sha1").update(firstExtracted[0]?.contentsValueBytes ?? new Uint8Array()).digest("hex").toUpperCase()}`;
    assert.deepEqual(vriKeys, [contentsKey], "VRI key must be the Contents SHA-1");
    ledger.record(section, "qpdf", "C03 VRI Contents key", "SHA-1 key", "SHA-1 key");

    // Exact artifact bytes, encoding-agnostic: qpdf decodes every DSS/VRI
    // stream (--filtered-stream-data), so compressed and uncompressed DSS
    // compare equally. Each retained stream must decode byte-identical
    // across the revision, and the VRI entry's streams must equal the
    // exact supplied validation-data bytes.
    const refObjectNumbers = (value: unknown): number[] => {
        const numbers: number[] = [];
        const collect = (entry: unknown): void => {
            if (typeof entry === "string") {
                const match = /^([0-9]{1,10}) [0-9]{1,10} R$/.exec(entry);
                if (match?.[1]) numbers.push(Number(match[1]));
            } else if (Array.isArray(entry)) {
                for (const item of entry) collect(item);
            } else if (isRecord(entry)) {
                for (const item of Object.values(entry)) collect(item);
            }
        };
        collect(value);
        return numbers;
    };
    const beforeCerts = refObjectNumbers(JSON.parse(dssCertRefs));
    const beforeCrls = refObjectNumbers(JSON.parse(dssCrlRefs));
    const beforeOcsps = refObjectNumbers(JSON.parse(dssOcspRefs));
    assert.ok(beforeCerts.length > 0, "C03 DSS must list certificates");
    const dumpDecoded = (pdfPath: string, objectNumber: number): Uint8Array => {
        const result = runBytes(
            "qpdf",
            [pdfPath, `--show-object=${objectNumber.toString()}`, "--filtered-stream-data"],
            PINNED_ORACLE_INSTALLATION_GUIDANCE
        );
        assert.equal(result.status, 0, result.stderr);
        return result.stdout;
    };
    const beforeStreams = new Map<number, Uint8Array>();
    for (const objectNumber of [...beforeCerts, ...beforeCrls, ...beforeOcsps]) {
        beforeStreams.set(objectNumber, dumpDecoded(withVriPath, objectNumber));
    }
    const afterDumps = (pdfPath: string, objectNumbers: number[]): Uint8Array[] =>
        objectNumbers.map((objectNumber) => dumpDecoded(pdfPath, objectNumber));
    const rev2Certs = refObjectNumbers(rev2Dss["/Certs"]);
    const rev2Crls = refObjectNumbers(rev2Dss["/CRLs"] ?? null);
    const rev2Ocsps = refObjectNumbers(rev2Dss["/OCSPs"] ?? null);
    const hexOf = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
    const multisetContains = (haystack: Uint8Array[], needle: Uint8Array): boolean =>
        haystack.some((candidate) => bytesEqual(candidate, needle));
    const streamOf = (objectNumber: number): Uint8Array => {
        const stream = beforeStreams.get(objectNumber);
        if (stream === undefined) {
            throw new Error(`C03: missing pre-revision stream for object ${objectNumber.toString()}`);
        }
        return stream;
    };
    for (const [label, before, afterNumbers] of [
        ["Certs", beforeCerts.map(streamOf), rev2Certs],
        ["CRLs", beforeCrls.map(streamOf), rev2Crls],
        ["OCSPs", beforeOcsps.map(streamOf), rev2Ocsps],
    ] as [string, Uint8Array[], number[]][]) {
        const after = afterDumps(rev2.pdfPath, afterNumbers);
        for (const stream of before) {
            assert.ok(multisetContains(after, stream), `C03: /DSS /${label} stream must survive byte-identical`);
        }
    }
    ledger.record(
        section,
        "qpdf",
        "C03 decoded bytes retention",
        `${beforeStreams.size.toString()} streams identical`,
        `${beforeStreams.size.toString()} streams identical`
    );
    // sol-finalgap O3: the dump path travels with the model explicitly
    // so a future second call cannot silently pair one revision's object
    // numbers with another revision's bytes.
    const vriStreams = (
        model: QpdfModel,
        pdfPath: string
    ): { certs: Uint8Array[]; crls: Uint8Array[]; ocsps: Uint8Array[] } => {
        const catalog = resolveQpdfReference(model.objects, model.trailer["/Root"], "catalog");
        const dss = resolveQpdfReference(model.objects, catalog["/DSS"], "catalog DSS");
        const entry = dss["/VRI"];
        if (!isRecord(entry)) throw new Error("VRI dictionary is missing");
        const first = Object.values(entry)[0];
        if (!isRecord(first)) throw new Error("VRI entry is missing");
        return {
            certs: refObjectNumbers(first["/Cert"]).map((n) => dumpDecoded(pdfPath, n)),
            crls: refObjectNumbers(first["/CRL"]).map((n) => dumpDecoded(pdfPath, n)),
            ocsps: refObjectNumbers(first["/OCSP"]).map((n) => dumpDecoded(pdfPath, n)),
        };
    };
    const vriDecoded = vriStreams(vriModel, withVriPath);
    assert.deepEqual(
        vriDecoded.certs.map(hexOf).sort(),
        [hexOf(revocation.tsaCertDer), hexOf(rootDer)].sort(),
        "VRI certificates must equal the supplied bytes exactly"
    );
    assert.deepEqual(
        vriDecoded.crls.map(hexOf),
        [hexOf(revocation.emptyCrlDer)],
        "VRI CRL must equal the supplied bytes exactly"
    );
    assert.deepEqual(
        vriDecoded.ocsps.map(hexOf),
        [hexOf(revocation.goodOcspDer)],
        "VRI OCSP must equal the supplied bytes exactly"
    );
    ledger.record(section, "qpdf", "C03 VRI bytes exact", "4/4 artifacts equal", "4/4 artifacts equal");

    const verifiedBy = await verifyWithVerifiedBy(rev2.pdf);
    assert.equal(verifiedBy.status, "verified-untrusted-root");
    assert.equal(verifiedBy.timestampCount, 2);
    assertVerifiedByElement(verifiedBy.elements[0], { documentMatches: true, anchored: false }, "C03 revision 1");
    assertVerifiedByElement(verifiedBy.elements[1], { documentMatches: true, anchored: false }, "C03 revision 2");
    ledger.record(section, "verifiedby", "C03 matrix", "2 elements verify", "2 elements verify");
    const anchored = await verifyWithVerifiedBy(rev2.pdf, [rootDer]);
    assert.equal(anchored.status, "verified");
    ledger.record(section, "verifiedby", "C03 anchored", "verified", "verified");

    const library = await verifyPdfTimestamps(rev2.pdf, {
        trustStore: (() => {
            const store = new SimpleTrustStore();
            store.addCertificate(pkijsCertificateFromDer(rootDer));
            return store;
        })(),
        strictESSValidation: true,
    });
    assert.deepEqual(
        library.map((entry) => entry.verified),
        [true, true],
        "C03 library per-revision verification"
    );
    ledger.record(section, "library", "C03 library verify", "[true, true]", "[true, true]");

    const firstCoverage = rev2Coverages[0];
    if (!firstCoverage) throw new Error("C03 revision coverages are missing");
    const tamper = tamperCoveredWhitespace(rev2.pdf, firstCoverage.byteRange);
    const tamperPath = writeArtifact(ctx, "c03-tampered.pdf", tamper.tampered, "C03 tamper control");
    const tamperedVerifiedBy = await verifyWithVerifiedBy(tamper.tampered);
    assert.equal(tamperedVerifiedBy.status, "mismatch");
    assert.equal(tamperedVerifiedBy.elements[0]?.documentMatches, false);
    const tamperedPyhanko = runPyhanko(ctx, tamperPath, rootCert);
    assert.notEqual(tamperedPyhanko.status, 0, "pyHanko must reject the C03 tamper");
    ledger.record(section, "verifiedby", "C03 tamper", "mismatch", "mismatch");
    ledger.record(section, "pyhanko", "C03 tamper", "rejected", "rejected");
}
const REQUIRED_SECTION_COUNTS = [
    "section:hash-breadth",
    "section:multi-signature",
    "section:validity-boundaries",
    "section:trust-target",
    "section:resigned-binding",
    "section:token-rigor",
    "section:revocation",
    "section:c03-closure",
];

const REQUIRED_ORACLE_COUNTS = [
    "oracle:openssl-ts",
    "oracle:openssl-verify",
    "oracle:openssl-ocsp",
    "oracle:openssl-crl",
    "oracle:qpdf",
    "oracle:pyhanko",
    "oracle:verifiedby",
    "oracle:library",
];

// sol-finalgap O2 (practical close): bare nonzero checks let a removed
// leg pass silently, so pin every section/oracle minimum at the
// measured breadth. Leg loss fails loudly; additions stay free -- raise
// the minimum when breadth grows on purpose, like coverage floors.
// Full case-name pinning stays deferred: names embed dynamic epochs
// (validity-boundaries attime values), so it needs a case-identity
// design first.
const REQUIRED_MINIMUM_COUNTS: Record<string, number> = {
    "section:hash-breadth": 69,
    "section:multi-signature": 23,
    "section:validity-boundaries": 25,
    "section:trust-target": 7,
    "section:resigned-binding": 7,
    "section:token-rigor": 12,
    "section:revocation": 26,
    "section:c03-closure": 12,
    "oracle:openssl-ts": 51,
    "oracle:openssl-verify": 10,
    "oracle:openssl-ocsp": 5,
    "oracle:openssl-crl": 6,
    "oracle:qpdf": 15,
    "oracle:pyhanko": 20,
    "oracle:verifiedby": 27,
    "oracle:library": 47,
};
const REQUIRED_MINIMUM_TOTAL = 182;

const RECORDED_LIMITATIONS = [
    "OpenSSL 3.0.13 ts -verify -attime treats notAfter as exclusive while the library and pyHanko 0.37.0 (tolerance 0) treat it as inclusive; pinned at the exact na instant in validity-boundaries and token-rigor.",
    "openssl ocsp -respin cannot verify a nonce-bearing response offline (Nonce Verify error even with the matching -reqin); strict-mode OCSP is oracle-qualified structurally (parse plus echoed-nonce hex equality plus Cert Status) while omit-mode carries the full signature verification.",
    "verifiedby 0.1.0 authentic excludes documentMatches by construction; covered-byte tampering is signaled by documentMatches=false plus top-level mismatch.",
    "Live-Sectigo remainder (M2): this gate adds owned local-fixture breadth (RSA/EC signers, fixed instants, revocation material); main-only qualification still needs a captured Sectigo TSQ/TSR/PDF fixture with fixed genTime and its recorded anchored baseline.",
];

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
        const ledger = new ConformanceLedger();
        const ctx: SectionContext = {
            workdir: workingDirectory,
            python,
            verifierPath: join(process.cwd(), "scripts", "verify-pades.py"),
            ledger,
        };
        const versions = collectEngineVersions(ctx);
        ledger.record("harness", "pinned-tools", "engine versions", "all pinned", JSON.stringify(versions));

        const { rootCert, config } = createLocalTsa(workingDirectory);
        const rootDer = readPemDer(rootCert);
        const tsaCert = join(workingDirectory, "tsa.pem");
        const tsaKey = join(workingDirectory, "tsa.key");
        const tsaCertDer = readPemDer(tsaCert);

        await sectionHashBreadth(ctx, config, rootCert, rootDer);
        await sectionMultiSignature(ctx, config, rootCert, rootDer);
        await sectionValidityBoundaries(ctx);
        await sectionTrustTargetAttack(ctx, config, rootCert);
        await sectionResignedBinding(ctx, config, tsaCert, tsaKey, rootCert);
        await sectionTokenRigorHistorical(ctx);
        const revocation = await sectionRevocationOcsp(ctx);
        await sectionRevocationUnsupported(ctx);
        await sectionClosureC03(ctx, config, rootCert, rootDer, {
            emptyCrlDer: revocation.emptyCrlDer,
            goodOcspDer: revocation.goodOcspDer,
            tsaCertDer,
        });

        for (const key of [...REQUIRED_SECTION_COUNTS, ...REQUIRED_ORACLE_COUNTS]) {
            const minimum = REQUIRED_MINIMUM_COUNTS[key] ?? 1;
            assert.ok(
                ledger.count(key) >= minimum,
                `conformance case count for ${key} must be at least ${minimum.toString()}`
            );
        }
        assert.ok(
            ledger.count("total") >= REQUIRED_MINIMUM_TOTAL,
            `conformance total must be at least ${REQUIRED_MINIMUM_TOTAL.toString()}`
        );

        const counts: Record<string, number> = {};
        for (const key of [...REQUIRED_SECTION_COUNTS, ...REQUIRED_ORACLE_COUNTS, "total"]) {
            counts[key] = ledger.count(key);
        }
        const lines = [
            `sections: ${REQUIRED_SECTION_COUNTS.map((key) => `${key.slice("section:".length)}=${ledger.count(key).toString()}`).join(" ")}`,
            `oracles: ${REQUIRED_ORACLE_COUNTS.map((key) => `${key.slice("oracle:".length)}=${ledger.count(key).toString()}`).join(" ")}`,
            `total cases: ${ledger.count("total").toString()}`,
        ];
        process.stdout.write("Offline PAdES interoperability checks passed.\n");
        process.stdout.write(`Engines: ${JSON.stringify(versions)}\n`);
        for (const line of lines) process.stdout.write(`${line}\n`);

        if (retainArtifacts) {
            const report = {
                tool: "offline-pades-conformance.ts",
                policy: PADES_ORACLE_POLICY,
                engines: versions,
                counts,
                cases: ledger.entries,
                artifacts: ledger.artifacts,
                limitations: RECORDED_LIMITATIONS,
            };
            writeFileSync(
                join(workingDirectory, "conformance-report.json"),
                `${JSON.stringify(report, null, 2)}\n`
            );
            process.stdout.write(`Retained local validation artifacts in ${workingDirectory}\n`);
        }
    } finally {
        if (!retainArtifacts) {
            rmSync(workingDirectory, { recursive: true, force: true });
        }
    }
}

async function main(): Promise<void> {
    // pnpm forwards its own `--` separator to the script (as in the
    // `test:interoperability -- --output-dir ...` CI invocation); drop it
    // the same way the packed/browser consumer runners do.
    const options = parseArguments(process.argv.slice(2).filter((argument) => argument !== "--"));
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
