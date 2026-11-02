// Contract between the Acrobat Reader COM oracle
// (packages/tests/scripts/acrobat-reader-oracle.ps1) and the vitest wrapper.
// The oracle reports numeric signatureValidate codes per PDF; this module
// parses that report strictly and checks each case against its expectation.

/** Wall-clock budget for one oracle run over the whole fixture matrix. */
export const ACROBAT_ORACLE_SPAWN_TIMEOUT_MS = 150_000;

export interface AcrobatSignatureField {
    readonly name: string;
    readonly fieldType: string;
    /** Field.signatureValidate code: -1 not-a-field, 0 blank, 1 unknown, 2 invalid, 3 valid/unverified, 4 valid/verified. */
    readonly validate: number;
    /** Uninterpreted extra oracle readings (status, docValidity, ...). */
    readonly details: Record<string, unknown>;
}

export interface AcrobatCaseResult {
    readonly name: string;
    readonly fields: readonly AcrobatSignatureField[];
}

export interface AcrobatOracleReport {
    readonly oracle: string;
    readonly version: number;
    readonly reader: { readonly product: string; readonly version: string | null };
    readonly results: readonly AcrobatCaseResult[];
}

export interface AcrobatCaseExpectation {
    readonly signed: boolean;
    readonly validate?: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function oracleError(reason: string): Error {
    return new Error(`Acrobat oracle report is unusable: ${reason}`);
}

function readField(value: unknown, caseName: string): AcrobatSignatureField {
    if (!isRecord(value)) throw oracleError(`case ${caseName} has a non-object field`);
    const { name, fieldType, validate, ...details } = value;
    if (typeof name !== "string" || name.length === 0) {
        throw oracleError(`case ${caseName} has a field without a name`);
    }
    if (typeof fieldType !== "string" || fieldType.length === 0) {
        throw oracleError(`case ${caseName} field ${name} has no field type`);
    }
    if (typeof validate !== "number" || !Number.isInteger(validate)) {
        throw oracleError(`case ${caseName} field ${name} has no integer validate code`);
    }
    return { name, fieldType, validate, details };
}

function readResult(value: unknown): AcrobatCaseResult {
    if (!isRecord(value)) throw oracleError("a case result is not an object");
    const { name, fields } = value;
    if (typeof name !== "string" || name.length === 0) {
        throw oracleError("a case result has no name");
    }
    // A null fields array is the oracle's version-independent encoding of an
    // empty field list (PowerShell ConvertTo-Json collapses empty arrays).
    if (fields === null) return { name, fields: [] };
    if (!Array.isArray(fields)) throw oracleError(`case ${name} has no fields array`);
    return { name, fields: fields.map((field) => readField(field, name)) };
}

/**
 * Parses and strictly validates one oracle stdout report. Rejects malformed
 * JSON, contract mismatches, and reports that checked zero cases.
 */
export function parseOracleOutput(stdout: string): AcrobatOracleReport {
    let parsed: unknown;
    try {
        parsed = JSON.parse(stdout) as unknown;
    } catch {
        throw oracleError("stdout is not JSON");
    }
    if (!isRecord(parsed)) throw oracleError("top level is not an object");
    if (parsed.oracle !== "acrobat-reader-oracle" || parsed.version !== 1) {
        throw oracleError("oracle/version contract mismatch");
    }
    if (!isRecord(parsed.reader) || typeof parsed.reader.product !== "string") {
        throw oracleError("reader identity is missing");
    }
    const readerVersion = parsed.reader.version;
    if (readerVersion !== null && typeof readerVersion !== "string") {
        throw oracleError("reader version is neither a string nor null");
    }
    if (!Array.isArray(parsed.results)) throw oracleError("results is not an array");
    if (parsed.results.length === 0) {
        throw oracleError("zero cases checked");
    }
    return {
        oracle: "acrobat-reader-oracle",
        version: 1,
        reader: { product: parsed.reader.product, version: readerVersion },
        results: parsed.results.map(readResult),
    };
}

/**
 * Checks one oracle case result against its expectation. Unsigned cases must
 * report no signature fields; signed cases must report at least one
 * signature-typed field, each carrying the expected validate code.
 */
export function assertAcrobatCase(
    result: AcrobatCaseResult,
    expectation: AcrobatCaseExpectation
): void {
    if (!expectation.signed) {
        if (result.fields.length > 0) {
            throw new Error(
                `Case ${result.name} should be unsigned but Reader reports ` +
                    `${String(result.fields.length)} signature field(s): ` +
                    result.fields.map((field) => field.name).join(", ")
            );
        }
        return;
    }
    if (result.fields.length === 0) {
        throw new Error(`Case ${result.name} should be signed but Reader reports no signature fields`);
    }
    for (const field of result.fields) {
        if (field.fieldType !== "signature") {
            throw new Error(
                `Case ${result.name} field ${field.name} has type ${field.fieldType}, expected signature`
            );
        }
        if (expectation.validate !== undefined && field.validate !== expectation.validate) {
            throw new Error(
                `Case ${result.name} field ${field.name} has validate code ` +
                    `${String(field.validate)}, expected ${String(expectation.validate)}`
            );
        }
    }
}
