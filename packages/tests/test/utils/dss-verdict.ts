// Contract between the DSS oracle driver (packages/tests/dss-oracle) and the
// PAdES conformance harness. The driver reports approval-signature IDs plus
// per-timestamp ETSI indications; this module parses that report strictly
// and checks each case against its expectation.

export interface DssTimestampVerdict {
    readonly id: string;
    readonly indication: string;
}

export interface DssReport {
    readonly tool: string;
    readonly dss: string;
    readonly pdf: string;
    readonly signatures: readonly string[];
    readonly timestamps: readonly DssTimestampVerdict[];
}

export interface DssCaseExpectation {
    readonly signatures: number;
    readonly timestamps: readonly { readonly indication: string }[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function dssError(reason: string): Error {
    return new Error(`DSS oracle report is unusable: ${reason}`);
}

function readTimestamp(value: unknown): DssTimestampVerdict {
    if (!isRecord(value)) throw dssError("a timestamp verdict is not an object");
    if (typeof value.id !== "string" || value.id.length === 0) {
        throw dssError("a timestamp verdict has no id");
    }
    if (typeof value.indication !== "string" || value.indication.length === 0) {
        throw dssError(`timestamp ${value.id} has no indication`);
    }
    return { id: value.id, indication: value.indication };
}

/** Parses and strictly validates one DSS oracle stdout report. */
export function parseDssOutput(stdout: string): DssReport {
    let parsed: unknown;
    try {
        parsed = JSON.parse(stdout) as unknown;
    } catch {
        throw dssError("stdout is not JSON");
    }
    if (!isRecord(parsed)) throw dssError("top level is not an object");
    if (parsed.tool !== "dss-oracle") throw dssError("tool/version contract mismatch");
    if (typeof parsed.dss !== "string" || parsed.dss.length === 0) {
        throw dssError("DSS engine version is missing");
    }
    if (typeof parsed.pdf !== "string" || parsed.pdf.length === 0) {
        throw dssError("validated PDF path is missing");
    }
    if (
        !Array.isArray(parsed.signatures) ||
        !parsed.signatures.every((id): id is string => typeof id === "string")
    ) {
        throw dssError("signatures is not a string array");
    }
    if (!Array.isArray(parsed.timestamps)) throw dssError("timestamps is not an array");
    return {
        tool: "dss-oracle",
        dss: parsed.dss,
        pdf: parsed.pdf,
        signatures: parsed.signatures,
        timestamps: parsed.timestamps.map(readTimestamp),
    };
}

/**
 * Checks one oracle case result against its expectation: exact signature
 * count, exact timestamp count, and per-timestamp ETSI indication.
 */
export function assertDssCase(report: DssReport, expectation: DssCaseExpectation): void {
    if (report.signatures.length !== expectation.signatures) {
        throw new Error(
            `DSS reports ${String(report.signatures.length)} approval signatures for ${report.pdf}, ` +
                `expected signature count ${String(expectation.signatures)}`
        );
    }
    if (report.timestamps.length !== expectation.timestamps.length) {
        if (expectation.timestamps.length === 0) {
            throw new Error(
                `DSS case ${report.pdf} should be unsigned but reports ` +
                    `${String(report.timestamps.length)} timestamp(s)`
            );
        }
        if (report.timestamps.length === 0) {
            throw new Error(
                `DSS case ${report.pdf} should be timestamped but reports no timestamps`
            );
        }
        throw new Error(
            `DSS reports timestamp count ${String(report.timestamps.length)} for ${report.pdf}, ` +
                `expected ${String(expectation.timestamps.length)}`
        );
    }
    for (const [index, expected] of expectation.timestamps.entries()) {
        const actual = report.timestamps[index]?.indication;
        if (actual !== expected.indication) {
            throw new Error(
                `DSS timestamp ${String(index)} of ${report.pdf} has indication ` +
                    `${String(actual)}, expected ${expected.indication}`
            );
        }
    }
}
