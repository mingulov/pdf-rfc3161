import { spawnSync } from "node:child_process";

export interface QpdfCheckResult {
    status: number | null;
    stdout?: string | null;
    stderr?: string | null;
}

function hasStructuralDamageOrRecovery(diagnostics: string): boolean {
    const normalized = diagnostics.toLowerCase();
    if (
        normalized.includes("file is damaged") ||
        normalized.includes("xref not found") ||
        normalized.includes("cross-reference table not found")
    ) {
        return true;
    }

    if (
        [
            "missing startxref",
            "can't find startxref",
            "cannot find startxref",
            "could not find startxref",
            "unable to find startxref",
            "startxref not found",
        ].some((message) => normalized.includes(message))
    ) {
        return true;
    }

    return (
        normalized.includes("reconstruct") &&
        (normalized.includes("xref") || normalized.includes("cross-reference"))
    );
}

function combinedDiagnostics(result: QpdfCheckResult): string {
    return `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
}

export function assertQpdfCheckResult(result: QpdfCheckResult): void {
    if (result.status === 0) return;

    const diagnostics = combinedDiagnostics(result);
    if (result.status === 3 && !hasStructuralDamageOrRecovery(diagnostics)) return;

    if (result.status === 3) {
        throw new Error(`qpdf --check reported structural damage or recovery:\n${diagnostics}`);
    }
    throw new Error(`Unexpected qpdf --check status ${String(result.status)}.\n${diagnostics}`);
}

export function assertQpdfCheck(pdfPath: string): void {
    const result = spawnSync("qpdf", ["--check", pdfPath], { encoding: "utf8" });
    if (result.error) throw result.error;
    assertQpdfCheckResult(result);
}
