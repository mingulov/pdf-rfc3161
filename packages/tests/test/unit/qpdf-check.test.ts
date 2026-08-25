import { describe, expect, it } from "vitest";
import { assertQpdfCheckResult } from "../../src/qpdf-check.js";

describe("assertQpdfCheckResult", () => {
    it("accepts clean qpdf output", () => {
        expect(() => {
            assertQpdfCheckResult({ status: 0, stdout: "", stderr: "" });
        }).not.toThrow();
    });

    it("accepts a nonstructural qpdf warning", () => {
        expect(() => {
            assertQpdfCheckResult({
                status: 3,
                stdout: "WARNING: qpdf: operation succeeded with warnings\n",
                stderr: "",
            });
        }).not.toThrow();
    });

    it.each([
        ["file damage", "WARNING: input.pdf: FiLe Is DaMaGeD\n", ""],
        ["missing startxref", "", "WARNING: input.pdf: missing startxref\n"],
        ["cannot-find startxref", "WARNING: input.pdf: can't find startxref\n", ""],
        ["cannot find startxref", "", "WARNING: input.pdf: cannot find startxref\n"],
        ["xref reconstruction", "", "WARNING: input.pdf: error reconstructing xref: bad offset\n"],
        [
            "cross-reference reconstruction",
            "WARNING: input.pdf: Attempting to reconstruct cross-reference table\n",
            "",
        ],
        ["missing xref", "", "WARNING: input.pdf: xref not found\n"],
    ])(
        "rejects qpdf warning status with %s diagnostics",
        (_name: string, stdout: string, stderr: string) => {
            expect(() => {
                assertQpdfCheckResult({ status: 3, stdout, stderr });
            }).toThrow(/structural damage or recovery/i);
        }
    );

    it.each([2, 1, null])("rejects qpdf status %s", (status: number | null) => {
        expect(() => {
            assertQpdfCheckResult({
                status,
                stdout: "WARNING: qpdf: operation succeeded with warnings\n",
                stderr: "",
            });
        }).toThrow(/unexpected qpdf --check status/i);
    });
});
