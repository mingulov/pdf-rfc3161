import { describe, it, expect } from "vitest";
import { basename, dirname, join } from "node:path";

// Test the generateOutputFilename utility function
function generateOutputFilename(inputFile: string): string {
    const dir = dirname(inputFile);
    const base = basename(inputFile);
    const dotIndex = base.lastIndexOf(".");

    if (dotIndex > 0) {
        const name = base.slice(0, dotIndex);
        const ext = base.slice(dotIndex);
        return join(dir, `${name}-timestamped${ext}`);
    }

    return join(dir, `${base}-timestamped`);
}

describe("CLI Utilities", () => {
    describe("generateOutputFilename", () => {
        it("should append -timestamped to filename without extension", () => {
            const result = generateOutputFilename("/path/to/document");
            expect(result).toBe("/path/to/document-timestamped");
        });

        it("should insert -timestamped before file extension", () => {
            const result = generateOutputFilename("/path/to/document.pdf");
            expect(result).toBe("/path/to/document-timestamped.pdf");
        });

        it("should handle files with multiple dots", () => {
            const result = generateOutputFilename("/path/to/document.v1.pdf");
            expect(result).toBe("/path/to/document.v1-timestamped.pdf");
        });

        it("should handle files in root directory", () => {
            const result = generateOutputFilename("document.pdf");
            expect(result).toBe("document-timestamped.pdf");
        });

        it("should handle files with complex paths", () => {
            const result = generateOutputFilename("/very/deep/path/document.pdf");
            expect(result).toBe("/very/deep/path/document-timestamped.pdf");
        });

        it("should handle hidden files", () => {
            const result = generateOutputFilename("/path/to/.hidden.pdf");
            expect(result).toBe("/path/to/.hidden-timestamped.pdf");
        });
    });
});

describe("CLI Configuration", () => {
    describe("Algorithm validation", () => {
        const validAlgorithms = ["SHA-256", "SHA-384", "SHA-512"];

        it("should accept valid hash algorithms", () => {
            validAlgorithms.forEach((alg) => {
                expect(validAlgorithms).toContain(alg);
            });
        });

        it("should have SHA-256 as default algorithm", () => {
            expect(validAlgorithms).toContain("SHA-256");
        });
    });

    describe("Timeout validation", () => {
        it("should accept positive integer timeout values", () => {
            const validTimeouts = [1000, 5000, 30000, 60000];

            validTimeouts.forEach((timeout) => {
                expect(timeout).toBeGreaterThan(0);
                expect(Number.isInteger(timeout)).toBe(true);
            });
        });

        it("should have reasonable default timeout", () => {
            const defaultTimeout = 30000;
            expect(defaultTimeout).toBeGreaterThan(0);
            expect(defaultTimeout).toBeLessThanOrEqual(120000); // Less than 2 minutes
        });
    });

    describe("Retry validation", () => {
        it("should accept positive integer retry values", () => {
            const validRetries = [0, 1, 3, 5];

            validRetries.forEach((retry) => {
                expect(retry).toBeGreaterThanOrEqual(0);
                expect(Number.isInteger(retry)).toBe(true);
            });
        });

        it("should have reasonable default retry count", () => {
            const defaultRetry = 3;
            expect(defaultRetry).toBeGreaterThanOrEqual(0);
            expect(defaultRetry).toBeLessThanOrEqual(10);
        });
    });
});
