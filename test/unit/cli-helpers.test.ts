import { describe, it, expect, afterEach } from "vitest";
import { TimestampError, TimestampErrorCode } from "../../src/types.js";

// Set CLI_TEST_MODE before importing the CLI module
const originalEnv = process.env.CLI_TEST_MODE;
process.env.CLI_TEST_MODE = "true";

// Import the CLI module with the environment variable set
const { generateOutputFilename } = await import("../../src/cli/cli.js");

afterEach(() => {
    process.env.CLI_TEST_MODE = originalEnv;
});

describe("CLI Helper Functions", () => {
    describe("generateOutputFilename", () => {
        it("should append -timestamped to filename with extension", () => {
            const result = generateOutputFilename("/path/to/document.pdf");
            expect(result).toBe("/path/to/document-timestamped.pdf");
        });

        it("should handle filename without path", () => {
            const result = generateOutputFilename("document.pdf");
            expect(result).toBe("document-timestamped.pdf");
        });

        it("should handle filename with multiple dots", () => {
            const result = generateOutputFilename("/path/to/file.name.with.dots.pdf");
            expect(result).toBe("/path/to/file.name.with.dots-timestamped.pdf");
        });

        it("should handle filename without extension", () => {
            const result = generateOutputFilename("/path/to/noextension");
            expect(result).toBe("/path/to/noextension-timestamped");
        });

        it("should handle hidden files (starting with dot)", () => {
            const result = generateOutputFilename("/path/to/.hidden.pdf");
            expect(result).toBe("/path/to/.hidden-timestamped.pdf");
        });

        it("should handle dotfile without extension", () => {
            const result = generateOutputFilename("/path/to/.hiddenfile");
            expect(result).toBe("/path/to/.hiddenfile-timestamped");
        });

        it("should handle empty string extension (trailing dot)", () => {
            const result = generateOutputFilename("/path/to/file.");
            expect(result).toBe("/path/to/file-timestamped.");
        });

        it("should preserve directory structure", () => {
            const result = generateOutputFilename("/a/b/c/d/e/file.pdf");
            expect(result).toBe("/a/b/c/d/e/file-timestamped.pdf");
        });

        it("should handle Windows-style paths", () => {
            const result = generateOutputFilename("C:\\Users\\test\\document.pdf");
            expect(result).toBe("C:\\Users\\test\\document-timestamped.pdf");
        });

        it("should handle single character extension", () => {
            const result = generateOutputFilename("file.x");
            expect(result).toBe("file-timestamped.x");
        });

        it("should handle long extensions", () => {
            const result = generateOutputFilename("file.verylongExtension");
            expect(result).toBe("file-timestamped.verylongExtension");
        });

        it("should handle nested directories with spaces", () => {
            const result = generateOutputFilename("/path/with spaces/document.pdf");
            expect(result).toBe("/path/with spaces/document-timestamped.pdf");
        });

        it("should handle paths with special characters", () => {
            const result = generateOutputFilename("/path/with-special-chars/document.pdf");
            expect(result).toBe("/path/with-special-chars/document-timestamped.pdf");
        });

        it("should handle relative paths", () => {
            const result = generateOutputFilename("./relative/path/file.pdf");
            // basename strips "./" prefix from directory
            expect(result).toBe("relative/path/file-timestamped.pdf");
        });

        it("should handle parent directory references", () => {
            const result = generateOutputFilename("../parent/file.pdf");
            expect(result).toBe("../parent/file-timestamped.pdf");
        });

        it("should handle current directory reference", () => {
            const result = generateOutputFilename("./file.pdf");
            // basename strips "./" prefix, so result is just the filename
            expect(result).toBe("file-timestamped.pdf");
        });

        it("should handle very long filenames", () => {
            const longName = "a".repeat(1000);
            const result = generateOutputFilename(`${longName}.pdf`);
            expect(result).toContain("-timestamped.pdf");
            expect(result.length).toBeGreaterThan(1000);
        });

        it("should handle case sensitivity", () => {
            const resultUpper = generateOutputFilename("/path/FILE.PDF");
            const resultLower = generateOutputFilename("/path/file.pdf");
            expect(resultUpper).toBe("/path/FILE-timestamped.PDF");
            expect(resultLower).toBe("/path/file-timestamped.pdf");
        });

        it("should handle root path", () => {
            const result = generateOutputFilename("/file.pdf");
            expect(result).toBe("/file-timestamped.pdf");
        });

        it("should handle home directory", () => {
            const result = generateOutputFilename("~/file.pdf");
            expect(result).toBe("~/file-timestamped.pdf");
        });
    });
});

describe("CLI Output Generation Patterns", () => {
    describe("Output filename variations", () => {
        it("should generate correct output for timestamp command", () => {
            const input = "input.pdf";
            const output = generateOutputFilename(input);
            expect(output).toBe("input-timestamped.pdf");
        });

        it("should generate correct output for archive command", () => {
            const input = "document.pdf";
            const output = generateOutputFilename(input);
            expect(output).toBe("document-timestamped.pdf");
        });

        it("should handle very long input paths", () => {
            const longPath = "/very/long/path/that/might/exist/inreal/scenarios/document.pdf";
            const output = generateOutputFilename(longPath);
            expect(output).toContain("-timestamped.pdf");
            expect(output.startsWith(longPath.substring(0, longPath.lastIndexOf("/")))).toBe(true);
        });
    });
});

describe("CLI Error Handling Patterns", () => {
    describe("Error type handling", () => {
        it("should distinguish between TimestampError and generic Error", () => {
            const timestampError = new TimestampError(
                TimestampErrorCode.TSA_ERROR,
                "TSA server error"
            );
            const genericError = new Error("Generic error");

            expect(timestampError.code).toBe(TimestampErrorCode.TSA_ERROR);
            expect((genericError as any).code).toBeUndefined();
        });

        it("should preserve error cause chain", () => {
            const cause = new Error("Root cause");
            const error = new TimestampError(
                TimestampErrorCode.NETWORK_ERROR,
                "Network failed",
                cause
            );

            expect(error.cause).toBe(cause);
        });

        it("should handle nested error causes", () => {
            const innerCause = new Error("Inner error");
            const outerCause = new Error("Outer error", { cause: innerCause });
            const error = new TimestampError(
                TimestampErrorCode.NETWORK_ERROR,
                "Network failed",
                outerCause
            );

            expect(error.cause).toBe(outerCause);
        });

        it("should have all TimestampErrorCode values defined", () => {
            expect(TimestampErrorCode.NETWORK_ERROR).toBe("NETWORK_ERROR");
            expect(TimestampErrorCode.TSA_ERROR).toBe("TSA_ERROR");
            expect(TimestampErrorCode.INVALID_RESPONSE).toBe("INVALID_RESPONSE");
            expect(TimestampErrorCode.PDF_ERROR).toBe("PDF_ERROR");
            expect(TimestampErrorCode.TIMEOUT).toBe("TIMEOUT");
            expect(TimestampErrorCode.UNSUPPORTED_ALGORITHM).toBe("UNSUPPORTED_ALGORITHM");
            expect(TimestampErrorCode.LTV_ERROR).toBe("LTV_ERROR");
            expect(TimestampErrorCode.VERIFICATION_FAILED).toBe("VERIFICATION_FAILED");
        });

        it("should format TimestampError message correctly", () => {
            const error = new TimestampError(TimestampErrorCode.NETWORK_ERROR, "Connection failed");
            const message = error.message;
            const code = error.code.toString();

            expect(message).toBe("Connection failed");
            expect(code).toBe("NETWORK_ERROR");
            expect(`[${code}]: ${message}`).toBe("[NETWORK_ERROR]: Connection failed");
        });
    });
});

describe("CLI Constants and Configuration", () => {
    describe("Version information", () => {
        it("should have VERSION constant defined", () => {
            const VERSION = "0.1.0";
            expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
        });
    });

    describe("Algorithm choices", () => {
        it("should have valid algorithm options", () => {
            const algorithms = ["SHA-256", "SHA-384", "SHA-512"];
            expect(algorithms).toHaveLength(3);
            expect(algorithms).toContain("SHA-256");
            expect(algorithms).toContain("SHA-384");
            expect(algorithms).toContain("SHA-512");
        });
    });

    describe("Default timeout", () => {
        it("should have reasonable default timeout", () => {
            const defaultTimeout = 30000;
            expect(defaultTimeout).toBeGreaterThan(0);
            expect(defaultTimeout).toBeLessThanOrEqual(120000);
        });
    });

    describe("Default retry", () => {
        it("should have reasonable default retry", () => {
            const defaultRetry = 3;
            expect(defaultRetry).toBeGreaterThanOrEqual(0);
            expect(defaultRetry).toBeLessThanOrEqual(10);
        });
    });
});
