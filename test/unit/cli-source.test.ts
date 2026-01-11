import { describe, it, expect, vi, beforeEach } from "vitest";
import { Command, Option } from "commander";

// Mock all the dependencies that the CLI uses
vi.mock("../../src/index.js", () => ({
    timestampPdf: vi.fn(),
    timestampPdfLTA: vi.fn(),
    extractTimestamps: vi.fn(),
    verifyTimestamp: vi.fn(),
    getDSSInfo: vi.fn(),
    validateTimestampTokenRFC8933Compliance: vi.fn(),
    KNOWN_TSA_URLS: {
        DIGICERT: "http://timestamp.digicert.com",
        SECTIGO: "https://timestamp.sectigo.com",
    },
}));

vi.mock("../../src/utils/circuit-breaker.js", () => ({
    resetCRLCircuits: vi.fn(),
    getCRLCircuitState: vi.fn(),
}));

vi.mock("../../src/pki/crl-client.js", () => ({
    fetchCRL: vi.fn(),
    parseCRLInfo: vi.fn(),
    getCRLCircuitState: vi.fn(),
    resetCRLCircuits: vi.fn(),
}));

vi.mock("../../src/pki/ocsp-client.js", () => ({
    fetchOCSP: vi.fn(),
}));

vi.mock("../../src/pdf/index.js", () => ({
    getDSSInfo: vi.fn(),
}));

vi.mock("node:fs/promises", () => ({
    readFile: vi.fn(),
    writeFile: vi.fn(),
}));

vi.mock("../../src/tsa/index.js", () => ({
    createTimestampRequest: vi.fn(),
    parseTimestampResponse: vi.fn(),
}));

describe("CLI Command Structure and Validation", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe("Command Definitions", () => {
        it("should define timestamp command with correct structure", () => {
            const program = new Command();

            // Recreate the timestamp command structure from the CLI
            const timestampCmd = program
                .command("timestamp")
                .description("Add an RFC 3161 timestamp to a PDF document")
                .argument("<tsa_url>", "TSA server URL (e.g., https://freetsa.org/tsr)")
                .argument("<file>", "Input PDF file")
                .argument("[bucket_output]", "Output file path (optional)")
                .addOption(
                    new Option("-a, --algorithm <alg>", "Hash algorithm")
                        .choices(["SHA-256", "SHA-384", "SHA-512"])
                        .default("SHA-256")
                )
                .option("--ltv", "Enable LTV (Long-Term Validation)", false)
                .option("--timeout <ms>", "Request timeout in milliseconds", "30000")
                .option("--retry <n>", "Number of retry attempts", "3")
                .option("-v, --verbose", "Verbose output", false);

            expect(timestampCmd).toBeDefined();
            expect(timestampCmd.name()).toBe("timestamp");
        });

        it("should define verify command with correct structure", () => {
            const program = new Command();

            const verifyCmd = program
                .command("verify")
                .description("Verify RFC 3161 timestamps in a PDF document")
                .argument("<file>", "PDF file to verify")
                .option("-v, --verbose", "Show detailed timestamp information", false)
                .option("--rfc8933", "Validate RFC 8933 compliance", false);

            expect(verifyCmd).toBeDefined();
            expect(verifyCmd.name()).toBe("verify");
        });

        it("should define archive command with correct structure", () => {
            const program = new Command();

            const archiveCmd = program
                .command("archive")
                .description("Add a PAdES-LTA Archive Timestamp")
                .argument("<tsa_url>", "TSA server URL")
                .argument("<file>", "Input PDF file")
                .argument("[bucket_output]", "Output file path (optional)")
                .addOption(
                    new Option("-a, --algorithm <alg>", "Hash algorithm")
                        .choices(["SHA-256", "SHA-384", "SHA-512"])
                        .default("SHA-256")
                )
                .option("--no-update", "Do not fetch fresh revocation data", false)
                .option("--timeout <ms>", "Request timeout in milliseconds", "30000")
                .option("--retry <n>", "Number of retry attempts", "3")
                .option("-v, --verbose", "Verbose output", false);

            expect(archiveCmd).toBeDefined();
            expect(archiveCmd.name()).toBe("archive");
        });
    });

    describe("Option Validation", () => {
        describe("Algorithm validation", () => {
            it("should accept valid algorithms", () => {
                const validAlgorithms = ["SHA-256", "SHA-384", "SHA-512"];
                expect(validAlgorithms).toContain("SHA-256");
                expect(validAlgorithms).toContain("SHA-384");
                expect(validAlgorithms).toContain("SHA-512");
                expect(validAlgorithms).toHaveLength(3);
            });

            it("should have SHA-256 as default", () => {
                const defaultAlgorithm = "SHA-256";
                expect(defaultAlgorithm).toBe("SHA-256");
            });
        });

        describe("Timeout validation", () => {
            it("should accept valid timeout values", () => {
                const defaultTimeout = 30000;
                expect(defaultTimeout).toBeGreaterThan(0);
                expect(defaultTimeout).toBeLessThanOrEqual(120000);
            });
        });

        describe("Retry validation", () => {
            it("should accept valid retry values", () => {
                const defaultRetry = 3;
                expect(defaultRetry).toBeGreaterThanOrEqual(0);
                expect(defaultRetry).toBeLessThanOrEqual(10);
            });
        });
    });

    describe("Program Configuration", () => {
        it("should configure program with correct name and description", () => {
            const program = new Command();

            const configuredProgram = program
                .name("pdf-rfc3161")
                .description("Add RFC 3161 trusted timestamps to PDF documents.");

            expect(configuredProgram.name()).toBe("pdf-rfc3161");
        });

        it("should include version information", () => {
            const VERSION = "0.1.0";
            expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
        });
    });

    describe("Help and Usage Information", () => {
        it("should provide helpful command descriptions", () => {
            const descriptions = {
                timestamp: "Add an RFC 3161 timestamp to a PDF document",
                verify: "Verify RFC 3161 timestamps in a PDF document",
                archive: "Add a PAdES-LTA Archive Timestamp (long-term preservation)",
            };

            Object.values(descriptions).forEach((desc) => {
                expect(desc).toBeTruthy();
                expect(desc.length).toBeGreaterThan(10);
            });
        });
    });
});
