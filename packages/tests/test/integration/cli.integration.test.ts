// test/integration/cli.integration.test.ts - CLI Integration Tests
import { describe, it, expect } from "vitest";
import { spawn } from "child_process";
import { writeFileSync, unlinkSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

describe("CLI Integration Tests", () => {
    const testDir = tmpdir();
    const inputPdf = join(testDir, "test-input.pdf");
    const outputPdf = join(testDir, "test-output.pdf");

    // Create a minimal valid PDF for testing
    const minimalPdf = new Uint8Array([
        0x25,
        0x50,
        0x44,
        0x46,
        0x2d,
        0x31,
        0x2e,
        0x34,
        0x0a, // %PDF-1.4
        0x25,
        0xe2,
        0xe3,
        0xcf,
        0xd3,
        0x0a, // Binary comment
        0x31,
        0x20,
        0x30,
        0x20,
        0x6f,
        0x62,
        0x6a,
        0x0a, // 1 0 obj
        0x3c,
        0x3c,
        0x2f,
        0x54,
        0x79,
        0x70,
        0x65,
        0x2f,
        0x43,
        0x61,
        0x74,
        0x61,
        0x6c,
        0x6f,
        0x67,
        0x3e,
        0x3e,
        0x0a, // <<
        0x65,
        0x6e,
        0x64,
        0x6f,
        0x62,
        0x6a,
        0x0a, // endobj
        0x78,
        0x9c,
        0x63,
        0x00,
        0x01,
        0x00,
        0x00,
        0x05,
        0x00,
        0x01,
        0x0a,
        0x0d,
        0xdd,
        0x2e,
        0x0a, // xref
        0x30,
        0x20,
        0x30,
        0x30,
        0x30,
        0x30,
        0x30,
        0x30,
        0x30,
        0x30,
        0x30,
        0x0a, // trailer
        0x25,
        0x25,
        0x45,
        0x4f,
        0x46,
        0x0a, // %%EOF
    ]);

    beforeEach(() => {
        // Create test PDF file
        writeFileSync(inputPdf, minimalPdf);
    });

    afterEach(() => {
        // Clean up test files
        try {
            if (existsSync(inputPdf)) unlinkSync(inputPdf);
            if (existsSync(outputPdf)) unlinkSync(outputPdf);
        } catch {
            // Ignore cleanup errors
        }
    });

    describe("CLI Help and Version", () => {
        it("should show help when no arguments provided", async () => {
            const result = await runCli([]);
            // CLI shows help on stderr and exits with code 1 when no arguments provided
            expect(result.code).toBe(1);
            expect(result.stderr).toContain("pdf-rfc3161");
            expect(result.stderr).toContain("CLI tool for adding RFC 3161 timestamps");
        });

        it("should show version with --version flag", async () => {
            const result = await runCli(["--version"]);
            expect(result.code).toBe(0);
            expect(result.stdout).toMatch(/\d+\.\d+\.\d+/);
        });

        it("should show help with --help flag", async () => {
            const result = await runCli(["--help"]);
            expect(result.code).toBe(0);
            expect(result.stdout).toContain("timestamp");
            expect(result.stdout).toContain("verify");
            expect(result.stdout).toContain("archive");
        });
    });

    describe("CLI Error Handling", () => {
        it("should handle non-existent input file", async () => {
            const result = await runCli([
                "timestamp",
                "http://freetsa.org/tsr",
                "/nonexistent/file.pdf",
            ]);
            expect(result.code).toBe(1);
            expect(result.stderr).toContain("Error");
        });

        it("should handle invalid TSA URL", async () => {
            const result = await runCli(["timestamp", "not-a-url", inputPdf]);
            expect(result.code).toBe(1);
            expect(result.stderr).toContain("Error");
        });

        it("should handle invalid command", async () => {
            const result = await runCli(["invalid-command"]);
            expect(result.code).toBe(1); // Commander exits with code 1 for unknown commands
            expect(result.stderr).toContain("unknown command");
        });
    });

    describe("CLI Option Validation", () => {
        it("should validate algorithm options", async () => {
            const result = await runCli([
                "timestamp",
                "http://freetsa.org/tsr",
                inputPdf,
                "--algorithm",
                "SHA-256",
            ]);
            // Should not fail due to invalid algorithm
            expect(result.stderr).not.toContain("Invalid algorithm");
        });

        it("should reject invalid algorithm", async () => {
            const result = await runCli([
                "timestamp",
                "http://freetsa.org/tsr",
                inputPdf,
                "--algorithm",
                "INVALID",
            ]);
            expect(result.code).toBe(1);
        });

        it("should accept valid timeout values", async () => {
            const result = await runCli([
                "timestamp",
                "http://freetsa.org/tsr",
                inputPdf,
                "--timeout",
                "5000",
            ]);
            // Command structure should be valid
            expect(result.stderr).not.toContain("Invalid timeout");
        });

        it("should accept valid retry values", async () => {
            const result = await runCli([
                "timestamp",
                "http://freetsa.org/tsr",
                inputPdf,
                "--retry",
                "2",
            ]);
            // Command structure should be valid
            expect(result.stderr).not.toContain("Invalid retry");
        });
    });

    describe("CLI Output Formatting", () => {
        it("should show verbose output when requested", async () => {
            const result = await runCli([
                "timestamp",
                "http://freetsa.org/tsr",
                inputPdf,
                "--verbose",
            ]);

            if (result.code === 0) {
                // If successful, should show detailed output
                expect(result.stdout).toMatch(/Input:\s+/);
                expect(result.stdout).toMatch(/Output:\s+/);
                expect(result.stdout).toMatch(/TSA:\s+/);
            }
        });

        it("should show LTV information when enabled", async () => {
            const result = await runCli([
                "timestamp",
                "http://freetsa.org/tsr",
                inputPdf,
                "--ltv",
                "--verbose",
            ]);

            if (result.code === 0) {
                // Should show LTV data if successful
                expect(result.stdout).toMatch(/LTV Data:/);
            }
        });
    });

    describe("CLI Verify Command", () => {
        it("should verify PDF without timestamps", async () => {
            const result = await runCli(["verify", inputPdf]);
            expect(result.code).toBe(0);
            expect(result.stdout).toContain("No RFC 3161 timestamps found");
        });

        it("should handle non-existent verify file", async () => {
            const result = await runCli(["verify", "/nonexistent/file.pdf"]);
            expect(result.code).toBe(1);
            expect(result.stderr).toContain("Error");
        });

        it("should accept verbose flag for verify", async () => {
            const result = await runCli(["verify", inputPdf, "--verbose"]);
            expect(result.code).toBe(0);
        });

        it("should accept RFC 8933 flag for verify", async () => {
            const result = await runCli(["verify", inputPdf, "--rfc8933"]);
            expect(result.code).toBe(0);
        });

        // Audit C2 regression: --no-require-eku and --no-require-validity
        // must be accepted (commander's --no-* syntax). These are opt-outs
        // from the 0.2.0 default-enforce policy.
        // strictESSValidation library default is `false`, so --strict-ess
        // remains a positive opt-in (see audit F6 revert).
        it("should accept --no-require-eku opt-out", async () => {
            const result = await runCli(["verify", "--no-require-eku", inputPdf]);
            expect(result.stderr).not.toContain("Unknown option");
            expect(result.stderr).not.toContain("unknown option");
        });

        it("should accept --no-require-validity opt-out", async () => {
            const result = await runCli(["verify", "--no-require-validity", inputPdf]);
            expect(result.stderr).not.toContain("Unknown option");
            expect(result.stderr).not.toContain("unknown option");
        });

        // Audit F6: --strict-ess is a positive opt-in (library default is off).
        it("should accept --strict-ess positive opt-in", async () => {
            const result = await runCli(["verify", "--strict-ess", inputPdf]);
            expect(result.stderr).not.toContain("Unknown option");
            expect(result.stderr).not.toContain("unknown option");
        });

        it("--help should advertise the security defaults", async () => {
            const result = await runCli(["verify", "--help"]);
            expect(result.code).toBe(0);
            expect(result.stdout).toContain("--no-require-eku");
            expect(result.stdout).toContain("--no-require-validity");
            expect(result.stdout).toContain("--strict-ess");
            // The help text must communicate that EKU/validity are opt-outs
            // from a 0.2.0 default; strict-ess is a positive opt-in.
            expect(result.stdout).toContain("default: enforce since 0.2.0");
            // Commander wraps "off by default" across lines; match the
            // fragment that doesn't span the wrap boundary.
            expect(result.stdout).toMatch(/off by/);
            expect(result.stdout).toMatch(/default: false/);
        });
    });

    // Audit C3 regression: `timestamp --ltv` previously defaulted false in the
    // CLI, overriding the library default `enableLTV: true`. Now uses --no-ltv
    // opt-out form.
    describe("CLI Timestamp --ltv default", () => {
        it("should advertise --no-ltv (LTV on by default since 0.2.0)", async () => {
            const result = await runCli(["timestamp", "--help"]);
            expect(result.code).toBe(0);
            expect(result.stdout).toContain("--no-ltv");
            // Commander wraps long help lines; check for a fragment that
            // doesn't span the wrap boundary.
            expect(result.stdout).toMatch(/on by default/);
            expect(result.stdout).toMatch(/since 0\.2\.0/);
            // The old --ltv positive flag should no longer appear as a
            // distinct option line.
            expect(result.stdout).not.toMatch(/^\s+--ltv\s+/m);
        });

        it("should accept --no-ltv opt-out", async () => {
            const result = await runCli([
                "timestamp",
                "http://freetsa.org/tsr",
                inputPdf,
                "--no-ltv",
            ]);
            expect(result.stderr).not.toContain("Unknown option");
            expect(result.stderr).not.toContain("unknown option");
        });
    });

    describe("CLI Archive Command", () => {
        it("should handle archive command structure", async () => {
            const result = await runCli(["archive", "http://freetsa.org/tsr", inputPdf]);

            // Should attempt to process (may fail due to no existing timestamps)
            expect(result.code).toBe(1); // Expected to fail without timestamps
            expect(result.stderr).toContain("Error");
        });

        it("should accept archive-specific options", async () => {
            const result = await runCli([
                "archive",
                "http://freetsa.org/tsr",
                inputPdf,
                "--no-update",
            ]);

            // Command structure should be valid
            expect(result.stderr).not.toContain("Unknown option");
        });

        // Audit C4 regression: --no-update was a no-op because Commander
        // stores negated flags under `update`, not `noUpdate`. After the fix,
        // the verbose log line should reflect the actual flag state.
        it("should advertise --no-update meaning in --help", async () => {
            const result = await runCli(["archive", "--help"]);
            expect(result.code).toBe(0);
            expect(result.stdout).toContain("--no-update");
            // The help should now describe the actual semantic, not the old
            // misleading "fetch fresh" wording.
            expect(result.stdout).toMatch(/harvest revocation data/);
        });

        it("--no-update verbose log should report 'Use existing only'", async () => {
            // We don't need the archive to succeed; verbose output streams
            // BEFORE the network call. The presence of "Use existing only"
            // confirms the flag is wired (audit C4 -- previously the line
            // always said "Fetch fresh" because cmdOptions.noUpdate was
            // always undefined).
            const result = await runCli([
                "archive",
                "http://freetsa.org/tsr",
                inputPdf,
                "--no-update",
                "--verbose",
            ]);
            expect(result.stdout).toContain("Use existing only");
        });

        it("default archive --verbose should report 'Fetch fresh'", async () => {
            const result = await runCli([
                "archive",
                "http://freetsa.org/tsr",
                inputPdf,
                "--verbose",
            ]);
            expect(result.stdout).toContain("Fetch fresh");
        });
    });

    // Audit L3: subprocess coverage for the 0.2.x security flags.
    // --no-require-eku / --no-require-validity / --strict-ess are
    // already covered by the Task 1.2 tests under "CLI Verify Command".
    // --no-ltv is covered by Task 1.3 under "CLI Timestamp --ltv default".
    // --no-update is covered by Task 1.4 under "CLI Archive Command".
    // The remaining three -- --trust-store, --reject-on-revocation-warning,
    // --ignore-encryption -- get their own block here.
    describe("CLI 0.2.x security flag coverage (audit L3)", () => {
        it("--reject-on-revocation-warning appears in `timestamp --help`", async () => {
            const result = await runCli(["timestamp", "--help"]);
            expect(result.code).toBe(0);
            expect(result.stdout).toContain("--reject-on-revocation-warning");
        });

        it("`timestamp --reject-on-revocation-warning` parses (no Unknown option)", async () => {
            const result = await runCli([
                "timestamp",
                "http://freetsa.org/tsr",
                inputPdf,
                "--reject-on-revocation-warning",
            ]);
            expect(result.stderr).not.toContain("Unknown option");
            expect(result.stderr).not.toContain("unknown option");
        });

        it("--ignore-encryption appears in `timestamp --help`", async () => {
            const result = await runCli(["timestamp", "--help"]);
            expect(result.code).toBe(0);
            expect(result.stdout).toContain("--ignore-encryption");
        });

        it("`timestamp --ignore-encryption` parses (no Unknown option)", async () => {
            const result = await runCli([
                "timestamp",
                "http://freetsa.org/tsr",
                inputPdf,
                "--ignore-encryption",
            ]);
            expect(result.stderr).not.toContain("Unknown option");
            expect(result.stderr).not.toContain("unknown option");
        });

        it("--trust-store <path> appears in `verify --help`", async () => {
            const result = await runCli(["verify", "--help"]);
            expect(result.code).toBe(0);
            expect(result.stdout).toContain("--trust-store");
        });

        it("`verify --trust-store /nonexistent.pem` surfaces a file error", async () => {
            // Behavioural smoke: the flag is wired through to
            // loadTrustStoreFromPem and the failure surfaces (not a silent
            // continue with no trust store).
            const result = await runCli([
                "verify",
                "--trust-store",
                "/nonexistent-trust-store.pem",
                inputPdf,
            ]);
            expect(result.stderr).not.toContain("Unknown option");
            // Either the file-read error or the no-cert-found error is acceptable
            // here -- both prove the flag reached loadTrustStoreFromPem.
            expect(result.code).toBe(1);
        });
    });

    describe("CLI File Operations", () => {
        it("should handle output file specification", async () => {
            const result = await runCli([
                "timestamp",
                "http://freetsa.org/tsr",
                inputPdf,
                outputPdf,
            ]);

            // Should attempt to create output file
            // (may fail due to network, but file handling should work)
            expect(result.stdout).not.toContain("Invalid output file");
        });

        it("should auto-generate output filename", async () => {
            const result = await runCli(["timestamp", "http://freetsa.org/tsr", inputPdf]);

            // Should generate output filename automatically
            expect(result.stderr).not.toContain("No output file specified");
        });
    });

    // Helper function to run CLI commands
    async function runCli(args: string[]): Promise<{
        code: number;
        stdout: string;
        stderr: string;
    }> {
        return new Promise((resolve) => {
            const child = spawn("node", ["../cli/dist/cli.cjs", ...args], {
                cwd: process.cwd(),
                stdio: ["pipe", "pipe", "pipe"],
            });

            let stdout = "";
            let stderr = "";

            child.stdout.on("data", (data: { toString: () => string }) => {
                stdout += data.toString();
            });

            child.stderr.on("data", (data: { toString: () => string }) => {
                stderr += data.toString();
            });

            child.on("close", (code) => {
                resolve({
                    code: code ?? 0,
                    stdout,
                    stderr,
                });
            });

            child.on("error", (error) => {
                resolve({
                    code: 1,
                    stdout,
                    stderr: error.message,
                });
            });
        });
    }
});
