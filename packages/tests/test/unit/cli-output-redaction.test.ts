import { beforeEach, describe, expect, it, vi } from "vitest";

const originalCliTestMode = process.env.CLI_TEST_MODE;
process.env.CLI_TEST_MODE = "true";

vi.mock("../../../core/src/index.js", () => ({
    timestampPdf: vi.fn(),
    archiveTimestamp: vi.fn(),
    extractTimestamps: vi.fn(),
    verifyTimestamp: vi.fn(),
    verifyPdfTimestamps: vi.fn(),
    validateTimestampTokenRFC8933Compliance: vi.fn(),
    KNOWN_TSA_URLS: {},
    setLogger: vi.fn(),
}));

vi.mock("node:fs/promises", () => ({
    readFile: vi.fn(),
    writeFile: vi.fn(),
}));

const { program } = await import("../../../cli/src/cli");
const { timestampPdf, archiveTimestamp } = await import("../../../core/src/index.js");
const { readFile, writeFile } = await import("node:fs/promises");

const SECRET_TSA_URL = "https://user:pass@tsa.example.test/ts?token=MARKER";

function timestampResult() {
    return {
        pdf: Uint8Array.of(0x25, 0x50, 0x44, 0x46),
        timestamp: {
            genTime: new Date("2024-01-01T00:00:00Z"),
            policy: "1.2.3.4.5",
            serialNumber: "12345",
            hashAlgorithm: "SHA-256",
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            messageDigest: "00",
            hasCertificate: true,
        },
    };
}

describe("CLI verbose TSA output redaction (T12 log audit)", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.mocked(readFile).mockResolvedValue(Buffer.from([0x25, 0x50, 0x44, 0x46]));
        vi.mocked(writeFile).mockResolvedValue(undefined);
        vi.mocked(timestampPdf).mockResolvedValue(timestampResult());
        vi.mocked(archiveTimestamp).mockResolvedValue(timestampResult());
    });

    it("redacts credentials and query data from the timestamp TSA line", async () => {
        const output: string[] = [];
        const log = vi.spyOn(console, "log").mockImplementation((message?: unknown) => {
            output.push(String(message));
        });

        try {
            await program.parseAsync(
                ["node", "pdf-rfc3161", "timestamp", SECRET_TSA_URL, "input.pdf", "-v"],
                { from: "node" }
            );

            const joined = output.join("\n");
            expect(joined).toContain("https://tsa.example.test/ts");
            expect(joined).not.toContain("MARKER");
            expect(joined).not.toContain("user:pass@");
        } finally {
            log.mockRestore();
        }
    });

    it("redacts credentials and query data from the archive TSA line", async () => {
        const output: string[] = [];
        const log = vi.spyOn(console, "log").mockImplementation((message?: unknown) => {
            output.push(String(message));
        });

        try {
            await program.parseAsync(
                ["node", "pdf-rfc3161", "archive", SECRET_TSA_URL, "input.pdf", "-v"],
                { from: "node" }
            );

            const joined = output.join("\n");
            expect(joined).toContain("https://tsa.example.test/ts");
            expect(joined).not.toContain("MARKER");
            expect(joined).not.toContain("user:pass@");
        } finally {
            log.mockRestore();
        }
    });
});

process.env.CLI_TEST_MODE = originalCliTestMode;
