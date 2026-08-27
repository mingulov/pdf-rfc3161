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

vi.mock("../../../core/src/internals.js", () => ({
    getDSSInfo: vi.fn(),
}));

vi.mock("node:fs/promises", () => ({
    readFile: vi.fn(),
    writeFile: vi.fn(),
}));

const { program } = await import("../../../cli/src/cli");
const { getDSSInfo } = await import("../../../core/src/internals.js");
const { extractTimestamps, verifyPdfTimestamps } = await import("../../../core/src/index.js");
const { readFile } = await import("node:fs/promises");

function timestamp(fieldName: string) {
    return {
        fieldName,
        info: {
            genTime: new Date("2024-01-01T00:00:00Z"),
            policy: "1.2.3.4.5",
            serialNumber: fieldName,
            hashAlgorithm: "SHA-256" as const,
            messageDigest: "00",
            hasCertificate: true,
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
        },
        token: Uint8Array.of(0x30, 0x00),
        contentsValueBytes: Uint8Array.of(0x30, 0x00),
        coversWholeDocument: true,
        verified: true,
        byteRange: [0, 1, 2, 3] as [number, number, number, number],
    };
}

describe("CLI verify batch routing", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.mocked(readFile).mockResolvedValue(Buffer.from([0x25, 0x50, 0x44, 0x46]));
        vi.mocked(getDSSInfo).mockResolvedValue(null);
        vi.mocked(extractTimestamps).mockResolvedValue([]);
        vi.mocked(verifyPdfTimestamps).mockResolvedValue([timestamp("First"), timestamp("Second")]);
    });

    it("verifies all timestamp fields through one PDF-level batch call", async () => {
        const output: string[] = [];
        const log = vi.spyOn(console, "log").mockImplementation((message?: unknown) => {
            output.push(String(message));
        });

        try {
            await program.parseAsync(["node", "pdf-rfc3161", "verify", "input.pdf"], {
                from: "node",
            });

            expect(vi.mocked(verifyPdfTimestamps)).toHaveBeenCalledTimes(1);
            expect(output.join("\n")).toContain("Found 2 timestamp(s)");
            expect(output.join("\n")).toContain("Timestamp 1:");
            expect(output.join("\n")).toContain("Timestamp 2:");
        } finally {
            log.mockRestore();
        }
    });

    it("forwards verify --ignore-encryption to DSS inspection and timestamp discovery", async () => {
        const log = vi.spyOn(console, "log").mockImplementation(() => undefined);

        try {
            await program.parseAsync(
                ["node", "pdf-rfc3161", "verify", "input.pdf", "--ignore-encryption"],
                { from: "node" }
            );

            expect(vi.mocked(getDSSInfo)).toHaveBeenCalledWith(expect.any(Uint8Array), {
                ignoreEncryption: true,
            });
            expect(vi.mocked(verifyPdfTimestamps)).toHaveBeenCalledWith(
                expect.any(Uint8Array),
                expect.objectContaining({ ignoreEncryption: true })
            );
        } finally {
            log.mockRestore();
        }
    });
});

process.env.CLI_TEST_MODE = originalCliTestMode;
