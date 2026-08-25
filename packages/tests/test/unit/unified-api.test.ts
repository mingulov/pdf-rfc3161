import { readFileSync } from "node:fs";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { TimestampResponseValidationOptions } from "../../../core/src/index.js";
import { TSAStatus, type TimestampOptions, type TimestampResult } from "../../../core/src/types.js";

const state = vi.hoisted(() => ({
    createRequest: vi.fn(async () => new Uint8Array([0x30, 0x00])),
    embed: vi.fn(async () => new Uint8Array([0x25, 0x50, 0x44, 0x46])),
    send: vi.fn(async () => new Uint8Array([0x30, 0x03, 0x30, 0x01, 0x00])),
    parse: vi.fn(() => ({
        status: TSAStatus.GRANTED,
        token: new Uint8Array([1, 2, 3]),
        info: {
            genTime: new Date("2026-08-24T00:00:00Z"),
            policy: "1.2.3.4.5",
            serialNumber: "1",
            hashAlgorithm: "SHA-256",
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            messageDigest: "00",
            hasCertificate: true,
        },
    })),
}));

vi.mock("../../../core/src/session.js", () => {
    class FakeSession {
        async createTimestampRequest(options: unknown): Promise<Uint8Array> {
            return state.createRequest(options);
        }

        async embedTimestampToken(response: Uint8Array): Promise<Uint8Array> {
            return state.embed(response);
        }

        static calculateOptimalSize(_token: Uint8Array): number {
            return 8192;
        }
    }
    return { TimestampSession: FakeSession };
});

vi.mock("../../../core/src/tsa/index.js", async (importOriginal) => {
    const original = await importOriginal<typeof import("../../../core/src/tsa/index.js")>();
    return {
        ...original,
        sendTimestampRequest: state.send,
        parseTimestampResponse: state.parse,
    };
});

const { timestampPdf } = await import("../../../core/src/index.js");

describe("Unified API Tests", () => {
    beforeEach(() => {
        state.createRequest.mockClear();
        state.embed.mockClear();
        state.send.mockClear();
        state.parse.mockClear();
    });

    it("passes the complete response through the session gate with effective request context", async () => {
        const result = await timestampPdf({
            pdf: new Uint8Array([0x25, 0x50, 0x44, 0x46]),
            tsa: {
                url: "http://timestamp.mock.test",
                hashAlgorithm: "SHA-384",
                policy: "1.2.3.4.5",
            },
            enableLTV: false,
            rejectOnRevocationWarning: false,
        });

        expect(state.createRequest).toHaveBeenCalledWith({
            hashAlgorithm: "SHA-384",
            policy: "1.2.3.4.5",
            requestCertificate: true,
        });
        expect(state.embed).toHaveBeenCalledWith(new Uint8Array([0x30, 0x03, 0x30, 0x01, 0x00]));
        expect(result.timestamp.policy).toBe("1.2.3.4.5");
        expect("tsaRevocationWarning" in result).toBe(false);
    });

    it("keeps the LTV result field in the public result type", async () => {
        type ResultCheck = Awaited<ReturnType<typeof timestampPdf>>;
        const hasLtvData: keyof ResultCheck = "ltvData";
        expect(hasLtvData).toBe("ltvData");
    });

    it("exports manual timestamp-response validation options from the root API", () => {
        const validationOptions: TimestampResponseValidationOptions = {
            signerCertificates: [new Uint8Array([0x30, 0x00])],
        };

        expect(validationOptions.signerCertificates?.[0]).toEqual(new Uint8Array([0x30, 0x00]));
    });

    it("rejects one-call certReq=false before sending a network request or embedding", async () => {
        await expect(
            timestampPdf({
                pdf: new Uint8Array([0x25, 0x50, 0x44, 0x46]),
                tsa: { url: "http://timestamp.mock.test", requestCertificate: false },
            })
        ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });

        expect(state.send).not.toHaveBeenCalled();
        expect(state.embed).not.toHaveBeenCalled();
    });

    it("retains intentionally deprecated public option and result fields", () => {
        const legacyOptions: TimestampOptions = {
            pdf: new Uint8Array([0x25, 0x50, 0x44, 0x46]),
            tsa: { url: "http://timestamp.mock.test" },
            rejectOnRevocationWarning: false,
        };
        const legacyResult: TimestampResult = {
            pdf: new Uint8Array([0x25, 0x50, 0x44, 0x46]),
            timestamp: state.parse().info,
            tsaRevocationWarning: undefined,
        };

        expect(legacyOptions.rejectOnRevocationWarning).toBe(false);
        expect(legacyResult.tsaRevocationWarning).toBeUndefined();
    });

    it("documents request-binding failures with the public verification error code", () => {
        const indexSource = readFileSync(
            new URL("../../../core/src/index.ts", import.meta.url),
            "utf8"
        );
        const timestampPdfDocs = indexSource.slice(
            indexSource.indexOf("/**\n * Adds an RFC 3161 trusted timestamp"),
            indexSource.indexOf("export async function timestampPdf")
        );

        expect(timestampPdfDocs).toContain("`VERIFICATION_FAILED` if the TSA response");
        expect(timestampPdfDocs).not.toContain("`INVALID_RESPONSE` if the TSA response");
    });

    it("keeps the status 4/5 and raw-embed migration guidance current", () => {
        const readRootFile = (name: string): string =>
            readFileSync(new URL("../../../../" + name, import.meta.url), "utf8");
        const migration = readRootFile("MIGRATION.md");
        const readme = readRootFile("README.md");
        const changelog = readRootFile("CHANGELOG.md");
        const cliSource = readFileSync(new URL("../../../cli/src/cli.ts", import.meta.url), "utf8");

        expect(migration).not.toMatch(/^\+\s+.*embedTimestampToken/m);
        expect(migration).toContain("TimestampSession.embedTimestampToken");
        expect(readme).toContain("TSA statuses 4/5 are always fatal");
        expect(changelog).toContain("TSA statuses 4/5 are always fatal");
        expect(cliSource).toContain("Deprecated no-op: TSA statuses 4/5 are always fatal");
    });
});
