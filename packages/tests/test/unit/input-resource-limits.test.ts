import { beforeEach, describe, expect, it, vi } from "vitest";
import { MAX_PDF_SIZE, MAX_SIGNATURE_SIZE } from "../../../core/src/constants.js";
import { timestampPdf } from "../../../core/src/index.js";
import { archiveTimestamp } from "../../../core/src/pdf/archive.js";
import { extractTimestamps } from "../../../core/src/pdf/extract.js";
import { preparePdfForTimestamp } from "../../../core/src/pdf/prepare.js";
import { TimestampSession } from "../../../core/src/session.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";

const send = vi.hoisted(() =>
    vi.fn(async (): Promise<Uint8Array> => {
        throw new TimestampError(TimestampErrorCode.NETWORK_ERROR, "mock TSA is unreachable");
    })
);

vi.mock("../../../core/src/tsa/index.js", async (importOriginal: <T = unknown>() => Promise<T>) => {
    const original = await importOriginal<typeof import("../../../core/src/tsa/index.js")>();
    return { ...original, sendTimestampRequest: send };
});

function minimalPdf(): Uint8Array {
    return new TextEncoder().encode(`%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>
endobj
xref
0 4
0000000000 65535 f${" "}
0000000009 00000 n${" "}
0000000058 00000 n${" "}
0000000115 00000 n${" "}
trailer
<< /Size 4 /Root 1 0 R >>
startxref
203
%%EOF`);
}

const INVALID_SIZES: [string, number][] = [
    ["negative", -1],
    ["fractional", 100.5],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["-Infinity", Number.NEGATIVE_INFINITY],
    ["limit + 1", MAX_SIGNATURE_SIZE + 1],
    ["huge", 2 ** 31],
    ["unsafe integer", Number.MAX_SAFE_INTEGER + 1],
];

const INVALID_MAX_SIZES: [string, number][] = [
    ["zero", 0],
    ["negative", -100],
    ["fractional", 100.5],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["above ceiling", MAX_PDF_SIZE + 1],
];

const TSA = { url: "https://tsa.invalid", retry: 0 };

function expectSyncCode(fn: () => unknown, code: TimestampErrorCode, messagePart?: string): void {
    try {
        fn();
    } catch (error) {
        expect(error).toBeInstanceOf(TimestampError);
        expect((error as TimestampError).code).toBe(code);
        if (messagePart !== undefined) {
            expect((error as TimestampError).message).toContain(messagePart);
        }
        return;
    }
    expect.unreachable(`expected TimestampError(${code})`);
}

describe("input resource limits (S3)", () => {
    beforeEach(() => {
        send.mockClear();
    });

    describe("preparePdfForTimestamp signatureSize", () => {
        it.each(INVALID_SIZES)(
            "rejects %s signatureSize with INVALID_ARGUMENT before PDF parsing",
            async (_label: string, signatureSize: number) => {
                await expect(
                    preparePdfForTimestamp(new Uint8Array([1, 2, 3]), { signatureSize })
                ).rejects.toMatchObject({ code: TimestampErrorCode.INVALID_ARGUMENT });
            }
        );

        it("rejects an over-cap reservation for a valid PDF without allocating it", async () => {
            await expect(
                preparePdfForTimestamp(minimalPdf(), { signatureSize: MAX_SIGNATURE_SIZE + 1 })
            ).rejects.toMatchObject({ code: TimestampErrorCode.INVALID_ARGUMENT });
        });

        it("preserves omitted and zero auto sizing", async () => {
            const omitted = await preparePdfForTimestamp(minimalPdf());
            expect(omitted.contentsPlaceholderLength).toBe(8192 * 2);
            const zero = await preparePdfForTimestamp(minimalPdf(), { signatureSize: 0 });
            expect(zero.contentsPlaceholderLength).toBe(8192 * 2);
        });

        it("accepts a reservation of exactly the 65,536-byte limit", async () => {
            const prepared = await preparePdfForTimestamp(minimalPdf(), {
                signatureSize: MAX_SIGNATURE_SIZE,
            });
            expect(prepared.contentsPlaceholderLength).toBe(MAX_SIGNATURE_SIZE * 2);
        });
    });

    describe("preparePdfForTimestamp PDF ceiling", () => {
        it("rejects a PDF larger than the 250 MiB ceiling before parsing it", async () => {
            await expect(
                preparePdfForTimestamp(new Uint8Array(MAX_PDF_SIZE + 1))
            ).rejects.toMatchObject({
                code: TimestampErrorCode.PDF_ERROR,
                message: expect.stringContaining("maximum supported size"),
            });
        });
    });

    describe("timestampPdf maxSize", () => {
        it.each(INVALID_MAX_SIZES)(
            "rejects %s maxSize with INVALID_ARGUMENT before any TSA request",
            async (_label: string, maxSize: number) => {
                await expect(
                    timestampPdf({ pdf: minimalPdf(), tsa: TSA, maxSize })
                ).rejects.toMatchObject({ code: TimestampErrorCode.INVALID_ARGUMENT });
                expect(send).not.toHaveBeenCalled();
            }
        );

        it("accepts maxSize of exactly the 250 MiB ceiling", async () => {
            await expect(
                timestampPdf({ pdf: minimalPdf(), tsa: TSA, maxSize: MAX_PDF_SIZE })
            ).rejects.toMatchObject({ code: TimestampErrorCode.NETWORK_ERROR });
            expect(send).toHaveBeenCalled();
        });
    });

    describe("TimestampSession entry limits", () => {
        it.each(INVALID_MAX_SIZES)(
            "rejects %s session maxSize with INVALID_ARGUMENT",
            (_label: string, maxSize: number) => {
                expectSyncCode(
                    () => new TimestampSession(minimalPdf(), { maxSize }),
                    TimestampErrorCode.INVALID_ARGUMENT
                );
            }
        );

        it("rejects an over-maxSize PDF in the constructor before preparation", () => {
            expectSyncCode(
                () => new TimestampSession(minimalPdf(), { maxSize: 64 }),
                TimestampErrorCode.PDF_ERROR,
                "maximum supported size"
            );
        });

        it("rejects a PDF larger than the default 250 MiB ceiling", () => {
            expectSyncCode(
                () => new TimestampSession(new Uint8Array(MAX_PDF_SIZE + 1)),
                TimestampErrorCode.PDF_ERROR
            );
        });

        it.each(INVALID_SIZES)(
            "rejects %s prepareOptions.signatureSize in the constructor",
            (_label: string, signatureSize: number) => {
                expectSyncCode(
                    () => new TimestampSession(minimalPdf(), { prepareOptions: { signatureSize } }),
                    TimestampErrorCode.INVALID_ARGUMENT
                );
            }
        );

        it("preserves omitted and zero session signatureSize auto behavior", () => {
            expect(new TimestampSession(minimalPdf(), { enableLTV: false }).signatureSize).toBe(
                8192
            );
            expect(
                new TimestampSession(minimalPdf(), {
                    enableLTV: false,
                    prepareOptions: { signatureSize: 0 },
                }).signatureSize
            ).toBe(8192);
        });
    });

    describe("extractTimestamps entry limits", () => {
        it.each(INVALID_MAX_SIZES)(
            "rejects %s maxSize with INVALID_ARGUMENT before PDF parsing",
            async (_label: string, maxSize: number) => {
                await expect(
                    extractTimestamps(new Uint8Array([1, 2, 3]), { maxSize })
                ).rejects.toMatchObject({ code: TimestampErrorCode.INVALID_ARGUMENT });
            }
        );

        it("rejects an over-maxSize PDF with PDF_ERROR before parsing", async () => {
            await expect(extractTimestamps(minimalPdf(), { maxSize: 64 })).rejects.toMatchObject({
                code: TimestampErrorCode.PDF_ERROR,
                message: expect.stringContaining("maximum supported size"),
            });
        });

        it("rejects a PDF larger than the default 250 MiB ceiling without parsing it", async () => {
            await expect(extractTimestamps(new Uint8Array(MAX_PDF_SIZE + 1))).rejects.toMatchObject(
                {
                    code: TimestampErrorCode.PDF_ERROR,
                    message: expect.stringContaining("maximum supported size"),
                }
            );
        });
    });

    describe("archiveTimestamp entry limits", () => {
        it.each(INVALID_MAX_SIZES)(
            "rejects %s maxSize with INVALID_ARGUMENT before discovery",
            async (_label: string, maxSize: number) => {
                await expect(
                    archiveTimestamp({ pdf: minimalPdf(), tsa: TSA, maxSize })
                ).rejects.toMatchObject({ code: TimestampErrorCode.INVALID_ARGUMENT });
                expect(send).not.toHaveBeenCalled();
            }
        );

        it("rejects an over-maxSize PDF with PDF_ERROR before discovery", async () => {
            const oversizedGarbage = new Uint8Array(128).fill(0x41);
            await expect(
                archiveTimestamp({ pdf: oversizedGarbage, tsa: TSA, maxSize: 64 })
            ).rejects.toMatchObject({
                code: TimestampErrorCode.PDF_ERROR,
                message: expect.stringContaining("maximum supported size"),
            });
            expect(send).not.toHaveBeenCalled();
        });

        it("rejects a PDF larger than the default 250 MiB ceiling without discovery", async () => {
            await expect(
                archiveTimestamp({ pdf: new Uint8Array(MAX_PDF_SIZE + 1), tsa: TSA })
            ).rejects.toMatchObject({
                code: TimestampErrorCode.PDF_ERROR,
                message: expect.stringContaining("maximum supported size"),
            });
            expect(send).not.toHaveBeenCalled();
        });

        it.each([
            ["NaN", Number.NaN],
            ["negative", -1],
            ["limit + 1", MAX_SIGNATURE_SIZE + 1],
        ])(
            "rejects %s signatureSize with INVALID_ARGUMENT before discovery",
            async (_label: string, signatureSize: number) => {
                await expect(
                    archiveTimestamp({ pdf: new Uint8Array([1, 2, 3]), tsa: TSA, signatureSize })
                ).rejects.toMatchObject({ code: TimestampErrorCode.INVALID_ARGUMENT });
                expect(send).not.toHaveBeenCalled();
            }
        );
    });
});
