import { beforeEach, describe, expect, it, vi } from "vitest";
import {
    PDFArray,
    PDFDict,
    PDFDocument,
    PDFName,
    PDFRawStream,
} from "pdf-lib-incremental-save";

vi.mock("../../../core/src/pdf/extract.js", () => {
    const extractTimestamps = vi.fn();
    const verifyTimestamp = vi.fn();
    return {
        extractTimestamps,
        discoverArchiveTimestamps: vi.fn(async (pdf: Uint8Array, options: unknown) => ({
            timestamps: await extractTimestamps(pdf, options),
            malformedFieldNames: [],
        })),
        verifyTimestamp,
        verifyTimestampsWithSharedIndex: vi.fn(async (timestamps: unknown[], options: unknown) =>
            Promise.all(timestamps.map((timestamp) => verifyTimestamp(timestamp, options)))
        ),
    };
});

vi.mock("../../../core/src/index.js", () => ({
    timestampPdf: vi.fn(),
}));

import { archiveTimestamp } from "../../../core/src/pdf/archive.js";
import { extractTimestamps } from "../../../core/src/pdf/extract.js";
import { timestampPdf } from "../../../core/src/index.js";
import type { TimestampOptions } from "../../../core/src/types.js";

async function createPdfWithExistingDssAndVri(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const certificate = context.register(
        PDFRawStream.of(PDFDict.withContext(context), Uint8Array.of(0x30, 0x01, 0x01))
    );
    const certificates = PDFArray.withContext(context);
    certificates.push(certificate);
    const vri = context.obj({ ExistingSignature: context.obj({ Type: PDFName.of("VRI") }) });
    document.catalog.set(
        PDFName.of("DSS"),
        context.obj({
            Type: PDFName.of("DSS"),
            Certs: certificates,
            VRI: vri,
            VendorData: PDFName.of("Preserved"),
        })
    );
    return document.save({ useObjectStreams: false });
}

function dssVriKeys(pdf: Uint8Array): Promise<string[]> {
    return PDFDocument.load(pdf, { updateMetadata: false }).then((document) => {
        const dss = document.catalog.lookup(PDFName.of("DSS"));
        expect(dss).toBeInstanceOf(PDFDict);
        if (!(dss instanceof PDFDict)) return [];
        const vri = dss.lookup(PDFName.of("VRI"));
        expect(vri).toBeInstanceOf(PDFDict);
        if (!(vri instanceof PDFDict)) return [];
        return [...vri.keys()].map((key) => key.decodeText());
    });
}

describe("archive document-timestamp renewal PDF boundary", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.mocked(extractTimestamps).mockResolvedValue([]);
    });

    it("preserves existing global DSS and VRI data without creating a VRI entry", async () => {
        const input = await createPdfWithExistingDssAndVri();
        let timestampInput: Uint8Array | undefined;
        vi.mocked(timestampPdf).mockImplementation(async (options: TimestampOptions) => {
            timestampInput = options.pdf;
            return {
                pdf: options.pdf,
                timestamp: {
                    genTime: new Date("2024-01-01T00:00:00Z"),
                    policy: "1.2.3.4.5",
                    serialNumber: "01",
                    hashAlgorithm: "SHA-256",
                    hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                    messageDigest: "00",
                    hasCertificate: true,
                },
            };
        });

        await archiveTimestamp({
            pdf: input,
            tsa: { url: "https://tsa.example.test" },
        });

        expect(timestampInput).toBeDefined();
        if (timestampInput === undefined) throw new Error("archive did not invoke timestampPdf");
        expect(timestampInput.slice(0, input.length)).toEqual(input);
        expect(await dssVriKeys(timestampInput)).toEqual(["ExistingSignature"]);

        const reloaded = await PDFDocument.load(timestampInput, { updateMetadata: false });
        const dss = reloaded.catalog.lookup(PDFName.of("DSS"));
        expect(dss).toBeInstanceOf(PDFDict);
        if (!(dss instanceof PDFDict)) return;
        expect(dss.get(PDFName.of("VendorData"))?.toString()).toBe("/Preserved");
        const certs = dss.lookup(PDFName.of("Certs"));
        expect(certs).toBeInstanceOf(PDFArray);
        if (certs instanceof PDFArray) expect(certs.size()).toBe(1);
    });
});
