import { describe, expect, it } from "vitest";
import {
    PDFArray,
    decodePDFRawStream,
    PDFDict,
    PDFDocument,
    PDFName,
    PDFRawStream,
    PDFRef,
} from "pdf-lib-incremental-save";
import { addDSS } from "../../../core/src/pdf/ltv.js";
import { restoreLargestObjectNumber } from "../../../core/src/pdf/internals.js";

interface DssFixtureOptions {
    indirectDss: boolean;
    indirectArrays: boolean;
}

async function createDssFixture(options: DssFixtureOptions): Promise<Uint8Array> {
    const pdfDoc = await PDFDocument.create();
    pdfDoc.addPage([100, 100]);
    const pdfBytes = await pdfDoc.save();

    const loadedPdf = await PDFDocument.load(pdfBytes, { updateMetadata: false });
    const snapshot = loadedPdf.takeSnapshot();
    const context = loadedPdf.context;
    restoreLargestObjectNumber(pdfBytes, context);

    const certificate = context.register(
        PDFRawStream.of(PDFDict.withContext(context), Uint8Array.of(0x30, 0x01))
    );
    const crl = context.register(
        PDFRawStream.of(PDFDict.withContext(context), Uint8Array.of(0x30, 0x02))
    );
    const certs = PDFArray.withContext(context);
    certs.push(certificate);
    const crls = PDFArray.withContext(context);
    crls.push(crl);

    const vri = context.obj({
        ExistingVRI: context.obj({ Type: PDFName.of("VRI"), VendorData: PDFName.of("Preserved") }),
    });
    const vendorData = context.obj({ ExistingVendorData: PDFName.of("Preserved") });
    const dss = context.obj({
        Type: PDFName.of("VendorDSS"),
        Certs: options.indirectArrays ? context.register(certs) : certs,
        CRLs: options.indirectArrays ? context.register(crls) : crls,
        VRI: vri,
        VendorData: vendorData,
    });
    const dssValue = options.indirectDss ? context.register(dss) : dss;
    loadedPdf.catalog.set(PDFName.of("DSS"), dssValue);

    snapshot.markRefForSave(certificate);
    snapshot.markRefForSave(crl);
    if (options.indirectArrays) {
        const certsRef = dss.get(PDFName.of("Certs"));
        const crlsRef = dss.get(PDFName.of("CRLs"));
        if (certsRef instanceof PDFRef) {
            snapshot.markRefForSave(certsRef);
        }
        if (crlsRef instanceof PDFRef) {
            snapshot.markRefForSave(crlsRef);
        }
    }
    if (dssValue instanceof PDFRef) {
        snapshot.markRefForSave(dssValue);
    }
    const catalogRef = context.trailerInfo.Root;
    if (catalogRef instanceof PDFRef) {
        snapshot.markRefForSave(catalogRef);
    }

    // Mirror production mutations: the stream writer invents unchecked ObjStm
    // and XRef references, so fixtures must use the checked classic writer too.
    context.pdfFileDetails.useObjectStreams = false;
    const incrementalBytes = await loadedPdf.saveIncremental(snapshot);
    const finalBytes = new Uint8Array(pdfBytes.length + incrementalBytes.length);
    finalBytes.set(pdfBytes, 0);
    finalBytes.set(incrementalBytes, pdfBytes.length);
    return finalBytes;
}

async function readDss(pdfBytes: Uint8Array): Promise<PDFDict> {
    const pdfDoc = await PDFDocument.load(pdfBytes, { updateMetadata: false });
    const dss = pdfDoc.catalog.lookup(PDFName.of("DSS"));
    expect(dss).toBeInstanceOf(PDFDict);
    if (!(dss instanceof PDFDict)) {
        throw new Error("DSS dictionary is missing");
    }
    return dss;
}

async function readDssBytes(pdfBytes: Uint8Array, key: string): Promise<Uint8Array[]> {
    const streams = await readDssStreams(pdfBytes, key);
    return streams.map((stream) => stream.getContents());
}

async function readDssStreams(pdfBytes: Uint8Array, key: string): Promise<PDFRawStream[]> {
    const dss = await readDss(pdfBytes);
    const entries = dss.lookup(PDFName.of(key));
    expect(entries).toBeInstanceOf(PDFArray);
    if (!(entries instanceof PDFArray)) {
        return [];
    }

    const streams: PDFRawStream[] = [];
    for (let index = 0; index < entries.size(); index++) {
        const stream = entries.lookup(index);
        expect(stream).toBeInstanceOf(PDFRawStream);
        if (stream instanceof PDFRawStream) {
            streams.push(stream);
        }
    }
    return streams;
}

async function createFilteredDssPdf(): Promise<Uint8Array> {
    const pdfDoc = await PDFDocument.create();
    pdfDoc.addPage([100, 100]);
    const pdfBytes = await pdfDoc.save();

    const loadedPdf = await PDFDocument.load(pdfBytes, { updateMetadata: false });
    const snapshot = loadedPdf.takeSnapshot();
    const context = loadedPdf.context;
    restoreLargestObjectNumber(pdfBytes, context);
    const filteredCertificate = context.register(context.flateStream(Uint8Array.of(0x30, 0x06)));
    const certs = PDFArray.withContext(context);
    certs.push(filteredCertificate);
    const dss = context.obj({ Certs: certs });
    const dssRef = context.register(dss);
    loadedPdf.catalog.set(PDFName.of("DSS"), dssRef);

    snapshot.markRefForSave(filteredCertificate);
    snapshot.markRefForSave(dssRef);
    const catalogRef = context.trailerInfo.Root;
    if (catalogRef instanceof PDFRef) {
        snapshot.markRefForSave(catalogRef);
    }

    context.pdfFileDetails.useObjectStreams = false;
    const incrementalBytes = await loadedPdf.saveIncremental(snapshot);
    const finalBytes = new Uint8Array(pdfBytes.length + incrementalBytes.length);
    finalBytes.set(pdfBytes, 0);
    finalBytes.set(incrementalBytes, pdfBytes.length);
    return finalBytes;
}

describe("validation store updates", () => {
    it.each([
        { name: "direct DSS", indirectDss: false, indirectArrays: false },
        { name: "indirect DSS and arrays", indirectDss: true, indirectArrays: true },
    ])(
        "preserves existing $name entries while appending validation material",
        async (fixture: DssFixtureOptions) => {
            const pdf = await createDssFixture(fixture);

            const updated = await addDSS(pdf, {
                certificates: [Uint8Array.of(0x30, 0x01), Uint8Array.of(0x30, 0x03)],
                crls: [Uint8Array.of(0x30, 0x04)],
                ocspResponses: [Uint8Array.of(0x30, 0x05)],
            });
            const dss = await readDss(updated);

            expect(updated.slice(0, pdf.length)).toEqual(pdf);
            expect(await readDssBytes(updated, "Certs")).toEqual([
                Uint8Array.of(0x30, 0x01),
                Uint8Array.of(0x30, 0x03),
            ]);
            expect(await readDssBytes(updated, "CRLs")).toEqual([
                Uint8Array.of(0x30, 0x02),
                Uint8Array.of(0x30, 0x04),
            ]);
            expect(await readDssBytes(updated, "OCSPs")).toEqual([Uint8Array.of(0x30, 0x05)]);
            expect(dss.get(PDFName.of("Type"))).toEqual(PDFName.of("VendorDSS"));

            const vri = dss.lookup(PDFName.of("VRI"));
            expect(vri).toBeInstanceOf(PDFDict);
            if (vri instanceof PDFDict) {
                const existingVri = vri.lookup(PDFName.of("ExistingVRI"));
                expect(existingVri).toBeInstanceOf(PDFDict);
                if (existingVri instanceof PDFDict) {
                    expect(existingVri.get(PDFName.of("Type"))).toEqual(PDFName.of("VRI"));
                    expect(existingVri.get(PDFName.of("VendorData"))).toEqual(
                        PDFName.of("Preserved")
                    );
                }
            }
            const vendorData = dss.lookup(PDFName.of("VendorData"));
            expect(vendorData).toBeInstanceOf(PDFDict);
            if (vendorData instanceof PDFDict) {
                expect(vendorData.get(PDFName.of("ExistingVendorData"))).toEqual(
                    PDFName.of("Preserved")
                );
            }
        }
    );

    it("deduplicates repeated validation material in a second DSS update", async () => {
        const pdfDoc = await PDFDocument.create();
        pdfDoc.addPage([100, 100]);
        const pdf = await pdfDoc.save();
        const validationData = {
            certificates: [Uint8Array.of(0x30, 0x01)],
            crls: [],
            ocspResponses: [],
        };

        const first = await addDSS(pdf, validationData);
        const second = await addDSS(first, validationData);

        expect(second.slice(0, first.length)).toEqual(first);
        expect(await readDssBytes(second, "Certs")).toEqual([Uint8Array.of(0x30, 0x01)]);
    });

    it("deduplicates validation material against an existing filtered stream", async () => {
        const pdf = await createFilteredDssPdf();

        const updated = await addDSS(pdf, {
            certificates: [Uint8Array.of(0x30, 0x06)],
            crls: [],
            ocspResponses: [],
        });
        const streams = await readDssStreams(updated, "Certs");

        expect(updated.slice(0, pdf.length)).toEqual(pdf);
        expect(streams).toHaveLength(1);
        const stream = streams[0];
        expect(stream).toBeDefined();
        if (stream) {
            expect(decodePDFRawStream(stream).decode()).toEqual(Uint8Array.of(0x30, 0x06));
        }
    });
});
