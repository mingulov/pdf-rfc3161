import { describe, it, expect } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
import { preparePdfForTimestamp } from "../../src/pdf/prepare.js";
import { addDSS } from "../../src/pdf/ltv.js";

describe("Regression Tests - LTV DSS Object Number Collision", () => {
    /**
     * Regression test for the object number collision bug in addDSS.
     *
     * Problem: When addDSS loaded a PDF that had already been timestamped,
     * pdf-lib-incremental-save's largestObjectNumber didn't account for objects
     * created in previous incremental updates. This caused new DSS objects to
     * reuse object numbers (8, 9, 10) that were already used by the timestamp
     * increment, leading to PDF corruption and Acrobat Reader Error 43.
     *
     * Fix: addDSS now scans the entire PDF for object definitions and manually
     * updates largestObjectNumber before registering new objects.
     */
    it("should not create duplicate object numbers when adding DSS to timestamped PDF", async () => {
        // 1. Create base PDF
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        const pdfBytes = await doc.save();

        // 2. Prepare for timestamp (this creates incremental update with objects 5, 6, 7, 8, 9)
        const prepared = await preparePdfForTimestamp(pdfBytes);

        // 3. Simulate LTV data (use minimal valid structure)
        const fakeLTVData = {
            certificates: [
                // Minimal DER certificate structure (just enough to be a valid stream)
                new Uint8Array([0x30, 0x82, 0x01, 0x00]),
                new Uint8Array([0x30, 0x82, 0x01, 0x01]),
            ],
            crls: [],
            ocspResponses: [],
        };

        // 4. Add DSS to the prepared PDF
        const pdfWithDSS = await addDSS(prepared.bytes, fakeLTVData);

        // 5. Parse the PDF to find all object definitions
        const pdfStr = new TextDecoder("latin1").decode(pdfWithDSS);
        const objMatches = [...pdfStr.matchAll(/(\d{1,20})\s+\d{1,20}\s+obj/g)];
        const objNums = objMatches.map((m) => parseInt(m[1] ?? "0", 10));

        // 6. Check for duplicates (excluding object 5 which is intentionally reused in ObjStm)
        const counts = new Map<number, number>();
        for (const num of objNums) {
            counts.set(num, (counts.get(num) ?? 0) + 1);
        }

        // Object 5 is allowed to appear multiple times (ObjStm reuse)
        // But objects 8, 9, 10+ should NOT be duplicated
        const problematicDuplicates: number[] = [];
        for (const [objNum, count] of counts) {
            if (objNum !== 5 && count > 1) {
                problematicDuplicates.push(objNum);
            }
        }

        expect(problematicDuplicates).toEqual([]);
    });

    it("should correctly embed DSS in catalog", async () => {
        // 1. Create and prepare PDF
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        const pdfBytes = await doc.save();

        const prepared = await preparePdfForTimestamp(pdfBytes);

        // 2. Add DSS with test certificates
        const fakeLTVData = {
            certificates: [new Uint8Array([0x30, 0x82, 0x01, 0x00])],
            crls: [],
            ocspResponses: [],
        };

        const pdfWithDSS = await addDSS(prepared.bytes, fakeLTVData);

        // 3. Verify by reloading the PDF (robust check)
        // This ensures the DSS is actually accessible via the PDF structure
        const reloadedDoc = await PDFDocument.load(pdfWithDSS);
        const { PDFName, PDFDict } = await import("pdf-lib-incremental-save");

        expect(reloadedDoc.catalog.has(PDFName.of("DSS"))).toBe(true);

        const dss = reloadedDoc.catalog.lookup(PDFName.of("DSS"));
        let certs;
        if (dss instanceof PDFDict) {
            certs = dss.lookup(PDFName.of("Certs"));
        }

        expect(certs).toBeDefined();
    });
});
