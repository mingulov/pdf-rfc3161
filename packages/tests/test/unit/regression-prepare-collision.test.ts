import { describe, it, expect } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
import { preparePdfForTimestamp } from "../../../core/src/pdf/prepare.js";

describe("Regression Tests - Prepare PDF Object Collision", () => {
    /**
     * Regression test for object number collision in preparePdfForTimestamp.
     *
     * Problem: When preparing a PDF that contains object streams (ObjStm),
     * pdf-lib-incremental-save incorrectly calculated largestObjectNumber,
     * often thinking it was lower than reality. This caused the new signature
     * dictionary to be assigned an object number that was already in use
     * (e.g., Object 5), effectively overwriting critical document structure.
     *
     * Fix: preparePdfForTimestamp now scans the entire PDF for object definitions
     * and manually updates largestObjectNumber before creating the signature.
     */
    it("should not overwrite existing objects when creating signature placeholder", async () => {
        // 1. Create a base PDF
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        // Add enough content to trigger object streams if possible,
        // or just ensure we have a known object number count.
        // By default pdf-lib might use ObjStm for minimal files.
        const pdfBytes = await doc.save();

        // 2. Prepare for timestamp
        const prepared = await preparePdfForTimestamp(pdfBytes);

        // 3. Analyze objects in the prepared PDF
        const pdfStr = new TextDecoder("latin1").decode(prepared.bytes);

        // Find all object definitions
        const objMatches = [...pdfStr.matchAll(/(\d+)\s+\d+\s+obj/g)];
        const objNums = objMatches.map((m) => parseInt(m[1] ?? "0", 10));

        // Count occurrences of each object number
        const counts = new Map<number, number>();
        for (const num of objNums) {
            counts.set(num, (counts.get(num) ?? 0) + 1);
        }

        // 4. Verify specific behavior:
        // - Object 5 (often the ObjStm in simple pdf-lib docs) should NOT be duplicated/overwritten
        // - The signature dictionary should have a NEW object number

        // Find duplicate object numbers
        const duplicates = [];
        for (const [num, count] of counts) {
            if (count > 1) {
                duplicates.push(num);
            }
        }

        // In a valid incremental update, essentially NO object number should be redefined
        // in a way that conflicts with its original type.
        // Note: '5 0 obj' appearing twice is technically valid in PDF increment
        // (replaces old version), BUT if the old version was an ObjStm and the new
        // one is a Dict, it destroys the objects inside the old ObjStm.

        // We can't strictly say "no duplicates" because standard incremental updates
        // DO duplicate object numbers (to update them).
        // BUT for a NEW signature on a fresh PDF, we shouldn't be updating
        // existing objects (like the catalog or pages) unless we explicitly meant to.
        // We DEFINITELY shouldn't update Object 5 if it's an ObjStm.

        // Let's check if the signature dictionary has a unique object number
        const sigDictMatch = /(\d+)\s+0\s+obj[\s\S]*?\/Type\s*\/Sig/.exec(pdfStr);
        expect(sigDictMatch).toBeDefined();
        if (sigDictMatch) {
            const sigObjNum = parseInt(sigDictMatch[1] ?? "0", 10);

            // Check if this object number existed in the original PDF
            // We can approximate "original PDF" by looking at the first half of the file
            // or just checking if there are multiple definitions of this object number
            const occurrences = counts.get(sigObjNum);

            // If the signature object number appears more than once, it means we
            // overwrote an existing object. This is BAD for a new signature
            // (it should be a fresh object).
            expect(occurrences).toBe(1);
        }
    });

    it("should produce a valid PDF structure according to simple analysis", async () => {
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        const pdfBytes = await doc.save();

        const prepared = await preparePdfForTimestamp(pdfBytes);
        const pdfStr = new TextDecoder("latin1").decode(prepared.bytes);

        // Check that we have a clean incremental update structure
        // Should have %%EOF at least twice (original + update)
        const eofCount = (pdfStr.match(/%%EOF/g) ?? []).length;
        expect(eofCount).toBeGreaterThanOrEqual(2);

        // Should have a new trailer/xref
        // (This is implicitly tested by generic PDF validity, but good to check)
    });
});
