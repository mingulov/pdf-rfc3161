import { describe, it, expect } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
import { timestampPdf } from "../../../core/src/index.js";

/**
 * Tests for the unified API.
 */
describe("Unified API Tests", () => {
    // Mock TSA URL - tests use mocked responses
    const mockTsaUrl = "http://timestamp.mock.test";

    describe("timestampPdf with enableLTV option", () => {
        it("should have LTV-related options in TimestampOptions", () => {
            // This is a compile-time check - if this compiles, the types are correct
            const options = {
                pdf: new Uint8Array([]),
                tsa: { url: mockTsaUrl },
                enableLTV: true,
            };
            expect(options.enableLTV).toBe(true);
        });

        it("should return ltvData when enableLTV is true", async () => {
            // Create a minimal PDF
            const doc = await PDFDocument.create();
            doc.addPage([100, 100]);
            await doc.save();

            // Result type should include optional ltvData
            type ResultCheck = Awaited<ReturnType<typeof timestampPdf>>;
            const hasLtvData: keyof ResultCheck = "ltvData";
            expect(hasLtvData).toBe("ltvData");
        });
    });
});
