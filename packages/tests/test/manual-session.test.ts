import { describe, it, expect, vi, beforeEach } from "vitest";
import { TimestampSession } from "pdf-rfc3161";
import { PDFDocument } from "pdf-lib-incremental-save";
import { getDSSInfo } from "../../core/src/pdf/ltv.js";
import { createRFC3161TokenFixtureFromRequest } from "./fixtures/rfc3161-token.js";

describe("TimestampSession Regression Tests", () => {

    let pdfBytes: Uint8Array;

    beforeEach(async () => {
        // Create a simple PDF if demo one isn't nearby or just loading it
        const pdfDoc = await PDFDocument.create();
        const page = pdfDoc.addPage();
        page.drawText('Test PDF');
        pdfBytes = await pdfDoc.save();
    });

    it("does not trigger LTV network work when enableLTV is false after strict token validation", async () => {
        const fetchSpy = vi.spyOn(global, "fetch");

        const session = new TimestampSession(pdfBytes, {
            enableLTV: false,
            prepareOptions: {
                signatureSize: 0, // Default
            },
            hashAlgorithm: "SHA-256",
        });

        const tsq = await session.createTimestampRequest();
        expect(tsq).toBeDefined();

        const response = await createRFC3161TokenFixtureFromRequest(tsq);
        await session.embedTimestampToken(response.response);
        expect(fetchSpy).not.toHaveBeenCalled();

        fetchSpy.mockRestore();
    });

    it("adds DSS data by default once a valid response passes the mandatory gate", async () => {
        const session = new TimestampSession(pdfBytes, {
            prepareOptions: { signatureSize: 0 },
            hashAlgorithm: "SHA-256",
        });

        const request = await session.createTimestampRequest();
        const response = await createRFC3161TokenFixtureFromRequest(request);
        const pdf = await session.embedTimestampToken(response.response);

        expect(await getDSSInfo(pdf)).toMatchObject({ certs: 1, crls: 0, ocsps: 0 });
    });
});
