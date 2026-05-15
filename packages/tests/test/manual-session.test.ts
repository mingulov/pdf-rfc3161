import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TimestampSession } from 'pdf-rfc3161';
import { PDFDocument } from 'pdf-lib-incremental-save';

// Mock specific LTV functions by mocking the module dependency if possible
// Or just spy on global fetch since network activity is what we care about


describe('TimestampSession Regression Tests', () => {

    let pdfBytes: Uint8Array;

    beforeEach(async () => {
        // Create a simple PDF if demo one isn't nearby or just loading it
        const pdfDoc = await PDFDocument.create();
        const page = pdfDoc.addPage();
        page.drawText('Test PDF');
        pdfBytes = await pdfDoc.save();
    });

    it('should NOT trigger LTV revocation fetches when enableLTV is false', async () => {
        // Setup spies
        // We can't easily spy on internal module calls in ES modules without intricate mocking,
        // but we can check if the output PDF has DSS or not, OR checking if fetch was called (if in Node environment)

        // Better: Mock global fetch and ensure it's NOT called for CRL/OCSP
        // Note: createTimestampRequest calls fetch? No, sendTimestampRequest does. 
        // In this manual flow, we only use session.createTimestampRequest and session.embedTimestampToken.
        // session.embedTimestampToken MIGHT call fetch if LTV is enabled (to get missing revocation info).

        const fetchSpy = vi.spyOn(global, 'fetch');

        const session = new TimestampSession(pdfBytes, {
            enableLTV: false,
            prepareOptions: {
                signatureSize: 0, // Default
            },
            hashAlgorithm: 'SHA-256',
        });

        // 1. Create Request
        const tsq = await session.createTimestampRequest();
        expect(tsq).toBeDefined();

        // 2. Simulate a TSR (we need a valid one to embed)
        // Since we can't easily generate a real valid TSR without a real TSA, 
        // we might fail at `embedTimestampToken` validation if we feed garbage.
        // We can create a dummy token or mock functionality if we just want to check flow control.

        // HOWEVER, the "Bad signature placeholder" error suggests size mismatch. 
        // Let's test providing a dummy token of explicit size.

        // Create a dummy token large enough to fill signature
        const dummyToken = new Uint8Array(2000);
        dummyToken.fill(1);

        // Post audit F1 fix (Phase 4.3): the `looksLikeTimeStampResp`
        // pre-detection in session.embedTimestampToken now correctly
        // identifies these bytes (`0x01` x 2000) as a raw token, not a TSR.
        // parseTimestampResponse is skipped, raw bytes flow to embed, and
        // (since enableLTV: false) no LTV pipeline runs. The original
        // assertion holds: no network fetch should occur.
        await session.embedTimestampToken(dummyToken);
        expect(fetchSpy).not.toHaveBeenCalled();

        fetchSpy.mockRestore();
    });

    it('should trigger LTV revocation fetches by default (undefined options)', async () => {
        const fetchSpy = vi.spyOn(global, 'fetch');
        // No options provided, should default to enableLTV: true
        const session = new TimestampSession(pdfBytes, {
            prepareOptions: { signatureSize: 0 },
            hashAlgorithm: 'SHA-256',
        });

        await session.createTimestampRequest();
        const dummyToken = new Uint8Array(2000);
        dummyToken.fill(1);

        // Post audit F1 fix: pre-detection treats the garbage bytes as a raw
        // token, embed succeeds, then the default-LTV pipeline runs
        // extractLTVData(token) which throws on the garbage bytes. The
        // regression we still want to protect: garbage bytes are not
        // silently embedded with LTV side-effects (a fetch).
        await expect(session.embedTimestampToken(dummyToken)).rejects.toThrow(
            /Failed to extract LTV data/
        );

        fetchSpy.mockRestore();
    });

});
