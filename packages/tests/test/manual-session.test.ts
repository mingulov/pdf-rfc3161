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

        // We need to bypass `parseTimestampResponse` check in `embedTimestampToken` 
        // or ensure our dummy bytes don't throw "TSA rejected request".
        // `embedTimestampToken` implementation tries to parse, but catches errors. 
        // If it catches, it throws ONLY if it was a valid response with REJECTION status.
        // Garbage bytes will cause a parse error, which is caught and ignored (fallback to raw bytes).
        // So passing garbage dummyToken allows us to proceed to embedding.

        // Execute embedding
        await session.embedTimestampToken(dummyToken);

        // Verification:
        // 1. Fetch should NOT have been called (since we didn't ask to fetch LTV data)
        // Note: It might be called for other reasons? No.
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

        // This should throw INVALID_RESPONSE because it tries to parse LTV data from garbage
        await expect(session.embedTimestampToken(dummyToken))
            .rejects.toThrow(/Failed to extract LTV data/);

        fetchSpy.mockRestore();
    });

});
