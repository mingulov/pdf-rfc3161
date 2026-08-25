import { describe, expect, it } from "vitest";
import { embedTimestampToken, extractBytesToHash } from "../../../core/src/pdf/embed.js";
import { extractTimestamps, verifyTimestamp } from "../../../core/src/pdf/extract.js";
import { preparePdfForTimestamp } from "../../../core/src/pdf/prepare.js";
import { TimestampSession } from "../../../core/src/session.js";
import { createTimestampRequest } from "../../../core/src/tsa/index.js";
import { createRFC3161TokenFixtureFromRequest } from "../fixtures/rfc3161-token.js";

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

async function embedRealSignedToken(): Promise<{
    prepared: Awaited<ReturnType<typeof preparePdfForTimestamp>>;
    token: Uint8Array;
    pdf: Uint8Array;
}> {
    const prepared = await preparePdfForTimestamp(minimalPdf(), { signatureSize: 4096 });
    const { request } = await createTimestampRequest(extractBytesToHash(prepared), {
        hashAlgorithm: "SHA-256",
        requestCertificate: true,
    });
    const fixture = await createRFC3161TokenFixtureFromRequest(request, { form: "raw" });
    return {
        prepared,
        token: fixture.rawToken,
        pdf: embedTimestampToken(prepared, fixture.rawToken),
    };
}

describe("PDF /Contents timestamp padding", () => {
    it("embeds and extracts a canonical primitive token through the Session gate", async () => {
        const session = new TimestampSession(minimalPdf(), {
            enableLTV: false,
            prepareOptions: { signatureSize: 4096 },
        });
        const request = await session.createTimestampRequest({
            hashAlgorithm: "SHA-256",
            requestCertificate: true,
        });
        const fixture = await createRFC3161TokenFixtureFromRequest(request, {
            form: "raw",
            eContentEncoding: "primitive",
        });
        expect(fixture.rawToken[0]).toBe(0x30);

        const pdf = await session.embedTimestampToken(fixture.rawToken);
        const extracted = await extractTimestamps(pdf);

        expect(extracted).toHaveLength(1);
        expect(extracted[0]?.token).toEqual(fixture.rawToken);
    });

    it("round-trips an actual prepared, requested, signed, embedded, extracted, and verified token", async () => {
        const { prepared, token, pdf } = await embedRealSignedToken();

        const extracted = await extractTimestamps(pdf);
        expect(extracted).toHaveLength(1);
        expect(extracted[0]?.token).toEqual(token);
        expect(extracted[0]?.contentsValueBytes).toHaveLength(
            prepared.contentsPlaceholderLength / 2
        );
        expect(extracted[0]?.contentsValueBytes.slice(0, token.length)).toEqual(token);
        expect(extracted[0]?.contentsValueBytes.slice(token.length)).toEqual(
            new Uint8Array(prepared.contentsPlaceholderLength / 2 - token.length)
        );

        const verified = await verifyTimestamp(extracted[0]!, {
            pdf,
            strictESSValidation: true,
        });
        expect(verified.verified).toBe(true);
    });

    it("rejects a PDF /Contents suffix containing a nonzero byte", async () => {
        const { prepared, token, pdf } = await embedRealSignedToken();
        const tampered = new Uint8Array(pdf);
        const firstPaddingHexDigit = prepared.contentsOffset + token.length * 2;
        tampered[firstPaddingHexDigit + 1] = "1".charCodeAt(0);

        await expect(extractTimestamps(tampered)).resolves.toEqual([]);
    });
});
