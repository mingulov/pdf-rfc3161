import { PDFDocument } from "pdf-lib-incremental-save";
import { vi } from "vitest";
import { createRFC3161TokenFixtureFromRequest } from "../fixtures/rfc3161-token.js";

// Scaffolding shared by the suites that timestamp a PDF offline: an in-process
// TSA and the two-page input they all start from. Both were byte-identical
// copies in several suites before review finding 9.

/**
 * Answers every `fetch` with an RFC 3161 response generated from the request
 * that was sent, so a suite can timestamp without touching the network. The
 * caller is responsible for `vi.unstubAllGlobals()` in its own `afterEach`.
 */
export function stubTsaFetch(): void {
    vi.stubGlobal(
        "fetch",
        vi.fn(async (_url: string | URL | Request, options?: RequestInit) => {
            if (!(options?.body instanceof ArrayBuffer)) {
                throw new Error("Expected the TSA request as an ArrayBuffer");
            }
            const fixture = await createRFC3161TokenFixtureFromRequest(
                new Uint8Array(options.body),
                { form: "response" }
            );
            return new Response(new Uint8Array(fixture.response).buffer, {
                headers: { "content-type": "application/timestamp-reply" },
            });
        })
    );
}

/**
 * A two-page PDF written with the requested cross-reference format: `true`
 * gives pdf-lib's default cross-reference stream, `false` a classic xref table.
 * Two pages so a strict reader's page count is itself an assertion.
 */
export async function makeInput(useObjectStreams: boolean): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([200, 200]);
    document.addPage([200, 200]);
    return document.save({ useObjectStreams });
}
