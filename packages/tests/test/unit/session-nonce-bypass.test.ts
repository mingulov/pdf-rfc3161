import { beforeEach, describe, expect, it, vi } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
import { TimestampErrorCode, TSAStatus } from "../../../core/src/types.js";
import { createRFC3161TokenFixtureFromRequest } from "../fixtures/rfc3161-token.js";

const embedSpy = vi.hoisted(() => vi.fn(() => new Uint8Array([0x25, 0x50, 0x44, 0x46])));

vi.mock("../../../core/src/pdf/embed.js", async (importOriginal) => {
    const original = await importOriginal<typeof import("../../../core/src/pdf/embed.js")>();
    return { ...original, embedTimestampToken: embedSpy };
});

const { TimestampSession } = await import("../../../core/src/session.js");

async function createSession(): Promise<InstanceType<typeof TimestampSession>> {
    const pdf = await PDFDocument.create();
    pdf.addPage([100, 100]);
    return new TimestampSession(await pdf.save(), { enableLTV: false });
}

describe("TimestampSession nonce and response bypass regression", () => {
    beforeEach(() => {
        embedSpy.mockClear();
    });

    it("propagates a nonce mismatch as VERIFICATION_FAILED before embedding", async () => {
        const session = await createSession();
        const request = await session.createTimestampRequest();
        const fixture = await createRFC3161TokenFixtureFromRequest(request, {
            form: "response",
            responseNonce: new Uint8Array([9, 8, 7, 6]),
        });

        await expect(session.embedTimestampToken(fixture.input)).rejects.toMatchObject({
            code: TimestampErrorCode.VERIFICATION_FAILED,
        });
        expect(embedSpy).not.toHaveBeenCalled();
    });

    it("propagates a granted response without a token as MALFORMED_RESPONSE", async () => {
        const session = await createSession();
        const request = await session.createTimestampRequest();
        const fixture = await createRFC3161TokenFixtureFromRequest(request, {
            form: "response",
            status: TSAStatus.GRANTED,
            includeToken: false,
        });

        await expect(session.embedTimestampToken(fixture.input)).rejects.toMatchObject({
            code: TimestampErrorCode.MALFORMED_RESPONSE,
        });
        expect(embedSpy).not.toHaveBeenCalled();
    });

    it("propagates every TSA rejection instead of falling back to raw bytes", async () => {
        const session = await createSession();
        const request = await session.createTimestampRequest();
        const fixture = await createRFC3161TokenFixtureFromRequest(request, {
            form: "response",
            status: TSAStatus.REJECTION,
        });

        await expect(session.embedTimestampToken(fixture.input)).rejects.toMatchObject({
            code: TimestampErrorCode.TSA_ERROR,
        });
        expect(embedSpy).not.toHaveBeenCalled();
    });

    it("rejects malformed raw ContentInfo rather than treating it as embeddable", async () => {
        const session = await createSession();
        await session.createTimestampRequest();
        const malformedRaw = new Uint8Array([
            0x30,
            0x0b,
            0x06,
            0x09,
            0x2a,
            0x86,
            0x48,
            0x86,
            0xf7,
            0x0d,
            0x01,
            0x07,
            0x02,
        ]);

        await expect(session.embedTimestampToken(malformedRaw)).rejects.toMatchObject({
            code: TimestampErrorCode.MALFORMED_RESPONSE,
        });
        expect(embedSpy).not.toHaveBeenCalled();
    });

    it("still accepts a valid raw ContentInfo through the exact same gate", async () => {
        const session = await createSession();
        const request = await session.createTimestampRequest();
        const fixture = await createRFC3161TokenFixtureFromRequest(request, { form: "raw" });

        await expect(session.embedTimestampToken(fixture.input)).resolves.toEqual(
            new Uint8Array([0x25, 0x50, 0x44, 0x46])
        );
        expect(embedSpy).toHaveBeenCalledTimes(1);
    });
});
