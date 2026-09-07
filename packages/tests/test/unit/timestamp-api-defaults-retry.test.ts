import { beforeEach, describe, expect, it, vi } from "vitest";
import { TSAStatus } from "../../../core/src/types.js";

interface MockLTVData {
    certificates: Uint8Array[];
    crls: Uint8Array[];
    ocspResponses: Uint8Array[];
}

const state = vi.hoisted(() => {
    const info = {
        genTime: new Date("2026-08-24T00:00:00Z"),
        policy: "1.2.3.4.5",
        serialNumber: "1",
        hashAlgorithm: "SHA-256",
        hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
        messageDigest: "00",
        hasCertificate: true,
    };
    return {
        sessionOptions: vi.fn(),
        createRequest: vi.fn(async (_options: unknown) => new Uint8Array([0x30, 0x00])),
        send: vi.fn(async () => new Uint8Array([0x30, 0x00])),
        parse: vi.fn(() => ({
            status: TSAStatus.GRANTED,
            token: new Uint8Array([1, 2, 3]),
            info,
        })),
        embedAttempts: 0,
        embed: vi.fn(async (_response: Uint8Array) => {
            state.embedAttempts++;
            if (state.embedAttempts === 1) throw new Error("Increase signatureSize");
            return new Uint8Array([0x25, 0x50, 0x44, 0x46]);
        }),
        extractLtv: vi.fn(() => ({ certificates: [], crls: [], ocspResponses: [] })),
        completeLtv: vi.fn(async (data: MockLTVData) => ({ data, errors: [] })),
        addDss: vi.fn(async (pdf: Uint8Array) => pdf),
    };
});

vi.mock("../../../core/src/session.js", () => {
    class FakeSession {
        constructor(_pdf: Uint8Array, options: unknown) {
            state.sessionOptions(options);
        }

        async createTimestampRequest(options: unknown): Promise<Uint8Array> {
            return state.createRequest(options);
        }

        async embedTimestampToken(response: Uint8Array): Promise<Uint8Array> {
            return state.embed(response);
        }

        setSignatureSize(_size: number): void {}

        static calculateOptimalSize(_token: Uint8Array): number {
            return 4096;
        }
    }
    return { TimestampSession: FakeSession };
});

vi.mock("../../../core/src/tsa/index.js", async (importOriginal: <T = unknown>() => Promise<T>) => {
    const original = await importOriginal<typeof import("../../../core/src/tsa/index.js")>();
    return {
        ...original,
        sendTimestampRequest: state.send,
        parseTimestampResponse: state.parse,
    };
});

vi.mock("../../../core/src/pdf/ltv.js", () => ({
    extractLTVData: state.extractLtv,
    completeLTVData: state.completeLtv,
    addDSS: state.addDss,
}));

const { timestampPdf } = await import("../../../core/src/index.js");

const options = {
    pdf: new Uint8Array([0x25, 0x50, 0x44, 0x46]),
    tsa: { url: "http://timestamp.mock.test" },
} as const;

describe("timestampPdf omitted options through optimization and retry", () => {
    beforeEach(() => {
        state.sessionOptions.mockClear();
        state.createRequest.mockClear();
        state.send.mockClear();
        state.parse.mockClear();
        state.embed.mockClear();
        state.extractLtv.mockClear();
        state.completeLtv.mockClear();
        state.addDss.mockClear();
        state.embedAttempts = 0;
    });

    it("keeps default retry and LTV behavior when optional options are omitted", async () => {
        const result = await timestampPdf(options);

        expect(state.sessionOptions).toHaveBeenCalledTimes(2);
        expect(state.sessionOptions.mock.calls[0]?.[0]).toMatchObject({
            enableLTV: false,
            prepareOptions: { signatureSize: 0 },
        });
        expect(state.sessionOptions.mock.calls[1]?.[0]).toMatchObject({
            enableLTV: false,
            prepareOptions: { signatureSize: 4096 },
        });
        expect(state.send).toHaveBeenCalledTimes(2);
        expect(state.embed).toHaveBeenCalledTimes(2);
        expect(state.addDss).toHaveBeenCalledTimes(1);
        expect(result.ltvData).toEqual({ certificates: [], crls: [], ocspResponses: [] });
    });

    it("keeps the omitted defaults through the optimization probe and retry", async () => {
        await timestampPdf({ ...options, optimizePlaceholder: true });

        expect(state.sessionOptions).toHaveBeenCalledTimes(3);
        expect(state.sessionOptions.mock.calls[0]?.[0]).toMatchObject({
            enableLTV: true,
            prepareOptions: { signatureSize: 0, optimizePlaceholder: true },
        });
        expect(state.sessionOptions.mock.calls[1]?.[0]).toMatchObject({
            enableLTV: false,
            prepareOptions: { signatureSize: 4096, optimizePlaceholder: true },
        });
        expect(state.sessionOptions.mock.calls[2]?.[0]).toMatchObject({
            enableLTV: false,
            prepareOptions: { signatureSize: 4096, optimizePlaceholder: true },
        });
        expect(state.send).toHaveBeenCalledTimes(3);
        expect(state.embed).toHaveBeenCalledTimes(2);
        expect(state.addDss).toHaveBeenCalledTimes(1);
    });
});
