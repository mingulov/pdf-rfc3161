import { beforeEach, describe, expect, it, vi } from "vitest";
import { PlaceholderTooSmallError } from "../../../core/src/pdf/embed.js";
import { TimestampErrorCode, TSAStatus } from "../../../core/src/types.js";

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
    const baseEmbed = async (_response: Uint8Array): Promise<Uint8Array> => {
        state.embedAttempts++;
        if (state.embedAttempts === 1) {
            throw new PlaceholderTooSmallError(
                4096,
                "Timestamp token is larger than placeholder. Increase signatureSize."
            );
        }
        return new Uint8Array([0x25, 0x50, 0x44, 0x46]);
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
        optimalCalls: 0,
        forceCappedOptimal: false,
        growingOptimal: false,
        baseEmbed,
        embed: vi.fn(baseEmbed),
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
            // First call per test optimizes the probe/initial reservation to
            // 4096; later calls grow, since the retry loop never repeats an
            // identical too-small reservation.
            state.optimalCalls++;
            if (state.forceCappedOptimal) return 65536;
            // Growing mode doubles every call so a persistently too-small
            // placeholder survives to the final retry attempt (T13: the
            // attempt < MAX_RETRIES exhaustion branch).
            if (state.growingOptimal) return 4096 * 2 ** (state.optimalCalls - 1);
            return state.optimalCalls === 1 ? 4096 : 8192;
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

const { timestampPdf, timestampPdfMultiple } = await import("../../../core/src/index.js");

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
        state.optimalCalls = 0;
        state.forceCappedOptimal = false;
        state.growingOptimal = false;
        state.embed.mockImplementation(state.baseEmbed);
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

    it("does not retry a plain Error that merely mentions the placeholder text", async () => {
        state.embed.mockImplementationOnce(async () => {
            throw new Error("Increase signatureSize");
        });

        await expect(timestampPdf(options)).rejects.toThrow("Increase signatureSize");
        expect(state.send).toHaveBeenCalledTimes(1);
        expect(state.embed).toHaveBeenCalledTimes(1);
    });

    it("never repeats an identical too-small reservation while growing", async () => {
        state.embed.mockImplementation(async () => {
            throw new PlaceholderTooSmallError(70000, "probe: Increase signatureSize");
        });

        await expect(timestampPdf(options)).rejects.toBeInstanceOf(PlaceholderTooSmallError);
        const sizes = state.sessionOptions.mock.calls.map(
            (call) =>
                (call[0] as { prepareOptions: { signatureSize: number } }).prepareOptions
                    .signatureSize
        );
        expect(sizes).toEqual([0, 4096, 8192]);
        expect(state.send).toHaveBeenCalledTimes(3);
        expect(state.embed).toHaveBeenCalledTimes(3);
    });

    it("issues no extra TSA request after the reservation cap is reached", async () => {
        state.forceCappedOptimal = true;
        state.embed.mockImplementation(async () => {
            throw new PlaceholderTooSmallError(70000, "probe: Increase signatureSize");
        });

        const failure = await timestampPdf(options).then(
            () => {
                throw new Error("unexpected success past the reservation cap");
            },
            (error: unknown) => error
        );
        expect(failure).toBeInstanceOf(PlaceholderTooSmallError);
        expect((failure as PlaceholderTooSmallError).requiredSignatureSize).toBe(70000);
        expect((failure as Error).message).toContain("reservation cap");
        const sizes = state.sessionOptions.mock.calls.map(
            (call) =>
                (call[0] as { prepareOptions: { signatureSize: number } }).prepareOptions
                    .signatureSize
        );
        expect(sizes).toEqual([0, 65536]);
        expect(state.send).toHaveBeenCalledTimes(2);
        expect(state.embed).toHaveBeenCalledTimes(2);
    });

    it("surfaces reservation-cap exhaustion from the optimization probe without another TSA request", async () => {
        state.forceCappedOptimal = true;
        const granted = state.parse();
        state.parse.mockClear();
        state.parse.mockReturnValueOnce({ ...granted, token: new Uint8Array(65537) });

        const failure = await timestampPdf({
            ...options,
            signatureSize: 65536,
            optimizePlaceholder: true,
        }).then(
            () => {
                throw new Error("unexpected success past the reservation cap");
            },
            (error: unknown) => error
        );
        expect(failure).toBeInstanceOf(PlaceholderTooSmallError);
        expect((failure as PlaceholderTooSmallError).requiredSignatureSize).toBe(65537);
        expect((failure as Error).message).toContain("reservation cap");
        const sizes = state.sessionOptions.mock.calls.map(
            (call) =>
                (call[0] as { prepareOptions: { signatureSize: number } }).prepareOptions
                    .signatureSize
        );
        expect(sizes).toEqual([65536]);
        expect(state.send).toHaveBeenCalledTimes(1);
        expect(state.embed).not.toHaveBeenCalled();
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
            prepareOptions: { signatureSize: 8192, optimizePlaceholder: true },
        });
        expect(state.send).toHaveBeenCalledTimes(3);
        expect(state.embed).toHaveBeenCalledTimes(2);
        expect(state.addDss).toHaveBeenCalledTimes(1);
    });

    it("surfaces the placeholder error when the final retry attempt still does not fit", async () => {
        state.growingOptimal = true;
        state.embed.mockImplementation(async () => {
            throw new PlaceholderTooSmallError(70000, "probe: Increase signatureSize");
        });

        const failure = await timestampPdf(options).then(
            () => {
                throw new Error("unexpected success after exhausting retries");
            },
            (error: unknown) => error
        );
        expect(failure).toBeInstanceOf(PlaceholderTooSmallError);
        expect((failure as PlaceholderTooSmallError).requiredSignatureSize).toBe(70000);
        // The reservation kept growing, so this is attempt exhaustion, not
        // the reservation-cap path.
        expect((failure as Error).message).not.toContain("reservation cap");
        const sizes = state.sessionOptions.mock.calls.map(
            (call) =>
                (call[0] as { prepareOptions: { signatureSize: number } }).prepareOptions
                    .signatureSize
        );
        expect(sizes).toEqual([0, 4096, 8192, 16384]);
        expect(state.send).toHaveBeenCalledTimes(4);
        expect(state.embed).toHaveBeenCalledTimes(4);
    });

    it("collects one LTV entry per TSA when timestamping with several TSAs", async () => {
        const result = await timestampPdfMultiple({
            pdf: options.pdf,
            tsaList: [
                { url: "http://timestamp-a.mock.test" },
                { url: "http://timestamp-b.mock.test" },
            ],
        });

        expect(result.timestamps).toHaveLength(2);
        expect(result.timestamps[0]).toMatchObject({ policy: "1.2.3.4.5" });
        expect(result.timestamps[1]).toMatchObject({ policy: "1.2.3.4.5" });
        expect(result.ltvData).toHaveLength(2);
        expect(result.ltvData?.[0]).toEqual({ certificates: [], crls: [], ocspResponses: [] });
        expect(result.ltvData?.[1]).toEqual({ certificates: [], crls: [], ocspResponses: [] });
        expect(result.pdf).toBeInstanceOf(Uint8Array);
    });

    it("passes the TSA policy through the optimization probe request", async () => {
        await timestampPdf({
            ...options,
            optimizePlaceholder: true,
            tsa: { url: "http://timestamp.mock.test", policy: "1.2.3.4" },
        });

        // The probe request carries the caller's policy, as do the retry
        // attempts that follow it.
        expect(state.createRequest).toHaveBeenCalledTimes(3);
        for (const call of state.createRequest.mock.calls) {
            expect(call[0]).toMatchObject({ policy: "1.2.3.4", requestCertificate: true });
        }
    });

    it("rejects timestamping with an empty TSA list", async () => {
        await expect(timestampPdfMultiple({ pdf: options.pdf, tsaList: [] })).rejects.toMatchObject(
            {
                code: TimestampErrorCode.INVALID_ARGUMENT,
                message: "At least one TSA must be specified",
            }
        );
        // The guard fires before any TSA request is issued.
        expect(state.send).not.toHaveBeenCalled();
    });
});
