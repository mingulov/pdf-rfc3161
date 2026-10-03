import { timestampPdf, TimestampError, TimestampErrorCode } from "pdf-rfc3161";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchBytesWithRetry } from "../../../core/src/utils/fetch-with-retry.js";
import { makeInput } from "../utils/timestamp-fixtures.js";

// sol-pr85 I1: the HTTP reason phrase is responder-controlled. A hostile
// endpoint must not be able to reflect configured-URL secrets into thrown
// messages and logs through `response.statusText`.
const SECRET_USER = "sol-user";
const SECRET_PASSWORD = "sol-pass";
const SECRET_TOKEN = "sol-query";
const SECRET_FRAGMENT = "sol-fragment";
const POISONED_REASON =
    `Rejected https://${SECRET_USER}:${SECRET_PASSWORD}@tsa.example.test/path` +
    `?token=${SECRET_TOKEN}#${SECRET_FRAGMENT}`;

function expectRedacted(text: string): void {
    expect(text).not.toContain(SECRET_USER);
    expect(text).not.toContain(SECRET_PASSWORD);
    expect(text).not.toContain(SECRET_TOKEN);
    expect(text).not.toContain(SECRET_FRAGMENT);
}

function poisonedResponse(status: number): Response {
    return new Response("error-body", { status, statusText: POISONED_REASON });
}

describe("HTTP reason-text redaction (sol-pr85 I1)", () => {
    const mockFetch = vi.fn();

    beforeEach(() => {
        vi.stubGlobal("fetch", mockFetch);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
        vi.resetAllMocks();
    });

    it.each([404, 429])("redacts a poisoned reason on terminal HTTP %i", async (status) => {
        mockFetch.mockResolvedValue(poisonedResponse(status));
        const error = await fetchBytesWithRetry({
            url: "https://tsa.example.test/ts",
            method: "POST",
            config: { retry: 0, retryDelay: 1, timeout: 1000, maxResponseBytes: 1024 },
            serviceLabel: "TSA",
        }).then(
            () => null,
            (e: unknown) => e
        );

        expect(error).toBeInstanceOf(TimestampError);
        const coded = error as TimestampError;
        expect(coded.code).toBe(TimestampErrorCode.NETWORK_ERROR);
        expect(coded.message).toContain(`HTTP ${String(status)}`);
        expectRedacted(coded.message);
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("keeps a benign reason phrase verbatim", async () => {
        mockFetch.mockResolvedValue(new Response("error-body", { status: 404, statusText: "Not Found" }));
        const error = await fetchBytesWithRetry({
            url: "https://tsa.example.test/ts",
            method: "POST",
            config: { retry: 0, retryDelay: 1, timeout: 1000, maxResponseBytes: 1024 },
            serviceLabel: "TSA",
        }).then(
            () => null,
            (e: unknown) => e
        );

        expect(error).toBeInstanceOf(TimestampError);
        expect((error as TimestampError).message).toBe("TSA returned HTTP 404: Not Found");
    });

    it("redacts a poisoned reason in the retryable 5xx cause", async () => {
        mockFetch.mockResolvedValue(poisonedResponse(500));
        const error = await fetchBytesWithRetry({
            url: "https://tsa.example.test/ts",
            method: "POST",
            config: { retry: 0, retryDelay: 1, timeout: 1000, maxResponseBytes: 1024 },
            serviceLabel: "TSA",
        }).then(
            () => null,
            (e: unknown) => e
        );

        expect(error).toBeInstanceOf(TimestampError);
        const coded = error as TimestampError;
        expect(coded.code).toBe(TimestampErrorCode.NETWORK_ERROR);
        expectRedacted(coded.message);
        expect(coded.cause).toBeInstanceOf(Error);
        expectRedacted((coded.cause as Error).message);
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("redacts a poisoned reason through timestampPdf", async () => {
        mockFetch.mockResolvedValue(poisonedResponse(404));
        const input = await makeInput(true);
        const error = await timestampPdf({
            pdf: input,
            tsa: { url: "https://tsa.example.test/ts", retry: 0 },
            enableLTV: false,
        }).then(
            () => null,
            (e: unknown) => e
        );

        expect(error).toBeInstanceOf(TimestampError);
        const coded = error as TimestampError;
        expect(coded.code).toBe(TimestampErrorCode.NETWORK_ERROR);
        expect(coded.message).toContain("HTTP 404");
        expectRedacted(coded.message);
        expect((coded.cause as Error | undefined)?.message ?? "").not.toContain(SECRET_TOKEN);
        expect(mockFetch).toHaveBeenCalledTimes(1);
    });
});
