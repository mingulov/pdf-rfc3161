import { inspect } from "node:util";
import { describe, expect, it, vi } from "vitest";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";
import { validateUrl } from "../../../core/src/utils/url.js";
import { fetchBytesWithRetry } from "../../../core/src/utils/fetch-with-retry.js";

const INVALID_SECRET_URL =
    "https://PRIVATE_USER:PRIVATE_PASSWORD@bad host/path?token=PRIVATE_TOKEN#PRIVATE_FRAGMENT";
const SECRETS = ["PRIVATE_USER", "PRIVATE_PASSWORD", "PRIVATE_TOKEN", "PRIVATE_FRAGMENT"];

function expectSafeError(error: unknown): void {
    expect(error).toBeInstanceOf(TimestampError);
    expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
    // Include non-enumerable fields and the native URL error's `input`.
    const rendered = inspect(error, { showHidden: true, depth: 8 });
    for (const secret of SECRETS) expect(rendered).not.toContain(secret);
}

describe("malformed URL diagnostic redaction", () => {
    it("does not retain credentials, query or fragment in a parse error or cause", () => {
        let failure: unknown;
        try {
            validateUrl(INVALID_SECRET_URL);
        } catch (error) {
            failure = error;
        }
        expectSafeError(failure);
    });

    it("fails safely before fetching a malformed credential-bearing URL", async () => {
        const fetch = vi.spyOn(globalThis, "fetch");
        try {
            const error: unknown = await fetchBytesWithRetry({
                url: INVALID_SECRET_URL,
                method: "GET",
                config: { retry: 0, retryDelay: 0, timeout: 1000, maxResponseBytes: 1024 },
            }).catch((failure: unknown) => failure);
            expectSafeError(error);
            expect(fetch).not.toHaveBeenCalled();
        } finally {
            fetch.mockRestore();
        }
    });
});
