import { expect, it, vi } from "vitest";
import { sendTimestampRequest } from "../../../core/src/tsa/client.js";
import { getLogger, setLogger } from "../../../core/src/utils/logger.js";

it("redacts reflected URL secrets from unexpected Content-Type warnings", async () => {
    const originalLogger = getLogger();
    const warn = vi.fn();
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(
        new Response(Uint8Array.of(1), {
            headers: {
                "content-type":
                    "application/other; source=https://PRIVATE_USER:PRIVATE_PASSWORD@" +
                    "example.invalid/tsr?key=PRIVATE_TOKEN#PRIVATE_FRAGMENT",
            },
        })
    );
    setLogger({ debug: vi.fn(), info: vi.fn(), warn, error: vi.fn() });
    try {
        await sendTimestampRequest(Uint8Array.of(1), {
            url: "https://example.invalid/tsr?key=PRIVATE_TOKEN",
            retry: 0,
        });
        expect(warn).toHaveBeenCalledTimes(1);
        const message = String(warn.mock.calls[0]?.[0]);
        expect(message).toContain("unexpected content-type");
        expect(message).toContain("https://example.invalid/tsr");
        for (const secret of [
            "PRIVATE_USER", "PRIVATE_PASSWORD", "PRIVATE_TOKEN", "PRIVATE_FRAGMENT",
        ]) {
            expect(message).not.toContain(secret);
        }
    } finally {
        fetch.mockRestore();
        setLogger(originalLogger);
    }
});
