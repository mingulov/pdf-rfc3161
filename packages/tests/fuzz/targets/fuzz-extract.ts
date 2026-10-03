import { extractTimestamps } from "../../../core/src/pdf/extract.js";
import { inputBytes, installNetworkDeny, runAsyncParse } from "./fuzz-common.js";

installNetworkDeny();

/**
 * Fuzzes timestamp extraction from arbitrary PDF bytes (pdf/extract.ts).
 * Awaited async target (Jazzer.js awaits the returned promise before
 * the next input), so it runs in default async mode, not --sync.
 * Extraction is parse-only; no verification or fetching is invoked.
 */
export async function fuzz(buf: Buffer): Promise<void> {
    const bytes = inputBytes(buf);
    await runAsyncParse(async () => {
        await extractTimestamps(bytes);
    });
}
