import { parseTimestampResponse } from "../../../core/src/tsa/response.js";
import { inputBytes, installNetworkDeny, runSyncParse } from "./fuzz-common.js";

installNetworkDeny();

/**
 * Fuzzes the complete-TimeStampResp entry (tsa/response.ts). Covers the
 * status grammar plus the shared strict token parser underneath. Runs
 * in synchronous mode (--sync).
 */
export function fuzz(buf: Buffer): void {
    const bytes = inputBytes(buf);
    runSyncParse(() => {
        parseTimestampResponse(bytes);
    });
}
