import { parseTimestampToken } from "../../../core/src/tsa/token-validation.js";
import { inputBytes, installNetworkDeny, runSyncParse } from "./fuzz-common.js";

installNetworkDeny();

/**
 * Fuzzes the strict CMS token parser (tsa/token-validation.ts), reached
 * both directly with raw ContentInfo tokens and via complete
 * TimeStampResp values. Runs in synchronous mode (--sync).
 */
export function fuzz(buf: Buffer): void {
    const bytes = inputBytes(buf);
    runSyncParse(() => {
        parseTimestampToken(bytes);
    });
}
