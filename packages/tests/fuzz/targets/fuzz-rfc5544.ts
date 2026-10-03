import { parseTimeStampedData } from "../../../core/src/rfcs/rfc5544.js";
import { inputBytes, installNetworkDeny, runSyncParse } from "./fuzz-common.js";

installNetworkDeny();

/**
 * Fuzzes the RFC 5544 TimeStampedData envelope parser (rfcs/rfc5544.ts):
 * ContentInfo typing, TimeStampedData item walk, and evidence decoding.
 * Runs in synchronous mode (--sync).
 */
export function fuzz(buf: Buffer): void {
    const bytes = inputBytes(buf);
    runSyncParse(() => {
        parseTimeStampedData(bytes);
    });
}
