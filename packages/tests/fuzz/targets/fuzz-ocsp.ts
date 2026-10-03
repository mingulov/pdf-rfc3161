import { parseOCSPResponse } from "../../../core/src/pki/ocsp-utils.js";
import { inputBytes, installNetworkDeny, runSyncParse } from "./fuzz-common.js";

installNetworkDeny();

/**
 * Fuzzes the OCSP response parser (pki/ocsp-utils.ts): response-status
 * grammar, BasicOCSPResponse decoding, and single-response/cert-status
 * classification. Parse only; revocation fetching stays stubbed.
 * Runs in synchronous mode (--sync).
 */
export function fuzz(buf: Buffer): void {
    const bytes = inputBytes(buf);
    runSyncParse(() => {
        parseOCSPResponse(bytes);
    });
}
