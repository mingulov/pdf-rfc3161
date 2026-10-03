import {
    createDerDecodeBudget,
    parseCanonicalDERSequenceTree,
    parseCanonicalDERValue,
} from "../../../core/src/pki/der-utils.js";
import { inputBytes, installNetworkDeny, runSyncParse, swallowExpected } from "./fuzz-common.js";

installNetworkDeny();

/**
 * Fuzzes the canonical-DER gates (pki/der-utils.ts): framing preflight,
 * depth/node budgets, and complete-consumption checks.
 *
 * Structured input: the first 2 bytes derive a small node budget
 * (1..4096 nodes, big-endian plus one) and the remainder is the DER
 * value under test. Deriving the budget from the input keeps
 * budget-exhaustion paths reachable within the 64 KiB input cap, and
 * depth-64 nesting needs only ~256 bytes, so this target needs no
 * larger-input justification. Both entry points share the DER format,
 * so one target exercises both, each with a fresh budget and each
 * guarded so the second still runs when the first rejects.
 * Runs in synchronous mode (--sync).
 */
export function fuzz(buf: Buffer): void {
    const bytes = inputBytes(buf);
    const high = bytes.length > 0 ? (bytes[0] ?? 0) : 0;
    const low = bytes.length > 1 ? (bytes[1] ?? 0) : 0;
    const budgetNodes = 1 + (((high << 8) | low) % 4096);
    const der = bytes.length > 2 ? bytes.subarray(2) : bytes;
    runSyncParse(() => {
        swallowExpected(() => {
            parseCanonicalDERSequenceTree(der, "fuzz-der", {
                budget: createDerDecodeBudget(budgetNodes),
            });
        });
        swallowExpected(() => {
            parseCanonicalDERValue(der, "fuzz-der", {
                budget: createDerDecodeBudget(budgetNodes),
            });
        });
    });
}
