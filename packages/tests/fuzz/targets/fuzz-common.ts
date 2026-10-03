import { TimestampError } from "../../../core/src/types.js";

/**
 * Shared Jazzer.js harness helpers (T16 pilot).
 *
 * Failure semantics: only the expected TimestampError is swallowed.
 * Unknown exceptions, hangs (via the Jazzer per-input timeout), and
 * crashes fail the run. Networking is stubbed and every attempt fails
 * the run, even when core's retry shell wraps the rejection into an
 * "expected" TimestampError(NETWORK_ERROR): attempts are counted at
 * the global fetch seam, not inferred from the error type.
 */

let networkAttempts = 0;

/**
 * Replaces global fetch with a stub that counts and rejects every call.
 * Core performs all HTTP through the global fetch seam (utils/fetchers
 * use bare fetch(); no node:http imports exist in core), so this one
 * stub covers TSA/OCSP/CRL/cert fetch paths. Called once per target
 * module, before any fuzz input runs.
 */
export function installNetworkDeny(): void {
    const denyFetch = (): Promise<Response> => {
        networkAttempts += 1;
        throw new Error("FUZZ_NETWORK_DENIED: networking is stubbed in fuzz targets");
    };
    globalThis.fetch = denyFetch;
}

function resetNetworkAttempts(): void {
    networkAttempts = 0;
}

/** Throws a plain (unexpected, run-failing) Error on any network attempt. */
function assertNoNetworkAttempt(): void {
    if (networkAttempts > 0) {
        throw new Error(
            `FUZZ_NETWORK_DENIED: target attempted ${String(networkAttempts)} network fetch(es)`
        );
    }
}

/** Zero-copy Uint8Array view over one Jazzer input Buffer. */
export function inputBytes(buf: Buffer): Uint8Array {
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

/** Runs one call, swallowing only the expected TimestampError. */
export function swallowExpected(fn: () => void): void {
    try {
        fn();
    } catch (error) {
        if (!(error instanceof TimestampError)) throw error;
    }
}

/** Sync one-input wrapper: expected-errors-only plus fail-on-network. */
export function runSyncParse(parse: () => void): void {
    resetNetworkAttempts();
    swallowExpected(parse);
    assertNoNetworkAttempt();
}

/** Async one-input wrapper: expected-errors-only plus fail-on-network. */
export async function runAsyncParse(parse: () => Promise<void>): Promise<void> {
    resetNetworkAttempts();
    try {
        await parse();
    } catch (error) {
        if (!(error instanceof TimestampError)) throw error;
    }
    assertNoNetworkAttempt();
}
