/**
 * Lazy Web Crypto initialiser.
 *
 * Older Node releases (and any environment where `globalThis.crypto` is not
 * pre-populated) need the `webcrypto` subset from `node:crypto` to be wired
 * onto `globalThis.crypto` before `crypto.subtle.digest(...)` calls work.
 *
 * The previous implementation lived at the top of tsa/request.ts and used
 * `require("node:crypto")`. That worked in CJS but tsup transformed it to
 * `__require("crypto")` in the ESM build, which throws and is silently
 * swallowed by the surrounding try/catch — leaving any ESM consumer without
 * a `crypto` global broken.
 *
 * Using `await import("node:crypto")` works in both ESM and CJS bundles. The
 * tradeoff is that callers must `await` it before the first `crypto.subtle.*`
 * call. We memoise the result with a module-scoped boolean so subsequent
 * calls are essentially free.
 *
 * Closes C1 / B2 ESM polyfill bug from the 2026-05-14 audit.
 */

let cryptoEnsured = false;

export async function ensureWebCrypto(): Promise<void> {
    if (cryptoEnsured) return;
    if (typeof globalThis.crypto !== "undefined") {
        cryptoEnsured = true;
        return;
    }
    try {
        const nodeCrypto = (await import("node:crypto")) as { webcrypto?: Crypto };
        if (nodeCrypto.webcrypto) {
            (globalThis as { crypto: Crypto }).crypto = nodeCrypto.webcrypto;
        }
    } catch {
        // Ignore if node:crypto is unavailable (Workers / Deno / browser).
        // The caller will see a useful TypeError when it reaches `crypto.subtle`.
    }
    cryptoEnsured = true;
}
