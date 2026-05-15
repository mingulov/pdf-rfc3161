// Node 18 does not expose `globalThis.crypto`; tests that spy on it (e.g.
// tsa-request.test.ts) hit `ReferenceError: crypto is not defined` before
// any production code can run `ensureWebCrypto()`. Polyfill here so tests
// behave the same across the supported Node range (>=18).
import { webcrypto } from "node:crypto";

if (typeof globalThis.crypto === "undefined") {
    (globalThis as { crypto: Crypto }).crypto = webcrypto as unknown as Crypto;
}
