// Node 22.12.0 exposes `globalThis.crypto`; retain the setup fallback for
// test environments that replace or omit the global before production code
// can run `ensureWebCrypto()`.
import { webcrypto } from "node:crypto";

if (typeof globalThis.crypto === "undefined") {
    (globalThis as { crypto: Crypto }).crypto = webcrypto as unknown as Crypto;
}
