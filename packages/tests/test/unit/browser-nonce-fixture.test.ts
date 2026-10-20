import { describe, expect, it } from "vitest";
import { flippedNonce } from "../../scripts/browser-nonce-fixture";
import { createRFC3161TokenFixture } from "../fixtures/rfc3161-token";
import { validateTimestampToken } from "../../../core/src/tsa/token-validation";

describe("browser wrong-nonce fixture", () => {
    it("always changes each possible leading byte without changing the input", () => {
        for (let first = 0; first <= 255; first++) {
            for (const input of [
                new Uint8Array([first]),
                new Uint8Array([first, 2, 3, 4, 5, 6, 7, 8]),
            ]) {
                const original = new Uint8Array(input);
                const changed = flippedNonce(input);
                expect(changed, `leading byte ${first}`).not.toEqual(original);
                expect(changed.length).toBe(input.length);
                expect(changed[0]).toBeGreaterThan(0);
                expect(changed[0]).toBeLessThan(128);
                expect(input).toEqual(original);
            }
        }
        expect(flippedNonce(new Uint8Array())).toEqual(new Uint8Array([1]));
    });

    it("makes the leading-0x01 negative fixture fail nonce binding", async () => {
        const nonce = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
        const valid = await createRFC3161TokenFixture({ nonce });
        await expect(validateTimestampToken(valid.rawToken, valid.context)).resolves.toHaveProperty(
            "token"
        );
        const wrong = await createRFC3161TokenFixture({
            nonce,
            responseNonce: flippedNonce(nonce),
        });
        await expect(validateTimestampToken(wrong.rawToken, wrong.context)).rejects.toMatchObject({
            code: "VERIFICATION_FAILED",
            message: expect.stringContaining("nonce does not match"),
        });
    });
});
