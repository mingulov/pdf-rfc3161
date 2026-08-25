import { describe, expect, it } from "vitest";
import { parseCanonicalDERSequenceTree } from "../../../core/src/pki/der-utils.js";

describe("canonical DER sequence tree validation", () => {
    it("rejects non-minimal high-tag-number encoding inside a canonical outer sequence", () => {
        const nonMinimalTag = Uint8Array.of(0x30, 0x03, 0x1f, 0x1e, 0x00);

        expect(() => parseCanonicalDERSequenceTree(nonMinimalTag, "test value")).toThrow(
            "non-minimal DER tag encoding"
        );
    });

    it("accepts minimally encoded large positive and negative INTEGER and ENUMERATED values", () => {
        const canonicalIntegers = Uint8Array.of(
            0x30,
            0x11,
            0x02,
            0x02,
            0x00,
            0x80,
            0x02,
            0x02,
            0xff,
            0x7f,
            0x0a,
            0x04,
            0x00,
            0x80,
            0x00,
            0x00,
            0x0a,
            0x01,
            0xff
        );

        expect(() => parseCanonicalDERSequenceTree(canonicalIntegers, "test value")).not.toThrow();
    });

    it.each([
        ["empty INTEGER", Uint8Array.of(0x30, 0x02, 0x02, 0x00)],
        ["constructed INTEGER", Uint8Array.of(0x30, 0x04, 0x22, 0x02, 0x01, 0x00)],
        ["redundant positive INTEGER", Uint8Array.of(0x30, 0x04, 0x02, 0x02, 0x00, 0x7f)],
        ["redundant negative INTEGER", Uint8Array.of(0x30, 0x04, 0x02, 0x02, 0xff, 0x80)],
        ["redundant ENUMERATED", Uint8Array.of(0x30, 0x04, 0x0a, 0x02, 0x00, 0x00)],
    ])("rejects %s", (_description: string, bytes: Uint8Array) => {
        expect(() => parseCanonicalDERSequenceTree(bytes, "test value")).toThrow(/INTEGER|ENUMERATED/);
    });
});
