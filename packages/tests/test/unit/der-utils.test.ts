import { describe, expect, it } from "vitest";
import {
    createDerDecodeBudget,
    parseCanonicalDERSequenceTree,
} from "../../../core/src/pki/der-utils.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";

/** Encodes DER length octets for a known content length. */
function derLengthOctets(contentLength: number): number[] {
    if (contentLength < 0x80) return [contentLength];
    const magnitude: number[] = [];
    let remaining = contentLength;
    while (remaining > 0) {
        magnitude.unshift(remaining & 0xff);
        remaining >>>= 8;
    }
    return [0x80 | magnitude.length, ...magnitude];
}

function derSequence(content: Uint8Array): Uint8Array {
    const header = [0x30, ...derLengthOctets(content.length)];
    const out = new Uint8Array(header.length + content.length);
    out.set(header, 0);
    out.set(content, header.length);
    return out;
}

/** Builds `depth` nested canonical SEQUENCEs around an empty SEQUENCE. */
function nestedSequences(depth: number): Uint8Array {
    let inner: Uint8Array = Uint8Array.of(0x30, 0x00);
    for (let level = 1; level < depth; level++) {
        inner = derSequence(inner);
    }
    return inner;
}

/** Builds one SEQUENCE holding `count` minimal `INTEGER 0` children. */
function wideSequence(count: number): Uint8Array {
    const child = [0x02, 0x01, 0x00];
    const content = new Uint8Array(count * child.length);
    for (let index = 0; index < count; index++) {
        content.set(child, index * child.length);
    }
    return derSequence(content);
}

function expectInvalidResponse(fn: () => unknown, messagePart: string): void {
    try {
        fn();
    } catch (error) {
        expect(error).toBeInstanceOf(TimestampError);
        expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
        expect((error as TimestampError).message).toContain(messagePart);
        return;
    }
    expect.unreachable("expected TimestampError(INVALID_RESPONSE)");
}

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

describe("canonical DER structural budgets (R26)", () => {
    it("accepts nesting of exactly 64 levels", () => {
        expect(() =>
            parseCanonicalDERSequenceTree(nestedSequences(64), "test value")
        ).not.toThrow();
    });

    it("rejects nesting of 65 levels with INVALID_RESPONSE", () => {
        expectInvalidResponse(
            () => parseCanonicalDERSequenceTree(nestedSequences(65), "test value"),
            "depth"
        );
    });

    it("rejects the 6,001-sequence reproduction with INVALID_RESPONSE, not RangeError", () => {
        const deep = nestedSequences(6001);
        expect(deep.length).toBeGreaterThan(20000);
        expectInvalidResponse(() => parseCanonicalDERSequenceTree(deep, "test value"), "depth");
    });

    it("rejects more than 1,000,000 TLV nodes with INVALID_RESPONSE", () => {
        expectInvalidResponse(
            () => parseCanonicalDERSequenceTree(wideSequence(1000000), "test value"),
            "node"
        );
    }, 60000);

    it("accepts a wide tree within the node budget", () => {
        expect(() => parseCanonicalDERSequenceTree(wideSequence(5000), "test value")).not.toThrow();
    });

    it("surfaces the underlying decoder limit detail for very wide values", () => {
        expectInvalidResponse(
            () => parseCanonicalDERSequenceTree(wideSequence(20000), "test value"),
            "Maximum ASN.1 node count exceeded"
        );
    });

    it("parses values from sliced views relative to the view", () => {
        const inner = derSequence(Uint8Array.of(0x02, 0x01, 0x00));
        const backing = new Uint8Array(inner.length + 64);
        backing.set([0x30, 0x03, 0x02, 0x01, 0x7f], 0);
        backing.set(inner, 64);
        const view = backing.subarray(64);
        expect(view.byteOffset).toBeGreaterThan(0);

        expect(() => parseCanonicalDERSequenceTree(view, "test value")).not.toThrow();
    });

    it("still rejects trailing bytes inside a sliced view", () => {
        const inner = derSequence(Uint8Array.of(0x02, 0x01, 0x00));
        const view = new Uint8Array(inner.length + 1);
        view.set(inner, 0);
        view[inner.length] = 0x00;

        expectInvalidResponse(
            () => parseCanonicalDERSequenceTree(view.subarray(0), "test value"),
            "trailing"
        );
    });
});

describe("canonical DER shared node budgets", () => {
    it("exhausts a small budget before the default limit", () => {
        const budget = createDerDecodeBudget(5);

        expectInvalidResponse(
            () => parseCanonicalDERSequenceTree(wideSequence(10), "test value", { budget }),
            "node count"
        );
    });

    it("reuses one budget across sequential nested decodings", () => {
        const budget = createDerDecodeBudget(12);
        const value = wideSequence(10);

        expect(() => parseCanonicalDERSequenceTree(value, "outer value", { budget })).not.toThrow();
        expectInvalidResponse(
            () => parseCanonicalDERSequenceTree(value, "nested value", { budget }),
            "node count"
        );
    });

    it("rejects a non-positive budget with INVALID_ARGUMENT", () => {
        for (const maxNodes of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
            try {
                createDerDecodeBudget(maxNodes);
            } catch (error) {
                expect(error).toBeInstanceOf(TimestampError);
                expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_ARGUMENT);
                continue;
            }
            expect.unreachable(`expected INVALID_ARGUMENT for budget ${String(maxNodes)}`);
        }
    });
});
