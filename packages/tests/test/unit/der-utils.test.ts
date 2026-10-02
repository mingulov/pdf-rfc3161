import { describe, expect, it } from "vitest";
import * as asn1js from "asn1js";
import {
    createDerDecodeBudget,
    parseCanonicalDERSequenceTree,
    parseCanonicalDERValue,
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
        expect(() => parseCanonicalDERSequenceTree(bytes, "test value")).toThrow(
            /INTEGER|ENUMERATED/
        );
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

describe("canonical DER value validation (any root tag)", () => {
    it("accepts canonical primitive roots other than SEQUENCE", () => {
        expect(() =>
            parseCanonicalDERValue(Uint8Array.of(0x04, 0x02, 0xaa, 0xbb), "test value")
        ).not.toThrow();
        expect(() =>
            parseCanonicalDERValue(Uint8Array.of(0x03, 0x02, 0x07, 0x80), "test value")
        ).not.toThrow();
        expect(() => parseCanonicalDERValue(Uint8Array.of(0x30, 0x00), "test value")).not.toThrow();
    });

    it("rejects indefinite-length and non-minimal-length roots", () => {
        expectInvalidResponse(
            () =>
                parseCanonicalDERValue(
                    Uint8Array.of(0x30, 0x80, 0x06, 0x01, 0x2a, 0x00, 0x00),
                    "test value"
                ),
            "indefinite-length"
        );
        expectInvalidResponse(
            () => parseCanonicalDERValue(Uint8Array.of(0x04, 0x81, 0x02, 0xaa, 0xbb), "test value"),
            "non-minimal"
        );
    });

    it("rejects trailing bytes after a canonical root", () => {
        expectInvalidResponse(
            () => parseCanonicalDERValue(Uint8Array.of(0x04, 0x01, 0xaa, 0x00), "test value"),
            "trailing"
        );
    });

    it("rejects truncated content and honors a shared budget", () => {
        expectInvalidResponse(
            () => parseCanonicalDERValue(Uint8Array.of(0x04, 0x02, 0xaa), "test value"),
            "truncated"
        );
        const budget = createDerDecodeBudget(1);
        expect(() =>
            parseCanonicalDERValue(Uint8Array.of(0x04, 0x01, 0xaa), "first value", { budget })
        ).not.toThrow();
        expectInvalidResponse(
            () =>
                parseCanonicalDERValue(Uint8Array.of(0x04, 0x01, 0xaa), "second value", { budget }),
            "node count"
        );
    });
});

function hexOf(bytes: Uint8Array): string {
    let out = "";
    for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
    return out;
}

type DifferentialOutcome =
    | { readonly ok: true; readonly encoding: string; readonly remaining: number }
    | {
          readonly ok: false;
          readonly code: TimestampErrorCode;
          readonly message: string;
          readonly remaining: number;
      };

/** Runs one entry point, capturing acceptance, decoded output, error identity, and budget use. */
function captureOutcome(
    parse: typeof parseCanonicalDERSequenceTree,
    bytes: Uint8Array,
    budgetSize: number
): DifferentialOutcome {
    const budget = createDerDecodeBudget(budgetSize);
    try {
        const tree = parse(bytes, "differential", { budget });
        return {
            ok: true,
            encoding: hexOf(new Uint8Array(tree.toBER(false))),
            remaining: budget.remainingNodes,
        };
    } catch (error) {
        // Only categorized failures are comparable: anything else (a
        // RangeError from a regressed preflight, for example) must fail loudly.
        if (!(error instanceof TimestampError)) throw error;
        return {
            ok: false,
            code: error.code,
            message: error.message,
            remaining: budget.remainingNodes,
        };
    }
}

interface DifferentialInput {
    readonly label: string;
    readonly bytes: Uint8Array;
}

/**
 * Fixed differential corpus over the preflight decision surface. Fully
 * deterministic (no randomness): hand-picked framing cases, nested and
 * wide shapes, a generative INTEGER sweep, and every single-octet
 * corruption plus every truncation of one seed value.
 */
function buildDifferentialCorpus(): DifferentialInput[] {
    const handPicked: [string, number[]][] = [
        ["empty sequence", [0x30, 0x00]],
        ["sequence with INTEGER 0", [0x30, 0x03, 0x02, 0x01, 0x00]],
        ["sequence with minimal INTEGER 128", [0x30, 0x04, 0x02, 0x02, 0x00, 0x80]],
        ["sequence with ENUMERATED", [0x30, 0x03, 0x0a, 0x01, 0x05]],
        ["sequence with OID child", [0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03]],
        ["sequence with empty OID child", [0x30, 0x02, 0x06, 0x00]],
        ["sequence with OCTET STRING", [0x30, 0x04, 0x04, 0x02, 0xaa, 0xbb]],
        ["sequence with NULL", [0x30, 0x02, 0x05, 0x00]],
        ["sequence with UTF8String", [0x30, 0x04, 0x0c, 0x02, 0x41, 0x42]],
        ["sequence with BIT STRING", [0x30, 0x04, 0x03, 0x02, 0x07, 0x80]],
        [
            "sequence with UTCTime",
            [
                0x30, 0x0f, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x35, 0x30, 0x31, 0x31, 0x32, 0x30, 0x30,
                0x30, 0x30, 0x5a,
            ],
        ],
        ["nested sequences", [0x30, 0x04, 0x30, 0x02, 0x30, 0x00]],
        ["explicit [0] wrapper", [0x30, 0x04, 0xa0, 0x02, 0x02, 0x01, 0x05]],
        ["private primitive tag", [0x30, 0x03, 0xc1, 0x01, 0xaa]],
        ["minimal high-tag-number primitive", [0x30, 0x04, 0x1f, 0x1f, 0x01, 0xaa]],
        ["indefinite-length root", [0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00]],
        ["indefinite-length child", [0x30, 0x06, 0x04, 0x80, 0xaa, 0xbb, 0x00, 0x00]],
        ["non-minimal long-form root length", [0x30, 0x81, 0x00]],
        ["leading-zero length octet", [0x30, 0x82, 0x00, 0x03, 0x02, 0x01, 0x00]],
        ["long-form for short length", [0x30, 0x81, 0x03, 0x02, 0x01, 0x00]],
        ["truncated tag", [0x30]],
        ["truncated length", [0x30, 0x81]],
        ["truncated content", [0x30, 0x03, 0x02, 0x01]],
        ["length overruns input", [0x30, 0x05, 0x02, 0x01, 0x00]],
        ["trailing byte", [0x30, 0x00, 0x00]],
        ["trailing TLV", [0x30, 0x00, 0x05, 0x00]],
        ["empty INTEGER", [0x30, 0x02, 0x02, 0x00]],
        ["constructed INTEGER", [0x30, 0x04, 0x22, 0x02, 0x01, 0x00]],
        ["redundant positive INTEGER", [0x30, 0x04, 0x02, 0x02, 0x00, 0x7f]],
        ["redundant negative INTEGER", [0x30, 0x04, 0x02, 0x02, 0xff, 0x80]],
        ["redundant ENUMERATED", [0x30, 0x04, 0x0a, 0x02, 0x00, 0x00]],
        ["non-minimal high-tag-number", [0x30, 0x03, 0x1f, 0x1e, 0x00]],
        ["high-tag leading-zero octet", [0x30, 0x05, 0x1f, 0x80, 0x1f, 0x01, 0x00]],
        ["EOC child", [0x30, 0x01, 0x00]],
        ["high-tag truncated", [0x30, 0x02, 0x1f, 0x81]],
        ["child overruns parent", [0x30, 0x03, 0x02, 0x02, 0x00]],
        ["length octets overrun", [0x30, 0x02, 0x02, 0x81]],
    ];
    const corpus: DifferentialInput[] = handPicked.map(([label, raw]) => ({
        label,
        bytes: Uint8Array.from(raw),
    }));
    corpus.push({ label: "nesting depth 63", bytes: nestedSequences(63) });
    corpus.push({ label: "nesting depth 64", bytes: nestedSequences(64) });
    corpus.push({ label: "nesting depth 65", bytes: nestedSequences(65) });
    const longPayload = new Uint8Array(200).fill(0xab);
    const longChild = new Uint8Array(3 + longPayload.length);
    longChild[0] = 0x04;
    longChild[1] = 0x81;
    longChild[2] = 0xc8;
    longChild.set(longPayload, 3);
    corpus.push({ label: "minimal long-form lengths", bytes: derSequence(longChild) });
    const seed = Uint8Array.of(
        0x30,
        0x0e,
        0x02,
        0x02,
        0x00,
        0x80,
        0x04,
        0x04,
        0x01,
        0x02,
        0x03,
        0x04,
        0x30,
        0x02,
        0x05,
        0x00
    );
    corpus.push({ label: "seed sequence", bytes: seed });
    for (let count = 0; count < 20; count++) {
        const children: asn1js.Integer[] = [];
        for (let value = 0; value < count; value++) {
            children.push(new asn1js.Integer({ value: value % 2 === 0 ? value : -value }));
        }
        corpus.push({
            label: `sequence of ${count.toString()} integers`,
            bytes: new Uint8Array(new asn1js.Sequence({ value: children }).toBER(false)),
        });
    }
    for (let offset = 1; offset < seed.length; offset++) {
        for (const octet of [0x00, 0x01, 0x80, 0x81, 0xff]) {
            const mutated = seed.slice();
            mutated[offset] = octet;
            corpus.push({
                label: `seed byte ${offset.toString()} -> ${octet.toString(16)}`,
                bytes: mutated,
            });
        }
    }
    for (let end = 1; end < seed.length; end++) {
        corpus.push({ label: `seed truncated to ${end.toString()}`, bytes: seed.slice(0, end) });
    }
    return corpus;
}

describe("canonical DER entry-point differential (drift guard)", () => {
    it("agrees between parseCanonicalDERSequenceTree and parseCanonicalDERValue on every corpus input", () => {
        const corpus = buildDifferentialCorpus();
        expect(corpus.length).toBeGreaterThan(100);
        for (const { label, bytes } of corpus) {
            for (const budgetSize of [1, 2, 8, 1024]) {
                const reference = captureOutcome(parseCanonicalDERSequenceTree, bytes, budgetSize);
                const candidate = captureOutcome(parseCanonicalDERValue, bytes, budgetSize);
                expect(
                    candidate,
                    `${label} (budget ${budgetSize.toString()}, ${hexOf(bytes)})`
                ).toEqual(reference);
            }
        }
    });

    it("pins non-SEQUENCE-root behavior: value accepts, sequence tree rejects", () => {
        const roots = [
            Uint8Array.of(0x04, 0x02, 0x01, 0x02),
            Uint8Array.of(0x03, 0x02, 0x07, 0x80),
            Uint8Array.of(0x02, 0x01, 0x01),
        ];
        for (const bytes of roots) {
            expect(captureOutcome(parseCanonicalDERValue, bytes, 8).ok).toBe(true);
            const rejected = captureOutcome(parseCanonicalDERSequenceTree, bytes, 8);
            expect(rejected.ok).toBe(false);
            if (!rejected.ok) {
                expect(rejected.message).toContain("expected canonical DER SEQUENCE tag");
            }
        }
    });
});
