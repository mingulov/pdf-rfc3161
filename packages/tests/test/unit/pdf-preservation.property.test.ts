import { describe, expect, it, beforeAll } from "vitest";
import * as fc from "fast-check";
import { createHash } from "node:crypto";
import { preparePdfForTimestamp, type PreparedPDF } from "../../../core/src/pdf/prepare.js";
import { embedTimestampToken, extractBytesToHash } from "../../../core/src/pdf/embed.js";
import { extractTimestamps, verifyPdfTimestamps } from "../../../core/src/pdf/extract.js";
import { createTimestampRequest } from "../../../core/src/tsa/request.js";
import { createRFC3161TokenFixtureFromRequest } from "../fixtures/rfc3161-token.js";

// T14: deterministic PDF preservation properties.
//
// Prefix preservation (byte-identical prefix), exact ByteRange hole
// arithmetic, and multi-revision tamper separation -- all over real
// prepared PDFs with real CMS tokens. Independent oracles: a
// hand-rolled /ByteRange parser, a hand-rolled DER walk to the TSTInfo
// imprint, and node:crypto digests. Fixture TSA keys are generated
// once per file inside the fixture module, never per generated case.

const SEED_PP_GEOMETRY = 14011;
const SEED_PP_TAMPER = 14012;
const GEOMETRY_RUNS = 24;
const TAMPER_RUNS = 24;

type ByteRange = [number, number, number, number];

const ASCII_ZERO = 0x30;
const ASCII_LT = 0x3c;
const ASCII_GT = 0x3e;

// ---------------------------------------------------------------------------
// Deterministic base-PDF builder with computed xref (no hand offsets).
// ---------------------------------------------------------------------------

interface BasePdf {
    bytes: Uint8Array;
    /** Offset of the first content-stream byte (parse-safe tamper site). */
    streamContentOffset: number;
    streamLength: number;
}

function buildBasePdf(streamContent: Uint8Array): BasePdf {
    const encoder = new TextEncoder();
    const chunks: Uint8Array[] = [];
    const pushText = (text: string): void => {
        chunks.push(encoder.encode(text));
    };
    const pushBytes = (bytes: Uint8Array): void => {
        chunks.push(bytes);
    };
    const currentLength = (): number => chunks.reduce((sum, chunk) => sum + chunk.length, 0);

    pushText("%PDF-1.4\n");
    const offsets: number[] = [0];
    const bodies = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents 4 0 R >>",
    ];
    for (let index = 0; index < bodies.length; index++) {
        offsets.push(currentLength());
        pushText(`${(index + 1).toString(10)} 0 obj\n${bodies[index] ?? ""}\nendobj\n`);
    }
    offsets.push(currentLength());
    pushText(`4 0 obj\n<< /Length ${streamContent.length.toString(10)} >>\nstream\n`);
    const streamContentOffset = currentLength();
    pushBytes(streamContent);
    pushText("\nendstream\nendobj\n");

    const xrefPosition = currentLength();
    pushText(`xref\n0 5\n`);
    for (const offset of offsets) {
        pushText(`${offset.toString(10).padStart(10, "0")} 00000 n \n`);
    }
    pushText(`trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n${xrefPosition.toString(10)}\n%%EOF`);

    const total = currentLength();
    const bytes = new Uint8Array(total);
    let cursor = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, cursor);
        cursor += chunk.length;
    }
    // Fix the object-0 entry to the free-head form (10 zeros + f).
    const xrefStart = xrefPosition + "xref\n0 5\n".length;
    const freeHead = encoder.encode("0000000000 65535 f \n");
    bytes.set(freeHead, xrefStart);
    return { bytes, streamContentOffset, streamLength: streamContent.length };
}

// ---------------------------------------------------------------------------
// Hand-rolled /ByteRange parser (independent oracle: raw byte scan).
// ---------------------------------------------------------------------------

const BYTERANGE_NEEDLE = new TextEncoder().encode("/ByteRange[");

function isAsciiDigit(byte: number): boolean {
    return byte >= 0x30 && byte <= 0x39;
}

/** Parses the LAST /ByteRange[...] array from raw PDF bytes. */
function handParseByteRange(pdf: Uint8Array): ByteRange {
    let start = -1;
    for (let index = 0; index + BYTERANGE_NEEDLE.length <= pdf.length; index++) {
        let match = true;
        for (let needle = 0; needle < BYTERANGE_NEEDLE.length; needle++) {
            if (pdf[index + needle] !== BYTERANGE_NEEDLE[needle]) {
                match = false;
                break;
            }
        }
        if (match) start = index;
    }
    if (start < 0) throw new Error("hand ByteRange: no /ByteRange[ found");
    let cursor = start + BYTERANGE_NEEDLE.length;
    const values: number[] = [];
    while (values.length < 4) {
        while (cursor < pdf.length && pdf[cursor] === 0x20) cursor++;
        const digitStart = cursor;
        while (cursor < pdf.length && isAsciiDigit(pdf[cursor] ?? 0)) cursor++;
        if (cursor === digitStart) throw new Error("hand ByteRange: expected integer");
        const text = new TextDecoder("ascii").decode(pdf.subarray(digitStart, cursor));
        const value = Number(text);
        if (!Number.isSafeInteger(value) || value < 0) {
            throw new Error("hand ByteRange: bad integer");
        }
        values.push(value);
    }
    while (cursor < pdf.length && pdf[cursor] === 0x20) cursor++;
    if (pdf[cursor] !== 0x5d) throw new Error("hand ByteRange: unterminated array");
    const [a, b, c, d] = [values[0], values[1], values[2], values[3]];
    if (a === undefined || b === undefined || c === undefined || d === undefined) {
        throw new Error("hand ByteRange: missing values");
    }
    return [a, b, c, d];
}

function handCoveredBytes(pdf: Uint8Array, range: ByteRange): Uint8Array {
    const [offset1, length1, offset2, length2] = range;
    if (offset1 + length1 > pdf.length || offset2 + length2 > pdf.length) {
        throw new Error("hand ByteRange: range overruns file");
    }
    const out = new Uint8Array(length1 + length2);
    out.set(pdf.subarray(offset1, offset1 + length1), 0);
    out.set(pdf.subarray(offset2, offset2 + length2), length1);
    return out;
}

// ---------------------------------------------------------------------------
// Hand-rolled DER walk to the TSTInfo imprint (independent oracle).
// ---------------------------------------------------------------------------

interface DerNode {
    tagClass: number;
    constructed: boolean;
    tagNumber: number;
    length: number;
    valueOffset: number;
    totalLength: number;
}

function readDerNode(bytes: Uint8Array, offset: number): DerNode {
    const tagByte = bytes[offset];
    if (tagByte === undefined) throw new Error("hand DER: truncated tag");
    const tagClass = (tagByte & 0xc0) >> 6;
    const constructed = (tagByte & 0x20) !== 0;
    let tagNumber = tagByte & 0x1f;
    let cursor = offset + 1;
    if (tagNumber === 0x1f) {
        tagNumber = 0;
        for (let index = 0; index < 4; index++) {
            const next = bytes[cursor];
            if (next === undefined) throw new Error("hand DER: truncated high tag");
            cursor++;
            tagNumber = tagNumber * 128 + (next & 0x7f);
            if ((next & 0x80) === 0) break;
            if (index === 3) throw new Error("hand DER: tag number too large");
        }
    }
    const lengthByte = bytes[cursor];
    if (lengthByte === undefined) throw new Error("hand DER: truncated length");
    cursor++;
    let length = 0;
    if (lengthByte < 0x80) {
        length = lengthByte;
    } else {
        if (lengthByte === 0x80) throw new Error("hand DER: indefinite length rejected");
        const octets = lengthByte & 0x7f;
        if (octets < 1 || octets > 4) throw new Error("hand DER: bad length octets");
        for (let index = 0; index < octets; index++) {
            const octet = bytes[cursor];
            if (octet === undefined) throw new Error("hand DER: truncated long length");
            cursor++;
            length = length * 256 + octet;
        }
    }
    if (cursor + length > bytes.length) throw new Error("hand DER: value overruns input");
    return {
        tagClass,
        constructed,
        tagNumber,
        length,
        valueOffset: cursor,
        totalLength: cursor + length - offset,
    };
}

function derChildren(bytes: Uint8Array, node: DerNode): DerNode[] {
    if (!node.constructed) throw new Error("hand DER: primitive has no children");
    const out: DerNode[] = [];
    let cursor = node.valueOffset;
    const end = node.valueOffset + node.length;
    while (cursor < end) {
        const child = readDerNode(bytes, cursor);
        out.push(child);
        cursor += child.totalLength;
    }
    if (cursor !== end) throw new Error("hand DER: child overrun");
    return out;
}

/** Extracts the TSTInfo message-imprint digest from a raw ContentInfo token. */
function handTstImprint(token: Uint8Array): Uint8Array {
    const outer = readDerNode(token, 0);
    const ciKids = derChildren(token, outer);
    const explicit = ciKids[1];
    if (explicit === undefined) throw new Error("hand DER: ContentInfo shape");
    const signedData = derChildren(token, explicit)[0];
    if (signedData === undefined) throw new Error("hand DER: missing SignedData");
    const encap = derChildren(token, signedData)[2];
    if (encap === undefined) throw new Error("hand DER: missing encapContentInfo");
    const eContentExplicit = derChildren(token, encap)[1];
    if (eContentExplicit === undefined) throw new Error("hand DER: missing eContent");
    const eContent = derChildren(token, eContentExplicit)[0];
    if (eContent?.tagClass !== 0 || eContent.tagNumber !== 4) {
        throw new Error("hand DER: eContent is not an OCTET STRING");
    }
    let tstInfoBytes = token.slice(eContent.valueOffset, eContent.valueOffset + eContent.length);
    if (eContent.constructed) {
        const segments = derChildren(token, eContent);
        let total = 0;
        for (const segment of segments) total += segment.length;
        const joined = new Uint8Array(total);
        let cursor = 0;
        for (const segment of segments) {
            joined.set(
                token.subarray(segment.valueOffset, segment.valueOffset + segment.length),
                cursor
            );
            cursor += segment.length;
        }
        tstInfoBytes = joined;
    }
    const tstOuter = readDerNode(tstInfoBytes, 0);
    const imprint = derChildren(tstInfoBytes, tstOuter)[2];
    if (imprint === undefined) throw new Error("hand DER: TSTInfo shape");
    const digestNode = derChildren(tstInfoBytes, imprint)[1];
    if (digestNode?.tagClass !== 0 || digestNode.tagNumber !== 4 || digestNode.constructed) {
        throw new Error("hand DER: imprint digest shape");
    }
    return tstInfoBytes.slice(digestNode.valueOffset, digestNode.valueOffset + digestNode.length);
}

function bytesToUpperHex(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("hex").toUpperCase();
}

interface BoundRange {
    tag: string;
    /** Token-byte offsets (half-open) inside the raw ContentInfo token. */
    start: number;
    end: number;
}

/**
 * Locates the cryptographically bound regions of a raw token: the TSTInfo
 * eContent segments (covered by the CMS message-digest), the embedded
 * certificates (covered by the ESS signing-certificate hash under strict
 * ESS validation), and the signedAttrs + signatureValue (covered by the
 * CMS signature). Flips anywhere inside these ranges must invalidate the
 * revision. Unsigned metadata (CMS versions, digest algorithm SET
 * framing) is deliberately excluded: flipping it is malleability, not
 * forgery, and the property must not demand its rejection.
 */
function handBoundRanges(token: Uint8Array): BoundRange[] {
    const ranges: BoundRange[] = [];
    const outer = readDerNode(token, 0);
    const ciKids = derChildren(token, outer);
    const explicit = ciKids[1];
    if (explicit === undefined) throw new Error("hand DER: ContentInfo shape");
    const signedData = derChildren(token, explicit)[0];
    if (signedData === undefined) throw new Error("hand DER: missing SignedData");
    const sdKids = derChildren(token, signedData);
    const encap = sdKids[2];
    if (encap === undefined) throw new Error("hand DER: missing encapContentInfo");
    const eContentExplicit = derChildren(token, encap)[1];
    if (eContentExplicit === undefined) throw new Error("hand DER: missing eContent");
    const eContent = derChildren(token, eContentExplicit)[0];
    if (eContent?.tagClass !== 0 || eContent.tagNumber !== 4) {
        throw new Error("hand DER: eContent shape");
    }
    if (eContent.constructed) {
        for (const segment of derChildren(token, eContent)) {
            ranges.push({
                tag: "tstinfo",
                start: segment.valueOffset,
                end: segment.valueOffset + segment.length,
            });
        }
    } else {
        ranges.push({
            tag: "tstinfo",
            start: eContent.valueOffset,
            end: eContent.valueOffset + eContent.length,
        });
    }
    for (const child of sdKids) {
        if (child.tagClass === 2 && child.tagNumber === 0 && child.constructed) {
            ranges.push({
                tag: "certs",
                start: child.valueOffset,
                end: child.valueOffset + child.length,
            });
        }
    }
    // signerInfos is the last SignedData child (a SET like digestAlgorithms).
    const last = sdKids[sdKids.length - 1];
    if (last?.tagClass !== 0 || last.tagNumber !== 17) {
        throw new Error("hand DER: missing signerInfos");
    }
    const signerInfo = derChildren(token, last)[0];
    if (signerInfo === undefined) throw new Error("hand DER: SignerInfo shape");
    for (const siChild of derChildren(token, signerInfo)) {
        if (siChild.tagClass === 2 && siChild.tagNumber === 0 && siChild.constructed) {
            ranges.push({
                tag: "signedAttrs",
                start: siChild.valueOffset,
                end: siChild.valueOffset + siChild.length,
            });
        }
        if (siChild.tagClass === 0 && siChild.tagNumber === 4 && !siChild.constructed) {
            ranges.push({
                tag: "signature",
                start: siChild.valueOffset,
                end: siChild.valueOffset + siChild.length,
            });
        }
    }
    const tags = new Set(ranges.map((range) => range.tag));
    for (const tag of ["tstinfo", "certs", "signedAttrs", "signature"]) {
        if (!tags.has(tag)) throw new Error(`hand DER: token has no ${tag} region`);
        const tagged = ranges.filter((range) => range.tag === tag);
        for (const range of tagged) {
            if (range.end <= range.start) throw new Error(`hand DER: empty ${tag} region`);
        }
    }
    return ranges;
}

// ---------------------------------------------------------------------------
// Generators: geometry inputs (valid structures).
// ---------------------------------------------------------------------------

const FIELD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".split("");

const geometryArb = fc.record({
    streamContent: fc.uint8Array({ minLength: 16, maxLength: 128 }),
    signatureSize: fc.integer({ min: 4096, max: 16384 }),
    fieldName: fc
        .array(fc.constantFrom(...FIELD_ALPHABET), { minLength: 1, maxLength: 10 })
        .map((chars) => `T${chars.join("")}`),
});

// ---------------------------------------------------------------------------
// Generators: multi-revision tampers (separate from valid geometry).
// ---------------------------------------------------------------------------

const tamperKindArb = fc.constantFrom("rev1-covered", "rev1-hole", "rev2-hole") as fc.Arbitrary<
    "rev1-covered" | "rev1-hole" | "rev2-hole"
>;

const tamperArb = fc.record({
    baseVariant: fc.integer({ min: 0, max: 1 }),
    kind: tamperKindArb,
    positionSalt: fc.integer({ min: 0, max: 1000000 }),
});

interface TwoRevisionBase {
    signed: Uint8Array;
    field1: string;
    field2: string;
    contentsOffset1: number;
    boundRanges1: BoundRange[];
    contentsOffset2: number;
    boundRanges2: BoundRange[];
    streamContentOffset: number;
    streamLength: number;
}

const TWO_REVISION_BASES: TwoRevisionBase[] = [];

async function signRevision(
    pdf: Uint8Array,
    signatureSize: number,
    fieldName: string
): Promise<{ signed: Uint8Array; prepared: PreparedPDF; token: Uint8Array }> {
    const prepared = await preparePdfForTimestamp(pdf, {
        signatureSize,
        signatureFieldName: fieldName,
    });
    const covered = extractBytesToHash(prepared);
    const { request } = await createTimestampRequest(covered, { hashAlgorithm: "SHA-256" });
    const fixture = await createRFC3161TokenFixtureFromRequest(request);
    const signed = embedTimestampToken(prepared, fixture.rawToken);
    return { signed, prepared, token: fixture.rawToken };
}

function flipHexChar(byte: number): number {
    return byte === ASCII_ZERO ? 0x66 : ASCII_ZERO;
}

describe("pdf preservation properties (T14)", () => {
    it("preserves the prefix and cuts an exact ByteRange hole across generated PDFs", async () => {
        const seenSizes = new Set<number>();
        const seenNames = new Set<string>();

        await fc.assert(
            fc.asyncProperty(geometryArb, async (input) => {
                seenSizes.add(input.signatureSize);
                seenNames.add(input.fieldName);

                const base = buildBasePdf(input.streamContent);
                const prepared = await preparePdfForTimestamp(base.bytes, {
                    signatureSize: input.signatureSize,
                    signatureFieldName: input.fieldName,
                });

                // Independent oracle 1: hand-parsed /ByteRange matches the
                // prepared range, and the hole arithmetic is exact.
                const wireRange = handParseByteRange(prepared.bytes);
                expect(wireRange).toEqual(prepared.byteRange);
                const holeStart = prepared.contentsOffset - 1;
                const holeEnd = prepared.contentsOffset + prepared.contentsPlaceholderLength + 1;
                expect(prepared.bytes[holeStart]).toBe(ASCII_LT);
                expect(prepared.bytes[holeEnd - 1]).toBe(ASCII_GT);
                expect(prepared.byteRange).toEqual([
                    0,
                    holeStart,
                    holeEnd,
                    prepared.bytes.length - holeEnd,
                ]);
                for (
                    let index = prepared.contentsOffset;
                    index < prepared.contentsOffset + prepared.contentsPlaceholderLength;
                    index++
                ) {
                    expect(prepared.bytes[index]).toBe(ASCII_ZERO);
                }

                // Independent oracle 2: hand-concatenated covered bytes
                // match the library extraction over the hand-parsed range.
                const handCovered = handCoveredBytes(prepared.bytes, wireRange);
                expect(handCovered).toEqual(extractBytesToHash(prepared));

                const { request } = await createTimestampRequest(handCovered, {
                    hashAlgorithm: "SHA-256",
                });
                const fixture = await createRFC3161TokenFixtureFromRequest(request);
                expect(fixture.rawToken.length * 2).toBeLessThanOrEqual(
                    prepared.contentsPlaceholderLength
                );
                const signed = embedTimestampToken(prepared, fixture.rawToken);

                // Prefix preservation: every byte outside the hole is
                // identical; the hole carries the token hex + zero padding.
                expect(signed.subarray(0, prepared.contentsOffset)).toEqual(
                    prepared.bytes.subarray(0, prepared.contentsOffset)
                );
                expect(signed.subarray(holeEnd)).toEqual(prepared.bytes.subarray(holeEnd));
                const embeddedHex = new TextDecoder("ascii").decode(
                    signed.subarray(
                        prepared.contentsOffset,
                        prepared.contentsOffset + prepared.contentsPlaceholderLength
                    )
                );
                expect(embeddedHex).toBe(
                    bytesToUpperHex(fixture.rawToken).padEnd(
                        prepared.contentsPlaceholderLength,
                        "0"
                    )
                );

                // Independent oracle 3: the TSTInfo imprint (hand DER)
                // commits to the node:crypto digest of the covered bytes.
                const signedCovered = handCoveredBytes(signed, handParseByteRange(signed));
                expect(signedCovered).toEqual(handCovered);
                const expectedDigest = new Uint8Array(
                    createHash("sha256").update(signedCovered).digest()
                );
                expect(handTstImprint(fixture.rawToken)).toEqual(expectedDigest);

                // Library roundtrip on top of the independent oracles,
                // under the strict ESS binding profile.
                const extracted = await extractTimestamps(signed);
                expect(extracted.map((entry) => entry.fieldName)).toContain(input.fieldName);
                const verified = await verifyPdfTimestamps(signed, { strictESSValidation: true });
                expect(verified.length).toBeGreaterThan(0);
                expect(verified.every((entry) => entry.verified)).toBe(true);
            }),
            { seed: SEED_PP_GEOMETRY, numRuns: GEOMETRY_RUNS }
        );

        // No vacuous coverage: sizes and field names must vary.
        expect(seenSizes.size).toBeGreaterThan(1);
        expect(seenNames.size).toBeGreaterThan(1);
    }, 120000);

    describe("multi-revision tamper separation", () => {
        beforeAll(async () => {
            const variants = [
                new Uint8Array(64).map((_, index) => (index * 7 + 3) % 251),
                new Uint8Array(96).map((_, index) => (index * 13 + 29) % 251),
            ];
            for (let variant = 0; variant < variants.length; variant++) {
                const streamContent = variants[variant];
                if (streamContent === undefined) throw new Error("missing tamper variant");
                const base = buildBasePdf(streamContent);
                const field1 = `T14First${variant.toString(10)}`;
                const field2 = `T14Second${variant.toString(10)}`;
                const first = await signRevision(base.bytes, 8192, field1);
                // Incremental append: the second preparation keeps the
                // first signed revision byte-identical as its prefix.
                const secondPrepared = await preparePdfForTimestamp(first.signed, {
                    signatureSize: 8192,
                    signatureFieldName: field2,
                });
                expect(secondPrepared.bytes.subarray(0, first.signed.length)).toEqual(first.signed);
                const covered = extractBytesToHash(secondPrepared);
                const { request } = await createTimestampRequest(covered, {
                    hashAlgorithm: "SHA-256",
                });
                const fixture = await createRFC3161TokenFixtureFromRequest(request);
                const signed = embedTimestampToken(secondPrepared, fixture.rawToken);
                TWO_REVISION_BASES.push({
                    signed,
                    field1,
                    field2,
                    contentsOffset1: first.prepared.contentsOffset,
                    boundRanges1: handBoundRanges(first.token),
                    contentsOffset2: secondPrepared.contentsOffset,
                    boundRanges2: handBoundRanges(fixture.rawToken),
                    streamContentOffset: base.streamContentOffset,
                    streamLength: base.streamLength,
                });
            }
        });

        it("separates per-revision tamper verdicts across generated tampers", async () => {
            const seenKinds = new Set<string>();
            const seenVariants = new Set<number>();
            const seenRegions = new Set<string>();
            // Rotates hole tampers across bound regions so every region is
            // exercised regardless of the salt draw.
            let regionCounter = 0;
            const strict = { strictESSValidation: true };

            await fc.assert(
                fc.asyncProperty(tamperArb, async (input) => {
                    seenKinds.add(input.kind);
                    seenVariants.add(input.baseVariant);
                    const base = TWO_REVISION_BASES[input.baseVariant];
                    if (base === undefined) throw new Error("missing two-revision base");

                    // Untouched control first: both revisions verify, so a
                    // later failure is the tamper's doing, not the base's.
                    const control = await verifyPdfTimestamps(base.signed, strict);
                    expect(control).toHaveLength(2);
                    expect(control.every((entry) => entry.verified)).toBe(true);

                    const tampered = new Uint8Array(base.signed);
                    let tamperOffset: number;
                    if (input.kind === "rev1-covered") {
                        // Inside the base content stream: covered by both
                        // revisions, structurally inert.
                        tamperOffset =
                            base.streamContentOffset + (input.positionSalt % base.streamLength);
                        const original = tampered[tamperOffset] ?? 0;
                        tampered[tamperOffset] = (original + 1) % 256;
                    } else {
                        // Inside a cryptographically bound token region of
                        // revision 1 or 2: the tampered revision must fail
                        // while an untouched earlier revision must survive.
                        const holeBase =
                            input.kind === "rev1-hole"
                                ? {
                                      contentsOffset: base.contentsOffset1,
                                      ranges: base.boundRanges1,
                                  }
                                : {
                                      contentsOffset: base.contentsOffset2,
                                      ranges: base.boundRanges2,
                                  };
                        const range = holeBase.ranges[regionCounter % holeBase.ranges.length];
                        if (range === undefined) throw new Error("missing bound range");
                        regionCounter += 1;
                        seenRegions.add(range.tag);
                        const hexStart = holeBase.contentsOffset + range.start * 2;
                        const hexLength = (range.end - range.start) * 2;
                        tamperOffset = hexStart + (input.positionSalt % hexLength);
                        tampered[tamperOffset] = flipHexChar(tampered[tamperOffset] ?? ASCII_ZERO);
                    }
                    expect(tampered[tamperOffset]).not.toBe(base.signed[tamperOffset]);

                    const results = await verifyPdfTimestamps(tampered, strict);
                    const first = results.find((entry) => entry.fieldName === base.field1);
                    const second = results.find((entry) => entry.fieldName === base.field2);
                    // Discovery drops a Contents whose token no longer
                    // parses, so a hole-tampered revision is either absent
                    // or present-but-unverified -- never verified. A
                    // revision whose own bytes are untouched must still
                    // verify (separation).
                    if (input.kind === "rev2-hole") {
                        expect(first?.verified).toBe(true);
                        expect(!second?.verified).toBe(true);
                    } else if (input.kind === "rev1-hole") {
                        expect(second?.verified).toBe(false);
                        expect(second).toBeDefined();
                        expect(!first?.verified).toBe(true);
                    } else {
                        // Covered-byte tamper: both Contents stay intact,
                        // so both revisions are discovered and both fail.
                        expect(results).toHaveLength(2);
                        expect(first?.verified).toBe(false);
                        expect(second?.verified).toBe(false);
                    }
                }),
                { seed: SEED_PP_TAMPER, numRuns: TAMPER_RUNS }
            );

            expect([...seenKinds].sort()).toEqual(["rev1-covered", "rev1-hole", "rev2-hole"]);
            expect([...seenVariants].sort()).toEqual([0, 1]);
            expect([...seenRegions].sort()).toEqual([
                "certs",
                "signature",
                "signedAttrs",
                "tstinfo",
            ]);
        }, 120000);
    });
});
