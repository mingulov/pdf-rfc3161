import * as asn1js from "asn1js";
import { MAX_DER_DEPTH, MAX_DER_NODES } from "../constants.js";
import { TimestampError, TimestampErrorCode } from "../types.js";
import { toArrayBuffer } from "../utils.js";

function invalidResponse(message: string): TimestampError {
    return new TimestampError(TimestampErrorCode.INVALID_RESPONSE, message);
}

/**
 * Mutable node budget shared across nested DER decodings. Each parsed TLV
 * consumes one node; exhaustion rejects with `INVALID_RESPONSE` before any
 * recursive decoder runs. Pass one budget through an outer value and its
 * nested OCTET STRING payloads to bound the aggregate instead of each layer.
 */
export interface DerDecodeBudget {
    remainingNodes: number;
    /**
     * Allowance the budget started with, cited when it exhausts. Budgets
     * from createDerDecodeBudget always record it; hand-built budgets
     * without it fall back to MAX_DER_NODES in the message.
     */
    initialNodes?: number;
}

/** Creates a fresh node budget (default: one full `MAX_DER_NODES` allowance). */
export function createDerDecodeBudget(maxNodes: number = MAX_DER_NODES): DerDecodeBudget {
    if (!Number.isSafeInteger(maxNodes) || maxNodes <= 0) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_ARGUMENT,
            `DER node budget must be a positive safe integer (got ${String(maxNodes)})`
        );
    }
    return { remainingNodes: maxNodes, initialNodes: maxNodes };
}

function consumeDerNode(budget: DerDecodeBudget, description: string): void {
    if (!Number.isSafeInteger(budget.remainingNodes) || budget.remainingNodes <= 0) {
        throw invalidResponse(
            `${description}: ASN.1 node count exceeds the supported limit of ${(budget.initialNodes ?? MAX_DER_NODES).toString()} nodes`
        );
    }
    budget.remainingNodes -= 1;
}

interface ParsedTag {
    contentOffset: number;
    constructed: boolean;
    tagClass: number;
    tagNumber: number;
}

function parseCanonicalDerTag(bytes: Uint8Array, offset: number, description: string): ParsedTag {
    const firstTag = bytes[offset];
    if (firstTag === undefined) throw invalidResponse(`${description}: ASN.1 tag is truncated`);
    if (firstTag === 0) throw invalidResponse(`${description}: DER must not contain end-of-contents`);

    let contentOffset = offset + 1;
    if ((firstTag & 0x1f) !== 0x1f) {
        return {
            contentOffset,
            constructed: (firstTag & 0x20) !== 0,
            tagClass: firstTag >>> 6,
            tagNumber: firstTag & 0x1f,
        };
    }

    let tagNumber = 0;
    let tagOctets = 0;
    let hasContinuation = true;
    while (hasContinuation) {
        if (contentOffset >= bytes.length || tagOctets >= 6) {
            throw invalidResponse(`${description}: ASN.1 high-tag-number is truncated`);
        }
        const octet = bytes[contentOffset];
        if (octet === undefined) {
            throw invalidResponse(`${description}: ASN.1 high-tag-number is truncated`);
        }
        if (tagOctets === 0 && (octet & 0x7f) === 0) {
            throw invalidResponse(`${description}: non-minimal DER tag encoding`);
        }
        tagNumber = tagNumber * 0x80 + (octet & 0x7f);
        if (!Number.isSafeInteger(tagNumber)) {
            throw invalidResponse(`${description}: ASN.1 tag number is too large`);
        }
        contentOffset++;
        tagOctets++;
        hasContinuation = (octet & 0x80) !== 0;
    }
    if (tagNumber < 31) throw invalidResponse(`${description}: non-minimal DER tag encoding`);
    return {
        contentOffset,
        constructed: (firstTag & 0x20) !== 0,
        tagClass: firstTag >>> 6,
        tagNumber,
    };
}

function validateCanonicalIntegerEncoding(
    tag: ParsedTag,
    bytes: Uint8Array,
    contentOffset: number,
    contentEnd: number,
    description: string
): void {
    // The DER primitive-value rules below are deliberately limited to
    // INTEGER and ENUMERATED. Generic TLV framing alone is insufficient for
    // these signed two's-complement values, while this helper does not claim
    // unrelated DER canonical properties such as SET ordering.
    if (tag.tagClass !== 0 || (tag.tagNumber !== 2 && tag.tagNumber !== 10)) return;

    const typeName = tag.tagNumber === 2 ? "INTEGER" : "ENUMERATED";
    if (tag.constructed) {
        throw invalidResponse(`${description}: DER ${typeName} must be primitive`);
    }

    const contentLength = contentEnd - contentOffset;
    if (contentLength === 0) {
        throw invalidResponse(`${description}: DER ${typeName} must not be empty`);
    }
    if (contentLength === 1) return;

    const firstOctet = bytes[contentOffset];
    const secondOctet = bytes[contentOffset + 1];
    if (firstOctet === undefined || secondOctet === undefined) {
        throw invalidResponse(`${description}: DER ${typeName} content is truncated`);
    }
    if (
        (firstOctet === 0 && (secondOctet & 0x80) === 0) ||
        (firstOctet === 0xff && (secondOctet & 0x80) !== 0)
    ) {
        throw invalidResponse(`${description}: non-minimal DER ${typeName} encoding`);
    }
}

function parseCanonicalDerLength(
    bytes: Uint8Array,
    offset: number,
    limit: number,
    description: string
): { contentOffset: number; contentLength: number } {
    const firstLength = bytes[offset];
    if (firstLength === undefined) throw invalidResponse(`${description}: ASN.1 length is truncated`);
    const contentOffset = offset + 1;
    if (firstLength < 0x80) return { contentOffset, contentLength: firstLength };
    if (firstLength === 0x80) {
        throw invalidResponse(`${description}: indefinite-length BER is not permitted`);
    }

    const lengthOctets = firstLength & 0x7f;
    if (lengthOctets > 6 || contentOffset + lengthOctets > limit) {
        throw invalidResponse(`${description}: ASN.1 length is truncated`);
    }
    const firstLengthOctet = bytes[contentOffset];
    if (firstLengthOctet === undefined || firstLengthOctet === 0) {
        throw invalidResponse(`${description}: non-minimal DER length encoding`);
    }

    let contentLength = 0;
    for (let index = 0; index < lengthOctets; index++) {
        const octet = bytes[contentOffset + index];
        if (octet === undefined) throw invalidResponse(`${description}: ASN.1 length is truncated`);
        contentLength = contentLength * 0x100 + octet;
    }
    if (contentLength < 0x80) {
        throw invalidResponse(`${description}: non-minimal DER length encoding`);
    }
    return { contentOffset: contentOffset + lengthOctets, contentLength };
}

interface DerPreflightFrame {
    contentEnd: number;
    nextChildOffset: number;
    childDepth: number;
}

/**
 * Iteratively validates canonical TLV framing for a whole DER tree. The old
 * recursive walk threw an uncategorized `RangeError` on deeply nested input;
 * this explicit stack instead enforces `MAX_DER_DEPTH` levels of nesting
 * (the outermost TLV counts as level 1) and consumes the shared node budget,
 * so hostile input fails with `INVALID_RESPONSE` before any recursive
 * decoder runs. All offsets stay relative to the input view, so sliced
 * `Uint8Array` windows validate exactly the bytes they span.
 */
function validateCanonicalDerTree(
    bytes: Uint8Array,
    offset: number,
    limit: number,
    description: string,
    budget: DerDecodeBudget
): number {
    const rootTag = parseCanonicalDerTag(bytes, offset, description);
    const rootLength = parseCanonicalDerLength(bytes, rootTag.contentOffset, limit, description);
    const rootContentEnd = rootLength.contentOffset + rootLength.contentLength;
    if (!Number.isSafeInteger(rootContentEnd) || rootContentEnd > limit) {
        throw invalidResponse(`${description}: ASN.1 content is truncated`);
    }
    validateCanonicalIntegerEncoding(
        rootTag,
        bytes,
        rootLength.contentOffset,
        rootContentEnd,
        description
    );
    consumeDerNode(budget, description);
    if (!rootTag.constructed) {
        return rootContentEnd;
    }

    const stack: DerPreflightFrame[] = [
        {
            contentEnd: rootContentEnd,
            nextChildOffset: rootLength.contentOffset,
            childDepth: 2,
        },
    ];
    while (stack.length > 0) {
        const frame = stack[stack.length - 1];
        if (frame === undefined) {
            throw invalidResponse(`${description}: ASN.1 preflight reached an invalid state`);
        }
        if (frame.nextChildOffset === frame.contentEnd) {
            stack.pop();
            continue;
        }
        if (frame.nextChildOffset > frame.contentEnd) {
            throw invalidResponse(`${description}: ASN.1 child bytes are truncated`);
        }
        if (frame.childDepth > MAX_DER_DEPTH) {
            throw invalidResponse(
                `${description}: ASN.1 nesting depth exceeds the supported limit of ${MAX_DER_DEPTH.toString()} levels`
            );
        }
        const tag = parseCanonicalDerTag(bytes, frame.nextChildOffset, description);
        const length = parseCanonicalDerLength(
            bytes,
            tag.contentOffset,
            frame.contentEnd,
            description
        );
        const contentEnd = length.contentOffset + length.contentLength;
        if (!Number.isSafeInteger(contentEnd) || contentEnd > frame.contentEnd) {
            throw invalidResponse(`${description}: ASN.1 content is truncated`);
        }
        validateCanonicalIntegerEncoding(tag, bytes, length.contentOffset, contentEnd, description);
        consumeDerNode(budget, description);
        if (contentEnd <= frame.nextChildOffset) {
            throw invalidResponse(`${description}: ASN.1 child does not advance`);
        }
        frame.nextChildOffset = contentEnd;
        if (tag.constructed) {
            stack.push({
                contentEnd,
                nextChildOffset: length.contentOffset,
                childDepth: frame.childDepth + 1,
            });
        }
    }
    return rootContentEnd;
}

/** Surfaces a short decoder diagnostic (for example a nested node-limit hit). */
function decoderDetail(parsed: { result?: { error?: unknown } }): string {
    const error: unknown = parsed.result?.error;
    if (typeof error !== "string" || error.length === 0) return "";
    return ` (${error.slice(0, 200)})`;
}

/**
 * Parses one complete DER SEQUENCE after iteratively validating canonical
 * TLV framing for every constructed child.
 *
 * This checks tag and length minimality, definite lengths, and child boundaries.
 * It deliberately does not claim full value canonicalization such as SET sorting;
 * callers remain responsible for ASN.1 schema and semantic checks.
 *
 * Nesting beyond `MAX_DER_DEPTH` levels and node counts beyond the budget
 * reject with `INVALID_RESPONSE` during the iterative preflight, before the
 * recursive ASN.1 decoder runs. Pass `options.budget` to bound an outer
 * value and its nested payloads against one shared allowance.
 */
export function parseCanonicalDERSequenceTree(
    bytes: Uint8Array,
    description: string,
    options: { budget?: DerDecodeBudget } = {}
): asn1js.BaseBlock {
    if (bytes[0] !== 0x30) {
        throw invalidResponse(`${description}: expected canonical DER SEQUENCE tag`);
    }
    // Self-contained on purpose: delegating to parseCanonicalDERValue
    // would keep that strict-side-only export reachable from the main
    // bundle (ltv.ts uses this function) and break tree-shaking.
    const budget = options.budget ?? createDerDecodeBudget();
    const end = validateCanonicalDerTree(bytes, 0, bytes.length, description, budget);
    if (end !== bytes.length) {
        throw invalidResponse(`${description}: trailing bytes are not permitted`);
    }

    // asn1js throws a plain Error on undecodable content (e.g. corrupted
    // GeneralizedTime); normalize it like the offset failure below.
    let parsed: ReturnType<typeof asn1js.fromBER>;
    try {
        parsed = asn1js.fromBER(toArrayBuffer(bytes));
    } catch {
        throw invalidResponse(`${description}: ASN.1 parse failed`);
    }
    if (parsed.offset === -1) {
        throw invalidResponse(`${description}: ASN.1 parse failed${decoderDetail(parsed)}`);
    }
    if (parsed.offset !== bytes.length) {
        throw invalidResponse(`${description}: trailing bytes are not permitted`);
    }
    return parsed.result;
}

/**
 * Parses one complete DER value with any root tag after iteratively
 * validating canonical TLV framing for the whole tree.
 *
 * Same preflight as parseCanonicalDERSequenceTree (tag and length
 * minimality, definite lengths, child boundaries, INTEGER/ENUMERATED
 * minimality, depth and node budgets), but without the SEQUENCE-root
 * requirement: extension payloads such as the nonce OCTET STRING and
 * the key usage BIT STRING are opaque to the outer preflight (their
 * OCTET STRING wrapper is primitive), so each gets its own canonical
 * framing and complete-consumption gate here. Callers remain
 * responsible for ASN.1 schema and semantic checks.
 */
export function parseCanonicalDERValue(
    bytes: Uint8Array,
    description: string,
    options: { budget?: DerDecodeBudget } = {}
): asn1js.BaseBlock {
    const budget = options.budget ?? createDerDecodeBudget();
    const end = validateCanonicalDerTree(bytes, 0, bytes.length, description, budget);
    if (end !== bytes.length) {
        throw invalidResponse(`${description}: trailing bytes are not permitted`);
    }

    // asn1js throws a plain Error on undecodable content (e.g. corrupted
    // GeneralizedTime); normalize it like the offset failure below.
    let parsed: ReturnType<typeof asn1js.fromBER>;
    try {
        parsed = asn1js.fromBER(toArrayBuffer(bytes));
    } catch {
        throw invalidResponse(`${description}: ASN.1 parse failed`);
    }
    if (parsed.offset === -1) {
        throw invalidResponse(`${description}: ASN.1 parse failed${decoderDetail(parsed)}`);
    }
    if (parsed.offset !== bytes.length) {
        throw invalidResponse(`${description}: trailing bytes are not permitted`);
    }
    return parsed.result;
}

/**
 * Ensures a schema decoder preserved every byte in a complete DER value.
 *
 * Canonical framing establishes that a value is a complete DER TLV tree, but
 * a higher-level schema decoder can still ignore an unknown child. Candidate
 * collectors use this after their exact outer grammar checks to reject that
 * lossy decoding rather than embedding bytes they did not fully recognize.
 */
export function requireSchemaRoundTrip(
    original: Uint8Array,
    reconstructed: ArrayBuffer,
    description: string
): void {
    const roundTripped = new Uint8Array(reconstructed);
    if (roundTripped.length !== original.length) {
        throw invalidResponse(`${description}: ASN.1 schema does not consume the complete value`);
    }
    for (let index = 0; index < original.length; index++) {
        if (roundTripped[index] !== original[index]) {
            throw invalidResponse(`${description}: ASN.1 schema does not preserve the complete value`);
        }
    }
}
