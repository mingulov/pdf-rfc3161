import * as asn1js from "asn1js";
import { TimestampError, TimestampErrorCode } from "../types.js";
import { toArrayBuffer } from "../utils.js";

function invalidResponse(message: string): TimestampError {
    return new TimestampError(TimestampErrorCode.INVALID_RESPONSE, message);
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

function validateCanonicalDerTlv(
    bytes: Uint8Array,
    offset: number,
    limit: number,
    description: string
): number {
    const tag = parseCanonicalDerTag(bytes, offset, description);
    const length = parseCanonicalDerLength(bytes, tag.contentOffset, limit, description);
    const contentEnd = length.contentOffset + length.contentLength;
    if (!Number.isSafeInteger(contentEnd) || contentEnd > limit) {
        throw invalidResponse(`${description}: ASN.1 content is truncated`);
    }

    validateCanonicalIntegerEncoding(tag, bytes, length.contentOffset, contentEnd, description);

    if (tag.constructed) {
        let childOffset = length.contentOffset;
        while (childOffset < contentEnd) {
            const nextChildOffset = validateCanonicalDerTlv(
                bytes,
                childOffset,
                contentEnd,
                description
            );
            if (nextChildOffset <= childOffset) {
                throw invalidResponse(`${description}: ASN.1 child does not advance`);
            }
            childOffset = nextChildOffset;
        }
        if (childOffset !== contentEnd) {
            throw invalidResponse(`${description}: ASN.1 child bytes are truncated`);
        }
    }
    return contentEnd;
}

/**
 * Parses one complete DER SEQUENCE after recursively validating canonical
 * TLV framing for every constructed child.
 *
 * This checks tag and length minimality, definite lengths, and child boundaries.
 * It deliberately does not claim full value canonicalization such as SET sorting;
 * callers remain responsible for ASN.1 schema and semantic checks.
 */
export function parseCanonicalDERSequenceTree(
    bytes: Uint8Array,
    description: string
): asn1js.BaseBlock {
    if (bytes[0] !== 0x30) {
        throw invalidResponse(`${description}: expected canonical DER SEQUENCE tag`);
    }
    const end = validateCanonicalDerTlv(bytes, 0, bytes.length, description);
    if (end !== bytes.length) {
        throw invalidResponse(`${description}: trailing bytes are not permitted`);
    }

    const parsed = asn1js.fromBER(toArrayBuffer(bytes));
    if (parsed.offset === -1) throw invalidResponse(`${description}: ASN.1 parse failed`);
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
