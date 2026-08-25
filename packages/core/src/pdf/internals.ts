// Internal helpers for working around pdf-lib-incremental-save quirks.
// Not part of the public API.

import { PDFRef, type PDFObject } from "pdf-lib-incremental-save";
import pako from "pako";
import { MAX_PDF_SIZE } from "../constants.js";
import { TimestampError, TimestampErrorCode } from "../types.js";

interface ObjectNumberContext {
    largestObjectNumber: number;
    enumerateIndirectObjects(): [{ objectNumber: number }, unknown][];
    pdfFileDetails: {
        prevStartXRef: number;
    };
}

const { Inflate } = pako;

/**
 * pdf-lib writes the classic xref /Size as largestObjectNumber + 1. Reserve
 * that final value so both an object number and the writer's /Size remain
 * exactly representable JavaScript integers.
 */
export const MAX_SUPPORTED_OBJECT_NUMBER = Number.MAX_SAFE_INTEGER - 1;

const MAX_PDF_INTEGER = Number.MAX_SAFE_INTEGER;

const MAX_XREF_CHAIN_LENGTH = 256;
const MAX_XREF_ENTRIES = 1_000_000;
const MAX_XREF_DECODED_BYTES = 8 * 1024 * 1024;
const MAX_OBJECT_STREAM_DECODED_BYTES = 8 * 1024 * 1024;
const MAX_XREF_COMPRESSION_RATIO = 64;
const START_XREF = "startxref";
const XREF = "xref";
const TRAILER = "trailer";
const OBJ = "obj";
const ENDOBJ = "endobj";
const STREAM = "stream";
const ENDSTREAM = "endstream";

function objectNumberError(message: string): TimestampError {
    return new TimestampError(TimestampErrorCode.PDF_ERROR, message);
}

function isWhitespace(byte: number | undefined): boolean {
    return (
        byte === 0x00 ||
        byte === 0x09 ||
        byte === 0x0a ||
        byte === 0x0c ||
        byte === 0x0d ||
        byte === 0x20
    );
}

function isDelimiter(byte: number | undefined): boolean {
    return (
        byte === undefined ||
        isWhitespace(byte) ||
        byte === 0x28 ||
        byte === 0x29 ||
        byte === 0x3c ||
        byte === 0x3e ||
        byte === 0x5b ||
        byte === 0x5d ||
        byte === 0x7b ||
        byte === 0x7d ||
        byte === 0x2f ||
        byte === 0x25
    );
}

function isDigit(byte: number | undefined): boolean {
    return byte !== undefined && byte >= 0x30 && byte <= 0x39;
}

function matchesAscii(bytes: Uint8Array, offset: number, text: string): boolean {
    if (offset < 0 || offset + text.length > bytes.length) {
        return false;
    }
    for (let index = 0; index < text.length; index++) {
        if (bytes[offset + index] !== text.charCodeAt(index)) {
            return false;
        }
    }
    return true;
}

function matchesKeyword(bytes: Uint8Array, offset: number, keyword: string): boolean {
    return (
        matchesAscii(bytes, offset, keyword) &&
        isDelimiter(bytes[offset - 1]) &&
        isDelimiter(bytes[offset + keyword.length])
    );
}

function skipWhitespaceAndComments(bytes: Uint8Array, offset: number): number {
    let next = offset;
    while (next < bytes.length) {
        while (isWhitespace(bytes[next])) {
            next++;
        }
        if (bytes[next] !== 0x25) {
            break;
        }
        while (next < bytes.length && bytes[next] !== 0x0a && bytes[next] !== 0x0d) {
            next++;
        }
    }
    return next;
}

function skipWhitespace(bytes: Uint8Array, offset: number): number {
    let next = offset;
    while (isWhitespace(bytes[next])) {
        next++;
    }
    return next;
}

function readUnsignedInteger(
    bytes: Uint8Array,
    offset: number,
    maximum: number,
    description: string
): { value: number; next: number } {
    let next = offset;
    let value = 0;
    let sawDigit = false;

    while (isDigit(bytes[next])) {
        sawDigit = true;
        const digit = (bytes[next] ?? 0) - 0x30;
        if (value > Math.floor((maximum - digit) / 10)) {
            throw objectNumberError(`${description} exceeds the supported safe integer range`);
        }
        value = value * 10 + digit;
        next++;
    }

    if (!sawDigit || !isDelimiter(bytes[next])) {
        throw objectNumberError(`${description} must be an unsigned integer`);
    }
    return { value, next };
}

function readIndirectObjectHeader(
    bytes: Uint8Array,
    offset: number,
    description: string
): { objectNumber: number; generationNumber: number; next: number } {
    const object = readUnsignedInteger(
        bytes,
        offset,
        MAX_SUPPORTED_OBJECT_NUMBER,
        `${description} object`
    );
    let next = skipWhitespaceAndComments(bytes, object.next);
    const generation = readUnsignedInteger(
        bytes,
        next,
        MAX_SUPPORTED_OBJECT_NUMBER,
        `${description} generation`
    );
    next = skipWhitespaceAndComments(bytes, generation.next);
    if (!matchesKeyword(bytes, next, OBJ)) {
        throw objectNumberError(`${description} is not an indirect object header`);
    }
    return {
        objectNumber: object.value,
        generationNumber: generation.value,
        next: next + OBJ.length,
    };
}

function skipLiteralString(bytes: Uint8Array, offset: number): number {
    let next = offset;
    let depth = 0;
    let escaped = false;
    while (next < bytes.length) {
        const byte = bytes[next++];
        if (escaped) {
            escaped = false;
        } else if (byte === 0x5c) {
            escaped = true;
        } else if (byte === 0x28) {
            depth++;
        } else if (byte === 0x29) {
            depth--;
            if (depth === 0) {
                return next;
            }
        }
    }
    throw objectNumberError("Unterminated PDF literal string while reading xref metadata");
}

function skipHexString(bytes: Uint8Array, offset: number): number {
    let next = offset + 1;
    while (next < bytes.length && bytes[next] !== 0x3e) {
        next++;
    }
    if (next === bytes.length) {
        throw objectNumberError("Unterminated PDF hex string while reading xref metadata");
    }
    return next + 1;
}

function hexValue(byte: number | undefined): number | undefined {
    if (byte !== undefined && byte >= 0x30 && byte <= 0x39) {
        return byte - 0x30;
    }
    if (byte !== undefined && byte >= 0x41 && byte <= 0x46) {
        return byte - 0x41 + 10;
    }
    if (byte !== undefined && byte >= 0x61 && byte <= 0x66) {
        return byte - 0x61 + 10;
    }
    return undefined;
}

function readName(bytes: Uint8Array, offset: number): { value: string; next: number } {
    if (bytes[offset] !== 0x2f) {
        throw objectNumberError("Expected a PDF name while reading xref metadata");
    }

    let value = "";
    let next = offset + 1;
    while (next < bytes.length && !isDelimiter(bytes[next])) {
        const byte = bytes[next];
        if (byte === 0x23) {
            const high = hexValue(bytes[next + 1]);
            const low = hexValue(bytes[next + 2]);
            if (high === undefined || low === undefined) {
                throw objectNumberError("PDF name contains an invalid # escape in xref metadata");
            }
            value += String.fromCharCode(high * 16 + low);
            next += 3;
        } else {
            value += String.fromCharCode(byte ?? 0);
            next++;
        }
    }
    return { value, next };
}

type ParsedValue =
    | { kind: "integer"; value: number; next: number }
    | { kind: "name"; value: string; next: number }
    | { kind: "array"; values: ParsedValue[]; next: number }
    | { kind: "dictionary"; values: Map<string, ParsedValue>; next: number }
    | { kind: "ref"; objectNumber: number; generationNumber: number; next: number }
    | { kind: "other"; next: number; text?: string };

function readBareToken(bytes: Uint8Array, offset: number): number {
    let next = offset;
    while (next < bytes.length && !isDelimiter(bytes[next])) {
        next++;
    }
    if (next === offset) {
        throw objectNumberError("Expected a PDF value while reading xref metadata");
    }
    return next;
}

function parsePdfValue(bytes: Uint8Array, offset: number, depth = 0): ParsedValue {
    if (depth > 64) {
        throw objectNumberError("PDF xref metadata exceeds the supported nesting depth");
    }
    const next = skipWhitespaceAndComments(bytes, offset);
    const byte = bytes[next];
    if (byte === 0x2f) {
        const name = readName(bytes, next);
        return { kind: "name", value: name.value, next: name.next };
    }
    if (byte === 0x28) {
        return { kind: "other", next: skipLiteralString(bytes, next) };
    }
    if (byte === 0x3c) {
        return bytes[next + 1] === 0x3c
            ? parsePdfDictionary(bytes, next, depth + 1)
            : { kind: "other", next: skipHexString(bytes, next) };
    }
    if (byte === 0x5b) {
        const values: ParsedValue[] = [];
        let arrayNext = next + 1;
        while (arrayNext < bytes.length) {
            arrayNext = skipWhitespaceAndComments(bytes, arrayNext);
            if (bytes[arrayNext] === 0x5d) {
                return { kind: "array", values, next: arrayNext + 1 };
            }
            values.push(parsePdfValue(bytes, arrayNext, depth + 1));
            arrayNext = values[values.length - 1]?.next ?? arrayNext;
        }
        throw objectNumberError("Unterminated PDF array while reading xref metadata");
    }
    if (isDigit(byte)) {
        const first = readUnsignedInteger(bytes, next, MAX_PDF_INTEGER, "PDF integer");
        const secondStart = skipWhitespaceAndComments(bytes, first.next);
        if (isDigit(bytes[secondStart])) {
            const second = readUnsignedInteger(
                bytes,
                secondStart,
                MAX_PDF_INTEGER,
                "PDF reference generation"
            );
            const marker = skipWhitespaceAndComments(bytes, second.next);
            if (matchesKeyword(bytes, marker, "R")) {
                return {
                    kind: "ref",
                    objectNumber: first.value,
                    generationNumber: second.value,
                    next: marker + 1,
                };
            }
        }
        return { kind: "integer", value: first.value, next: first.next };
    }
    const tokenEnd = readBareToken(bytes, next);
    return {
        kind: "other",
        next: tokenEnd,
        text: new TextDecoder("ascii").decode(bytes.slice(next, tokenEnd)),
    };
}

function parsePdfDictionary(bytes: Uint8Array, offset: number, depth = 0): ParsedValue {
    if (bytes[offset] !== 0x3c || bytes[offset + 1] !== 0x3c) {
        throw objectNumberError("xref metadata must begin with a PDF dictionary");
    }
    const values = new Map<string, ParsedValue>();
    let next = offset + 2;
    while (next < bytes.length) {
        next = skipWhitespaceAndComments(bytes, next);
        if (bytes[next] === 0x3e && bytes[next + 1] === 0x3e) {
            return { kind: "dictionary", values, next: next + 2 };
        }
        const key = readName(bytes, next);
        if (values.has(key.value)) {
            throw objectNumberError(`xref metadata contains more than one /${key.value}`);
        }
        const value = parsePdfValue(bytes, key.next, depth + 1);
        values.set(key.value, value);
        next = value.next;
    }
    throw objectNumberError("Unterminated PDF dictionary while reading xref metadata");
}

function requiredPositiveInteger(
    dictionary: Map<string, ParsedValue>,
    key: string,
    description: string
): number {
    const value = dictionary.get(key);
    if (value?.kind !== "integer" || value.value <= 0) {
        throw objectNumberError(`${description} must be a direct positive integer`);
    }
    return value.value;
}

function optionalOffset(dictionary: Map<string, ParsedValue>, key: string): number | undefined {
    const value = dictionary.get(key);
    if (value === undefined) {
        return undefined;
    }
    if (value.kind !== "integer" || value.value <= 0) {
        throw objectNumberError(`xref /${key} must be a direct positive offset`);
    }
    return value.value;
}

function assertObjectNumber(value: number, description: string): void {
    if (!Number.isSafeInteger(value) || value < 0 || value > MAX_SUPPORTED_OBJECT_NUMBER) {
        throw objectNumberError(`${description} is outside the supported safe object number range`);
    }
}

function readFixedWidthInteger(bytes: Uint8Array, offset: number, width: number): number {
    let value = 0;
    for (let index = 0; index < width; index++) {
        const byte = bytes[offset + index];
        if (byte === undefined || value > Math.floor((MAX_SUPPORTED_OBJECT_NUMBER - byte) / 256)) {
            throw objectNumberError("xref stream entry exceeds the supported safe integer range");
        }
        value = value * 256 + byte;
    }
    return value;
}

interface XrefEntry {
    objectNumber: number;
    generationNumber: number;
    kind: "free" | "uncompressed" | "compressed";
    offset?: number;
    objectStreamNumber?: number;
    objectStreamIndex?: number;
}

interface XrefSection {
    offset: number;
    size: number;
    previous?: number;
    hybrid?: number;
    entries: XrefEntry[];
    objectNumbers: Set<number>;
    revisionEnd: number;
    terminatorEnd?: number;
    xrefObjectNumber?: number;
    xrefGenerationNumber?: number;
    root?: { objectNumber: number; generationNumber: number };
}

function optionalReference(
    dictionary: Map<string, ParsedValue>,
    key: string,
    description: string
): { objectNumber: number; generationNumber: number } | undefined {
    const value = dictionary.get(key);
    if (value === undefined) {
        return undefined;
    }
    if (value.kind !== "ref") {
        throw objectNumberError(`${description} must be an indirect reference`);
    }
    assertObjectNumber(value.objectNumber, `${description} object number`);
    if (!Number.isSafeInteger(value.generationNumber) || value.generationNumber < 0) {
        throw objectNumberError(`${description} generation number is unsafe`);
    }
    return { objectNumber: value.objectNumber, generationNumber: value.generationNumber };
}

function parseRevisionTerminator(
    bytes: Uint8Array,
    offset: number,
    xrefOffset?: number
): number {
    let next = skipWhitespaceAndComments(bytes, offset);
    if (!matchesKeyword(bytes, next, START_XREF)) {
        throw objectNumberError("xref revision is missing its startxref marker");
    }
    next = skipWhitespaceAndComments(bytes, next + START_XREF.length);
    const pointer = readUnsignedInteger(bytes, next, bytes.length - 1, "startxref offset");
    if (xrefOffset !== undefined && pointer.value !== xrefOffset) {
        throw objectNumberError("startxref does not point to its enclosing xref revision");
    }
    next = skipWhitespace(bytes, pointer.next);
    if (!matchesAscii(bytes, next, "%%EOF")) {
        throw objectNumberError("startxref must be followed by %%EOF");
    }
    return next + "%%EOF".length;
}

function assertFinalRevision(bytes: Uint8Array, terminatorEnd: number): void {
    if (skipWhitespace(bytes, terminatorEnd) !== bytes.length) {
        throw objectNumberError("final xref revision must terminate the PDF file");
    }
}

function parseClassicXref(
    bytes: Uint8Array,
    offset: number,
    requireTerminator: boolean
): XrefSection {
    if (!matchesKeyword(bytes, offset, XREF)) {
        throw objectNumberError("startxref does not point exactly to an xref table");
    }
    const entries: XrefEntry[] = [];
    const objectNumbers = new Set<number>();
    let next = offset + XREF.length;

    while (next < bytes.length) {
        next = skipWhitespaceAndComments(bytes, next);
        if (matchesKeyword(bytes, next, TRAILER)) {
            const dictionary = parsePdfDictionary(
                bytes,
                skipWhitespaceAndComments(bytes, next + TRAILER.length)
            );
            if (dictionary.kind !== "dictionary") {
                throw objectNumberError("xref trailer must be a dictionary");
            }
            const size = requiredPositiveInteger(dictionary.values, "Size", "xref /Size");
            for (const objectNumber of objectNumbers) {
                if (objectNumber >= size) {
                    throw objectNumberError("xref /Size is smaller than an xref subsection object");
                }
            }
            return {
                offset,
                size,
                previous: optionalOffset(dictionary.values, "Prev"),
                hybrid: optionalOffset(dictionary.values, "XRefStm"),
                entries,
                objectNumbers,
                revisionEnd: dictionary.next,
                terminatorEnd: requireTerminator
                    ? parseRevisionTerminator(bytes, dictionary.next, offset)
                    : undefined,
                root: optionalReference(dictionary.values, "Root", "xref /Root"),
            };
        }

        const first = readUnsignedInteger(
            bytes,
            next,
            MAX_SUPPORTED_OBJECT_NUMBER,
            "xref subsection start"
        );
        next = skipWhitespaceAndComments(bytes, first.next);
        const count = readUnsignedInteger(bytes, next, MAX_XREF_ENTRIES, "xref subsection count");
        if (count.value > MAX_XREF_ENTRIES - entries.length) {
            throw objectNumberError("xref subsection count is outside the supported range");
        }
        if (count.value === 0) {
            next = count.next;
            continue;
        }
        const last = first.value + count.value - 1;
        assertObjectNumber(last, "xref subsection object number");
        next = count.next;

        for (let index = 0; index < count.value; index++) {
            next = skipWhitespaceAndComments(bytes, next);
            const entryOffset = readUnsignedInteger(
                bytes,
                next,
                bytes.length - 1,
                "xref entry offset"
            );
            next = skipWhitespaceAndComments(bytes, entryOffset.next);
            const generation = readUnsignedInteger(
                bytes,
                next,
                MAX_SUPPORTED_OBJECT_NUMBER,
                "xref entry generation"
            );
            next = skipWhitespaceAndComments(bytes, generation.next);
            const kind = bytes[next];
            if ((kind !== 0x6e && kind !== 0x66) || !isDelimiter(bytes[next + 1])) {
                throw objectNumberError("xref entry must end with an n or f marker");
            }
            const objectNumber = first.value + index;
            objectNumbers.add(objectNumber);
            entries.push({
                objectNumber,
                generationNumber: generation.value,
                kind: kind === 0x6e ? "uncompressed" : "free",
                offset: entryOffset.value,
            });
            next++;
        }
    }
    throw objectNumberError("xref table is missing its trailer dictionary");
}

function directStreamLength(value: ParsedValue | undefined, description: string): number {
    if (value?.kind === "integer") {
        if (Number.isSafeInteger(value.value) && value.value >= 0) {
            return value.value;
        }
    }
    throw objectNumberError(`${description} /Length must be a safe direct integer`);
}

function xrefUsesFlateFilter(dictionary: Map<string, ParsedValue>): boolean {
    const decodeParms = dictionary.get("DecodeParms");
    const isNullDecodeParms =
        decodeParms?.kind === "other" && decodeParms.text === "null";
    const isNullDecodeParmsArray =
        decodeParms?.kind === "array" &&
        decodeParms.values.every((value) => value.kind === "other" && value.text === "null");
    if (decodeParms !== undefined && !isNullDecodeParms && !isNullDecodeParmsArray) {
        // pdf-lib's stream decoder does not apply PDF predictor parameters. Do
        // not prove xref metadata using bytes decoded under different semantics.
        throw objectNumberError("xref stream /DecodeParms is unsupported for safe metadata proof");
    }
    const filter = dictionary.get("Filter");
    if (filter === undefined) {
        return false;
    }
    if (filter.kind === "name" && filter.value === "FlateDecode") {
        return true;
    }
    if (
        filter.kind === "array" &&
        filter.values.length === 1 &&
        filter.values[0]?.kind === "name" &&
        filter.values[0].value === "FlateDecode"
    ) {
        return true;
    }
    throw objectNumberError("xref stream /Filter must be absent or a single /FlateDecode");
}

class DecodedOutputLimitError extends Error {}

function concatenateDecodedChunks(chunks: Uint8Array[], length: number): Uint8Array {
    const decoded = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
        decoded.set(chunk, offset);
        offset += chunk.length;
    }
    return decoded;
}

function decodeFlateWithinLimit(encoded: Uint8Array, limit: number): Uint8Array {
    const chunks: Uint8Array[] = [];
    let decodedLength = 0;
    const inflate = new Inflate({ chunkSize: Math.max(1, Math.min(16384, limit)) });
    inflate.onData = (chunk: Uint8Array): void => {
        if (chunk.length > limit - decodedLength) {
            const permitted = limit - decodedLength;
            if (permitted > 0) {
                chunks.push(chunk.slice(0, permitted));
                decodedLength += permitted;
            }
            throw new DecodedOutputLimitError();
        }
        chunks.push(chunk);
        decodedLength += chunk.length;
    };
    try {
        if (!inflate.push(encoded, true) || inflate.err !== 0) {
            throw objectNumberError(
                `Flate stream could not be decoded: ${inflate.msg || inflate.err.toString()}`
            );
        }
    } catch (error) {
        if (error instanceof DecodedOutputLimitError) {
            return concatenateDecodedChunks(chunks, decodedLength);
        }
        if (error instanceof TimestampError) {
            throw error;
        }
        throw objectNumberError(
            `Flate stream could not be decoded: ${error instanceof Error ? error.message : String(error)}`
        );
    }
    return concatenateDecodedChunks(chunks, decodedLength);
}

function decodeXrefBytes(
    dictionary: Map<string, ParsedValue>,
    encoded: Uint8Array,
    expectedLength: number,
    description: string
): Uint8Array {
    const ratioBound = encoded.length * MAX_XREF_COMPRESSION_RATIO;
    const outputBound = Math.min(MAX_PDF_SIZE, MAX_XREF_DECODED_BYTES, Math.max(65536, ratioBound));
    if (!Number.isSafeInteger(expectedLength) || expectedLength < 0 || expectedLength > outputBound) {
        throw objectNumberError(`${description} exceeds the bounded decoded xref budget`);
    }
    try {
        const limit = expectedLength + 1;
        const decoded = xrefUsesFlateFilter(dictionary)
            ? decodeFlateWithinLimit(encoded, limit)
            : encoded.slice(0, limit);
        if (decoded.length !== expectedLength) {
            throw objectNumberError(`${description} has an unexpected decoded length`);
        }
        return Uint8Array.from(decoded);
    } catch (error) {
        if (error instanceof TimestampError) {
            throw error;
        }
        throw objectNumberError(
            `${description} could not be decoded: ${error instanceof Error ? error.message : String(error)}`
        );
    }
}

function xrefStreamIndex(
    dictionary: Map<string, ParsedValue>,
    size: number
): { first: number; count: number }[] {
    const index = dictionary.get("Index");
    if (index === undefined) {
        if (size > MAX_XREF_ENTRIES) {
            throw objectNumberError("xref stream /Size exceeds the supported entry count");
        }
        return [{ first: 0, count: size }];
    }
    if (index.kind !== "array" || index.values.length === 0 || index.values.length % 2 !== 0) {
        throw objectNumberError("xref stream /Index must contain object-number/count pairs");
    }
    const ranges: { first: number; count: number }[] = [];
    let total = 0;
    for (let position = 0; position < index.values.length; position += 2) {
        const first = index.values[position];
        const count = index.values[position + 1];
        if (first?.kind !== "integer" || count?.kind !== "integer" || count.value <= 0) {
            throw objectNumberError("xref stream /Index must contain positive integer ranges");
        }
        const last = first.value + count.value - 1;
        assertObjectNumber(last, "xref stream /Index object number");
        if (last >= size || count.value > MAX_XREF_ENTRIES - total) {
            throw objectNumberError("xref stream /Index is outside /Size or supported range");
        }
        const previousRange = ranges[ranges.length - 1];
        if (
            previousRange !== undefined &&
            first.value <= previousRange.first + previousRange.count - 1
        ) {
            throw objectNumberError("xref stream /Index ranges must be ascending and non-overlapping");
        }
        for (const range of ranges) {
            const rangeLast = range.first + range.count - 1;
            if (first.value <= rangeLast && range.first <= last) {
                throw objectNumberError("xref stream /Index ranges must not overlap");
            }
        }
        total += count.value;
        ranges.push({ first: first.value, count: count.value });
    }
    return ranges;
}

function xrefStreamWidths(dictionary: Map<string, ParsedValue>): [number, number, number] {
    const widths = dictionary.get("W");
    if (widths?.kind !== "array" || widths.values.length !== 3) {
        throw objectNumberError("xref stream /W must contain exactly three widths");
    }
    const values = widths.values.map((value) => {
        if (value.kind !== "integer" || value.value > 8) {
            throw objectNumberError("xref stream /W entries must be integers from 0 through 8");
        }
        return value.value;
    });
    const first = values[0];
    const second = values[1];
    const third = values[2];
    if (
        first === undefined ||
        second === undefined ||
        third === undefined ||
        first + second + third === 0
    ) {
        throw objectNumberError("xref stream /W must contain a non-zero field width");
    }
    return [first, second, third];
}

function parseXrefStream(
    bytes: Uint8Array,
    offset: number,
    requireTerminator: boolean
): XrefSection {
    const header = readIndirectObjectHeader(bytes, offset, "xref stream");
    const dictionary = parsePdfDictionary(bytes, skipWhitespaceAndComments(bytes, header.next));
    if (dictionary.kind !== "dictionary") {
        throw objectNumberError("xref stream dictionary is invalid");
    }
    const type = dictionary.values.get("Type");
    if (type?.kind !== "name" || type.value !== "XRef") {
        throw objectNumberError("startxref stream does not have /Type /XRef");
    }
    const size = requiredPositiveInteger(dictionary.values, "Size", "xref stream /Size");
    if (header.objectNumber >= size) {
        throw objectNumberError("xref stream object number is outside its /Size");
    }
    const widths = xrefStreamWidths(dictionary.values);
    const ranges = xrefStreamIndex(dictionary.values, size);
    const length = directStreamLength(dictionary.values.get("Length"), "xref stream");
    let next = skipWhitespaceAndComments(bytes, dictionary.next);
    if (!matchesKeyword(bytes, next, STREAM)) {
        throw objectNumberError("xref stream is missing its stream data");
    }
    next += STREAM.length;
    if (bytes[next] === 0x0d) {
        next++;
        if (bytes[next] === 0x0a) {
            next++;
        }
    } else if (bytes[next] === 0x0a) {
        next++;
    } else {
        throw objectNumberError("xref stream keyword must be followed by an end-of-line");
    }
    if (length > bytes.length - next) {
        throw objectNumberError("xref stream /Length exceeds the PDF byte length");
    }
    const streamEnd = next + length;
    let afterStream = skipWhitespace(bytes, streamEnd);
    if (!matchesKeyword(bytes, afterStream, ENDSTREAM)) {
        throw objectNumberError("xref stream /Length does not reach endstream");
    }
    afterStream = skipWhitespaceAndComments(bytes, afterStream + ENDSTREAM.length);
    if (!matchesKeyword(bytes, afterStream, ENDOBJ)) {
        throw objectNumberError("xref stream is missing endobj");
    }

    const expectedEntries = ranges.reduce((total, range) => total + range.count, 0);
    const entryWidth = widths[0] + widths[1] + widths[2];
    const decoded = decodeXrefBytes(
        dictionary.values,
        bytes.slice(next, streamEnd),
        expectedEntries * entryWidth,
        "xref stream data"
    );

    const entries: XrefEntry[] = [];
    const objectNumbers = new Set<number>();
    let cursor = 0;
    for (const range of ranges) {
        for (let index = 0; index < range.count; index++) {
            const objectNumber = range.first + index;
            const type = widths[0] === 0 ? 1 : readFixedWidthInteger(decoded, cursor, widths[0]);
            cursor += widths[0];
            const fieldTwo = readFixedWidthInteger(decoded, cursor, widths[1]);
            cursor += widths[1];
            const fieldThree = readFixedWidthInteger(decoded, cursor, widths[2]);
            cursor += widths[2];
            objectNumbers.add(objectNumber);
            if (type === 0) {
                entries.push({ objectNumber, generationNumber: fieldThree, kind: "free" });
            } else if (type === 1) {
                entries.push({
                    objectNumber,
                    generationNumber: fieldThree,
                    kind: "uncompressed",
                    offset: fieldTwo,
                });
            } else if (type === 2) {
                entries.push({
                    objectNumber,
                    generationNumber: 0,
                    kind: "compressed",
                    objectStreamNumber: fieldTwo,
                    objectStreamIndex: fieldThree,
                });
            } else {
                throw objectNumberError("xref stream contains an unsupported entry type");
            }
        }
    }

    return {
        offset,
        size,
        previous: optionalOffset(dictionary.values, "Prev"),
        entries,
        objectNumbers,
        revisionEnd: afterStream + ENDOBJ.length,
        terminatorEnd: requireTerminator
            ? parseRevisionTerminator(bytes, afterStream + ENDOBJ.length, offset)
            : undefined,
        xrefObjectNumber: header.objectNumber,
        xrefGenerationNumber: header.generationNumber,
        root: optionalReference(dictionary.values, "Root", "xref stream /Root"),
    };
}

interface ParsedRawStream {
    header: { objectNumber: number; generationNumber: number; next: number };
    dictionary: Map<string, ParsedValue>;
    contents: Uint8Array;
}

function parseRawStreamAt(
    bytes: Uint8Array,
    offset: number,
    description: string
): ParsedRawStream {
    const header = readIndirectObjectHeader(bytes, offset, description);
    const dictionary = parsePdfDictionary(bytes, skipWhitespaceAndComments(bytes, header.next));
    if (dictionary.kind !== "dictionary") {
        throw objectNumberError(`${description} dictionary is invalid`);
    }
    let next = skipWhitespaceAndComments(bytes, dictionary.next);
    if (!matchesKeyword(bytes, next, STREAM)) {
        throw objectNumberError(`${description} is missing stream data`);
    }
    next += STREAM.length;
    if (bytes[next] === 0x0d) {
        next++;
        if (bytes[next] === 0x0a) {
            next++;
        }
    } else if (bytes[next] === 0x0a) {
        next++;
    } else {
        throw objectNumberError(`${description} stream keyword must be followed by an end-of-line`);
    }
    const length = directStreamLength(dictionary.values.get("Length"), description);
    if (length > bytes.length - next) {
        throw objectNumberError(`${description} /Length exceeds the PDF byte length`);
    }
    const streamEnd = next + length;
    let afterStream = skipWhitespace(bytes, streamEnd);
    if (!matchesKeyword(bytes, afterStream, ENDSTREAM)) {
        throw objectNumberError(`${description} /Length does not reach endstream`);
    }
    afterStream = skipWhitespaceAndComments(bytes, afterStream + ENDSTREAM.length);
    if (!matchesKeyword(bytes, afterStream, ENDOBJ)) {
        throw objectNumberError(`${description} is missing endobj`);
    }
    return { header, dictionary: dictionary.values, contents: bytes.slice(next, streamEnd) };
}

function requiredObjectStreamInteger(
    dictionary: Map<string, ParsedValue>,
    key: string,
    description: string
): number {
    const value = dictionary.get(key);
    if (value?.kind !== "integer" || !Number.isSafeInteger(value.value) || value.value < 0) {
        throw objectNumberError(`${description} /${key} must be a direct non-negative integer`);
    }
    return value.value;
}

function decodeBoundedStream(
    dictionary: Map<string, ParsedValue>,
    encoded: Uint8Array,
    maximumLength: number,
    description: string
): Uint8Array {
    if (!Number.isSafeInteger(maximumLength) || maximumLength < 0 || maximumLength >= MAX_PDF_SIZE) {
        throw objectNumberError(`${description} exceeds the supported decoded stream budget`);
    }
    const limit = maximumLength + 1;
    const decoded = xrefUsesFlateFilter(dictionary)
        ? decodeFlateWithinLimit(encoded, limit)
        : encoded.slice(0, limit);
    if (decoded.length > maximumLength) {
        throw objectNumberError(`${description} exceeds the supported decoded stream budget`);
    }
    return decoded;
}

interface ParsedObjectStream {
    objectNumbers: readonly number[];
}

function parseObjectStreamContainer(
    bytes: Uint8Array,
    entry: XrefEntry
): ParsedObjectStream {
    if (entry.objectStreamNumber === undefined || entry.objectStreamNumber <= 0) {
        throw objectNumberError("xref stream compressed entry has invalid object-stream metadata");
    }
    if (entry.offset === undefined) {
        throw objectNumberError("object stream container has no active byte offset");
    }
    const stream = parseRawStreamAt(bytes, entry.offset, "object stream container");
    if (
        stream.header.objectNumber !== entry.objectStreamNumber ||
        stream.header.generationNumber !== 0
    ) {
        throw objectNumberError("object stream container header does not match its active xref entry");
    }
    const type = stream.dictionary.get("Type");
    if (type?.kind !== "name" || type.value !== "ObjStm") {
        throw objectNumberError("compressed xref entry container is not an /ObjStm stream");
    }
    const count = requiredObjectStreamInteger(stream.dictionary, "N", "object stream container");
    const first = requiredObjectStreamInteger(stream.dictionary, "First", "object stream container");
    if (count === 0 || first === 0) {
        throw objectNumberError("object stream container has an invalid /N or /First");
    }
    const decoded = decodeBoundedStream(
        stream.dictionary,
        stream.contents,
        Math.min(MAX_PDF_SIZE - 1, MAX_OBJECT_STREAM_DECODED_BYTES),
        "object stream container"
    );
    if (first >= decoded.length) {
        throw objectNumberError("object stream /First does not leave any object data");
    }
    const headerBytes = decoded.slice(0, first);
    const objectNumbers: number[] = [];
    const objectOffsets: number[] = [];
    const seenObjectNumbers = new Set<number>();
    let next = 0;
    for (let index = 0; index < count; index++) {
        next = skipWhitespace(headerBytes, next);
        const objectNumber = readUnsignedInteger(
            headerBytes,
            next,
            MAX_SUPPORTED_OBJECT_NUMBER,
            "object stream object number"
        );
        assertObjectNumber(objectNumber.value, "object stream object number");
        if (objectNumber.value === 0 || seenObjectNumbers.has(objectNumber.value)) {
            throw objectNumberError("object stream header contains a duplicate or invalid object number");
        }
        seenObjectNumbers.add(objectNumber.value);
        next = skipWhitespace(headerBytes, objectNumber.next);
        const objectOffset = readUnsignedInteger(
            headerBytes,
            next,
            MAX_SUPPORTED_OBJECT_NUMBER,
            "object stream object offset"
        );
        next = objectOffset.next;
        objectNumbers.push(objectNumber.value);
        objectOffsets.push(objectOffset.value);
    }
    if (skipWhitespace(headerBytes, next) !== headerBytes.length) {
        throw objectNumberError("object stream /First does not delimit its complete object header");
    }
    const objectDataLength = decoded.length - first;
    for (let index = 0; index < objectOffsets.length; index++) {
        const offset = objectOffsets[index];
        const nextOffset = objectOffsets[index + 1] ?? objectDataLength;
        if (
            offset === undefined ||
            (index === 0 && offset !== 0) ||
            offset >= nextOffset ||
            nextOffset > objectDataLength
        ) {
            throw objectNumberError("object stream header has unsorted or out-of-bounds object offsets");
        }
    }
    return { objectNumbers: Object.freeze(objectNumbers) };
}

function validateCompressedObjectEntry(
    bytes: Uint8Array,
    entry: XrefEntry,
    activeEntries: Map<number, XrefEntry>,
    parsedObjectStreams: Map<number, ParsedObjectStream>
): void {
    if (
        entry.objectStreamNumber === undefined ||
        entry.objectStreamIndex === undefined ||
        entry.objectStreamNumber <= 0
    ) {
        throw objectNumberError("xref stream compressed entry has invalid object-stream metadata");
    }
    const container = activeEntries.get(entry.objectStreamNumber);
    if (
        container?.kind !== "uncompressed" ||
        container.generationNumber !== 0 ||
        container.offset === undefined
    ) {
        throw objectNumberError(
            "xref stream compressed entry has no active generation-zero object-stream container"
        );
    }
    let parsed = parsedObjectStreams.get(entry.objectStreamNumber);
    if (parsed === undefined) {
        parsed = parseObjectStreamContainer(bytes, {
            ...container,
            objectStreamNumber: entry.objectStreamNumber,
        });
        parsedObjectStreams.set(entry.objectStreamNumber, parsed);
    }
    if (entry.objectStreamIndex >= parsed.objectNumbers.length) {
        throw objectNumberError("compressed xref entry has an invalid object-stream index");
    }
    if (parsed.objectNumbers[entry.objectStreamIndex] !== entry.objectNumber) {
        throw objectNumberError("compressed xref entry does not match its object-stream header index");
    }
}

function validateXrefEntryHeaders(
    bytes: Uint8Array,
    section: XrefSection,
    allowForwardObjectOffsets: boolean
): void {
    for (const entry of section.entries) {
        if (entry.kind !== "uncompressed") {
            continue;
        }
        if (
            entry.offset === undefined ||
            (!allowForwardObjectOffsets && entry.offset > section.offset)
        ) {
            throw objectNumberError("xref entry offset does not point to a permitted object");
        }
        const header = readIndirectObjectHeader(bytes, entry.offset, "xref entry target");
        if (
            header.objectNumber !== entry.objectNumber ||
            header.generationNumber !== entry.generationNumber
        ) {
            throw objectNumberError("xref entry does not match its indirect object header");
        }
    }
}

interface LinearizationInfo {
    originalLength: number;
}

export interface PdfXrefProof {
    readonly anchor: number;
    readonly largestObjectNumber: number;
    readonly objectNumbers: readonly number[];
}

function terminalStartXref(bytes: Uint8Array): number {
    let next = bytes.length;
    while (next > 0 && isWhitespace(bytes[next - 1])) {
        next--;
    }
    const eofStart = next - "%%EOF".length;
    if (eofStart < 0 || !matchesAscii(bytes, eofStart, "%%EOF")) {
        throw objectNumberError("PDF must end with an exact startxref and %%EOF terminator");
    }
    next = eofStart;
    while (next > 0 && isWhitespace(bytes[next - 1])) {
        next--;
    }
    let numberStart = next;
    while (numberStart > 0 && isDigit(bytes[numberStart - 1])) {
        numberStart--;
    }
    if (numberStart === next || numberStart === 0 || !isWhitespace(bytes[numberStart - 1])) {
        throw objectNumberError("terminal startxref must contain a safe decimal offset");
    }
    const pointer = readUnsignedInteger(
        bytes,
        numberStart,
        bytes.length - 1,
        "terminal startxref offset"
    );
    if (pointer.next !== next || pointer.value <= 0 || pointer.value >= bytes.length) {
        throw objectNumberError("terminal startxref must contain a safe in-file offset");
    }
    next = numberStart;
    while (next > 0 && isWhitespace(bytes[next - 1])) {
        next--;
    }
    const markerStart = next - START_XREF.length;
    if (
        markerStart < 0 ||
        !matchesAscii(bytes, markerStart, START_XREF) ||
        !isDelimiter(bytes[markerStart - 1])
    ) {
        throw objectNumberError("PDF must end with an exact startxref and %%EOF terminator");
    }
    return pointer.value;
}

function firstObjectLinearization(bytes: Uint8Array): LinearizationInfo | undefined {
    const firstObjectOffset = skipWhitespaceAndComments(bytes, 0);
    const header = readIndirectObjectHeader(bytes, firstObjectOffset, "first PDF object");
    const dictionaryOffset = skipWhitespaceAndComments(bytes, header.next);
    if (bytes[dictionaryOffset] !== 0x3c || bytes[dictionaryOffset + 1] !== 0x3c) {
        return undefined;
    }
    const dictionary = parsePdfDictionary(bytes, dictionaryOffset);
    if (dictionary.kind !== "dictionary") {
        throw objectNumberError("first PDF object dictionary is invalid");
    }
    const linearized = dictionary.values.get("Linearized");
    const length = dictionary.values.get("L");
    const terminalXref = dictionary.values.get("T");
    if (
        linearized?.kind !== "integer" ||
        linearized.value !== 1 ||
        length?.kind !== "integer" ||
        terminalXref?.kind !== "integer"
    ) {
        return undefined;
    }
    if (
        !Number.isSafeInteger(length.value) ||
        length.value <= 0 ||
        length.value > bytes.length ||
        !Number.isSafeInteger(terminalXref.value) ||
        terminalXref.value <= 0 ||
        terminalXref.value >= length.value
    ) {
        throw objectNumberError("linearization dictionary contains an invalid /L or /T");
    }
    return { originalLength: length.value };
}

function revisionTerminatorIfPresent(
    bytes: Uint8Array,
    offset: number,
    xrefOffset: number
): number | undefined {
    const next = skipWhitespaceAndComments(bytes, offset);
    return matchesKeyword(bytes, next, START_XREF)
        ? parseRevisionTerminator(bytes, offset, xrefOffset)
        : undefined;
}

function validateXrefSelfEntry(section: XrefSection, fallback?: XrefSection): void {
    if (
        section.xrefObjectNumber === undefined ||
        section.xrefGenerationNumber === undefined
    ) {
        return;
    }
    const hasMatchingEntry = (candidate: XrefSection): boolean =>
        candidate.entries.some(
            (entry) =>
                entry.kind === "uncompressed" &&
                entry.objectNumber === section.xrefObjectNumber &&
                entry.generationNumber === section.xrefGenerationNumber &&
                entry.offset === section.offset
        );
    if (!hasMatchingEntry(section) && (fallback === undefined || !hasMatchingEntry(fallback))) {
        throw objectNumberError("xref stream has no matching active or authoritative self entry");
    }
}

function validateXrefChain(bytes: Uint8Array, initialOffset: number): PdfXrefProof {
    if (
        !Number.isSafeInteger(initialOffset) ||
        initialOffset <= 0 ||
        initialOffset >= bytes.length
    ) {
        throw objectNumberError("terminal startxref offset is outside the PDF byte range");
    }

    const linearized = firstObjectLinearization(bytes);
    const seenOffsets = new Set<number>();
    const seenHybridOffsets = new Set<number>();
    const sections: XrefSection[] = [];
    const allObjectNumbers = new Set<number>();
    let offset: number | undefined = initialOffset;
    let newestSize: number | undefined;
    let sectionCount = 0;
    let linearizedBoundaryProven = false;

    while (offset !== undefined) {
        if (sectionCount++ >= MAX_XREF_CHAIN_LENGTH || seenOffsets.has(offset)) {
            throw objectNumberError("xref /Prev chain is cyclic or exceeds the supported length");
        }
        if (!Number.isSafeInteger(offset) || offset <= 0 || offset >= bytes.length) {
            throw objectNumberError("xref /Prev offset is outside the PDF byte range");
        }
        seenOffsets.add(offset);

        let section: XrefSection;
        if (matchesKeyword(bytes, offset, XREF)) {
            section = parseClassicXref(bytes, offset, false);
            if (section.hybrid !== undefined) {
                if (
                    section.hybrid <= 0 ||
                    section.hybrid >= bytes.length ||
                    section.hybrid === section.offset ||
                    seenOffsets.has(section.hybrid) ||
                    seenHybridOffsets.has(section.hybrid)
                ) {
                    throw objectNumberError("xref /XRefStm offset is invalid or cyclic");
                }
                const hybrid = parseXrefStream(bytes, section.hybrid, false);
                if (hybrid.size > section.size) {
                    throw objectNumberError(
                        "hybrid xref stream /Size exceeds its authoritative classic xref table"
                    );
                }
                validateXrefEntryHeaders(bytes, hybrid, linearized !== undefined);
                validateXrefSelfEntry(hybrid, section);
                sections.push(hybrid);
                for (const objectNumber of hybrid.objectNumbers) {
                    allObjectNumbers.add(objectNumber);
                }
                seenHybridOffsets.add(section.hybrid);
            }
        } else {
            section = parseXrefStream(bytes, offset, false);
            validateXrefSelfEntry(section);
        }

        validateXrefEntryHeaders(bytes, section, linearized !== undefined);
        sections.push(section);
        for (const objectNumber of section.objectNumbers) {
            allObjectNumbers.add(objectNumber);
        }
        if (newestSize === undefined) {
            newestSize = section.size;
            if (linearized === undefined) {
                const terminatorEnd = revisionTerminatorIfPresent(
                    bytes,
                    section.revisionEnd,
                    initialOffset
                );
                if (terminatorEnd === undefined) {
                    throw objectNumberError("final xref revision is missing its terminator");
                }
                assertFinalRevision(bytes, terminatorEnd);
            }
        }
        if (section.previous !== undefined) {
            if (
                (linearized === undefined && section.previous >= section.offset) ||
                seenOffsets.has(section.previous)
            ) {
                throw objectNumberError("xref /Prev points to a cyclic or invalid revision");
            }
        } else if (linearized !== undefined) {
            const terminatorEnd = parseRevisionTerminator(bytes, section.revisionEnd);
            if (terminatorEnd > linearized.originalLength) {
                throw objectNumberError("linearized revision /L does not end at a proven %%EOF boundary");
            }
            for (let index = terminatorEnd; index < linearized.originalLength; index++) {
                if (!isWhitespace(bytes[index])) {
                    throw objectNumberError(
                        "linearized revision /L does not end at a proven %%EOF boundary"
                    );
                }
            }
            linearizedBoundaryProven = true;
        }
        offset = section.previous;
    }

    if (newestSize === undefined) {
        throw objectNumberError("PDF does not contain a final xref revision");
    }
    if (linearized !== undefined && !linearizedBoundaryProven) {
        throw objectNumberError("linearized PDF did not prove its original %%EOF boundary");
    }
    let totalEntries = 0;
    const activeEntries = new Map<number, XrefEntry>();
    let foundRoot = false;
    for (const section of sections) {
        if (section.size > newestSize) {
            throw objectNumberError("final xref /Size is smaller than an earlier xref revision /Size");
        }
        if (totalEntries > MAX_XREF_ENTRIES - section.entries.length) {
            throw objectNumberError("xref chain exceeds the supported total entry count");
        }
        totalEntries += section.entries.length;
        for (const entry of section.entries) {
            if (!activeEntries.has(entry.objectNumber)) {
                activeEntries.set(entry.objectNumber, entry);
            }
        }
        if (section.root !== undefined) {
            foundRoot = true;
        }
    }
    if (!foundRoot) {
        throw objectNumberError("xref revision chain does not contain a /Root reference");
    }
    for (const section of sections) {
        if (section.root === undefined) {
            continue;
        }
        const rootEntry = activeEntries.get(section.root.objectNumber);
        if (
            rootEntry === undefined ||
            rootEntry.kind === "free" ||
            rootEntry.generationNumber !== section.root.generationNumber
        ) {
            throw objectNumberError("xref /Root is absent from the active xref entries");
        }
    }
    for (const objectNumber of allObjectNumbers) {
        if (objectNumber >= newestSize) {
            throw objectNumberError(
                "final xref /Size is smaller than an object in its revision chain"
            );
        }
    }
    const parsedObjectStreams = new Map<number, ParsedObjectStream>();
    for (const entry of activeEntries.values()) {
        if (entry.kind === "compressed") {
            validateCompressedObjectEntry(bytes, entry, activeEntries, parsedObjectStreams);
        }
    }
    return Object.freeze({
        anchor: initialOffset,
        largestObjectNumber: newestSize - 1,
        objectNumbers: Object.freeze([...allObjectNumbers].sort((left, right) => left - right)),
    });
}

function assertCurrentObjectNumber(value: number, description: string): void {
    if (!Number.isSafeInteger(value) || value < 0 || value > MAX_SUPPORTED_OBJECT_NUMBER) {
        throw objectNumberError(`${description} is outside the supported safe object number range`);
    }
}

/**
 * Restores the highest safe object number from a structurally verified final
 * xref chain. This intentionally does not search arbitrary PDF bytes: text in
 * strings or streams is never evidence of an object allocation boundary.
 */
export function preflightPdfXref(pdfBytes: Uint8Array): PdfXrefProof {
    return validateXrefChain(pdfBytes, terminalStartXref(pdfBytes));
}

/**
 * Compares the dependency's post-load metadata with a pre-load structural
 * proof before allowing a mutation to allocate a fresh indirect reference.
 */
export function restoreLargestObjectNumber(
    pdfBytes: Uint8Array,
    context: ObjectNumberContext,
    proof = preflightPdfXref(pdfBytes)
): void {
    assertCurrentObjectNumber(context.largestObjectNumber, "PDF context object number");
    if (context.pdfFileDetails.prevStartXRef !== proof.anchor) {
        throw objectNumberError("PDF parser final xref offset does not match the pre-load proof");
    }
    const proofObjectNumbers = new Set(proof.objectNumbers);
    for (const [ref] of context.enumerateIndirectObjects()) {
        assertObjectNumber(ref.objectNumber, "Parsed PDF object number");
        if (!proofObjectNumbers.has(ref.objectNumber)) {
            throw objectNumberError("parsed PDF object is absent from the pre-load xref proof");
        }
    }
    assertCurrentObjectNumber(proof.largestObjectNumber, "Computed PDF object number");
    context.largestObjectNumber = proof.largestObjectNumber;
}

/**
 * Allocate through pdf-lib only while its next object number remains exactly
 * representable. Callers must use this for every mutation-time registration.
 */
export function checkedRegister<T extends PDFObject>(
    context: ObjectNumberContext & { register(object: T): PDFRef },
    object: T
): PDFRef {
    assertCurrentObjectNumber(context.largestObjectNumber, "PDF context object number");
    if (context.largestObjectNumber >= MAX_SUPPORTED_OBJECT_NUMBER) {
        throw objectNumberError(
            "PDF object number allocation exceeds the supported safe integer range"
        );
    }
    const expected = context.largestObjectNumber + 1;
    const ref = context.register(object);
    if (ref.objectNumber !== expected || !Number.isSafeInteger(ref.objectNumber)) {
        throw objectNumberError(
            "PDF object allocation did not produce the expected safe object number"
        );
    }
    return ref;
}
