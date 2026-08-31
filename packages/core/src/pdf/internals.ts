// Internal helpers for working around pdf-lib-incremental-save quirks.
// Not part of the public API.

import { PDFRef, type PDFObject } from "pdf-lib-incremental-save";
import { TimestampError, TimestampErrorCode } from "../types.js";

interface ObjectNumberContext {
    largestObjectNumber: number;
    enumerateIndirectObjects(): [PDFRef, unknown][];
}

/**
 * pdf-lib writes the classic xref /Size as largestObjectNumber + 1. Reserve
 * that final value so both an object number and the writer's /Size remain
 * exactly representable JavaScript integers.
 */
export const MAX_SUPPORTED_OBJECT_NUMBER = Number.MAX_SAFE_INTEGER - 1;

const MAX_OBJECT_HEADER_SEPARATOR_BYTES = 100;
const HEADER_SCAN_WORK_MULTIPLIER = 8;

function objectNumberError(message: string): TimestampError {
    return new TimestampError(TimestampErrorCode.PDF_ERROR, message);
}

function assertSupportedObjectNumber(value: number, description: string): void {
    if (!Number.isSafeInteger(value) || value < 0 || value > MAX_SUPPORTED_OBJECT_NUMBER) {
        throw objectNumberError(`${description} is outside the supported safe object number range`);
    }
}

function isPdfWhitespace(byte: number | undefined): boolean {
    return (
        byte === 0x00 ||
        byte === 0x09 ||
        byte === 0x0a ||
        byte === 0x0c ||
        byte === 0x0d ||
        byte === 0x20
    );
}

function isAsciiDigit(byte: number | undefined): boolean {
    return byte !== undefined && byte >= 0x30 && byte <= 0x39;
}

interface HeaderInteger {
    value: number;
    next: number;
    isSafe: boolean;
}

interface HeaderSeparators {
    next: number;
    exceedsLimit: boolean;
}

interface HeaderScanBudget {
    remaining: number;
}

/**
 * Reads a decimal token without ever converting an unsafe value through
 * Number. The scan is intentionally only used after `PDFDocument.load` has
 * constructed a context; the original bytes remain untrusted. This is a
 * compatibility guard for missing physical container references, not a PDF parser.
 */
function readHeaderInteger(bytes: Uint8Array, offset: number): HeaderInteger {
    let next = offset;
    let value = 0;
    let isSafe = true;

    while (isAsciiDigit(bytes[next])) {
        const digit = (bytes[next] ?? 0) - 0x30;
        if (
            isSafe &&
            value > Math.floor((MAX_SUPPORTED_OBJECT_NUMBER - digit) / 10)
        ) {
            isSafe = false;
        } else if (isSafe) {
            value = value * 10 + digit;
        }
        next++;
    }

    return { value, next, isSafe };
}

/**
 * Models only the loader's whitespace/comment separators between the three
 * header tokens. The caller fails closed only after confirming the complete
 * loose header for the separator-size limit. A shared work budget also bounds
 * repeated scans of intentionally ambiguous literal/stream content.
 */
function scanHeaderSeparators(
    bytes: Uint8Array,
    offset: number,
    budget: HeaderScanBudget,
    allowEmpty = false
): HeaderSeparators | undefined {
    let next = offset;
    let count = 0;
    let sawSeparator = false;
    let exceedsLimit = false;

    for (;;) {
        while (isPdfWhitespace(bytes[next])) {
            consumeHeaderScanWork(budget);
            sawSeparator = true;
            count++;
            if (count > MAX_OBJECT_HEADER_SEPARATOR_BYTES) {
                exceedsLimit = true;
            }
            next++;
        }

        if (bytes[next] !== 0x25) {
            return sawSeparator || allowEmpty ? { next, exceedsLimit } : undefined;
        }

        sawSeparator = true;
        while (next < bytes.length && bytes[next] !== 0x0a && bytes[next] !== 0x0d) {
            consumeHeaderScanWork(budget);
            count++;
            if (count > MAX_OBJECT_HEADER_SEPARATOR_BYTES) {
                exceedsLimit = true;
            }
            next++;
        }
    }
}

function consumeHeaderScanWork(budget: HeaderScanBudget): void {
    if (budget.remaining === 0) {
        throw objectNumberError("Physical PDF object header compatibility scan work budget exhausted");
    }
    budget.remaining--;
}

function createHeaderScanBudget(byteLength: number): HeaderScanBudget {
    const largestMultipliableLength = Math.floor(
        Number.MAX_SAFE_INTEGER / HEADER_SCAN_WORK_MULTIPLIER
    );
    return {
        remaining:
            byteLength > largestMultipliableLength
                ? Number.MAX_SAFE_INTEGER
                : byteLength * HEADER_SCAN_WORK_MULTIPLIER,
    };
}

function isObjectKeyword(bytes: Uint8Array, offset: number): boolean {
    return bytes[offset] === 0x6f && bytes[offset + 1] === 0x62 && bytes[offset + 2] === 0x6a;
}

/**
 * Returns the largest number in a bounded loader-like `N G obj` candidate.
 * It deliberately can overestimate: a literal string or stream can contain
 * the same loose byte sequence. Overestimation reserves a safe later object
 * number; over-limit separators, unsafe matches, and exhausted scan work fail
 * closed. This is not an authoritative PDF parse.
 */
function largestPhysicalHeaderObjectNumber(pdfBytes: Uint8Array): number {
    let largest = 0;
    const budget = createHeaderScanBudget(pdfBytes.length);

    for (let offset = 0; offset < pdfBytes.length; offset++) {
        if (!isAsciiDigit(pdfBytes[offset]) || isAsciiDigit(pdfBytes[offset - 1])) {
            continue;
        }

        const object = readHeaderInteger(pdfBytes, offset);
        const generationSeparator = scanHeaderSeparators(pdfBytes, object.next, budget);
        if (
            generationSeparator === undefined ||
            !isAsciiDigit(pdfBytes[generationSeparator.next])
        ) {
            offset = object.next - 1;
            continue;
        }

        const generation = readHeaderInteger(pdfBytes, generationSeparator.next);
        const keywordSeparator = scanHeaderSeparators(pdfBytes, generation.next, budget, true);
        if (keywordSeparator === undefined || !isObjectKeyword(pdfBytes, keywordSeparator.next)) {
            offset = object.next - 1;
            continue;
        }

        if (generationSeparator.exceedsLimit || keywordSeparator.exceedsLimit) {
            throw objectNumberError(
                "Physical PDF object header separator exceeds the compatibility scan limit"
            );
        }

        if (!object.isSafe || !generation.isSafe) {
            throw objectNumberError(
                "Physical PDF object header contains an unsupported object or generation number"
            );
        }

        largest = Math.max(largest, object.value);
        offset = keywordSeparator.next + 2;
    }

    return largest;
}

/**
 * Restores the largest object number after `PDFDocument.load` has populated
 * its context. pdf-lib-incremental-save can omit physical ObjStm and XRef
 * container references from that context. The bounded raw-header scan closes
 * that writer-collision gap but is intentionally only a compatibility
 * heuristic; see docs/pdf-lib-incremental-save-limitations.md.
 */
export function restoreLargestObjectNumber(
    pdfBytes: Uint8Array,
    context: ObjectNumberContext
): void {
    assertSupportedObjectNumber(context.largestObjectNumber, "PDF context object number");

    let largest = context.largestObjectNumber;
    for (const [ref] of context.enumerateIndirectObjects()) {
        assertSupportedObjectNumber(ref.objectNumber, "Parsed PDF object number");
        largest = Math.max(largest, ref.objectNumber);
    }

    largest = Math.max(largest, largestPhysicalHeaderObjectNumber(pdfBytes));
    assertSupportedObjectNumber(largest, "Computed PDF object number");
    context.largestObjectNumber = largest;
}

/** PDFStreamWriter's default objectsPerStream; one ObjStm reference per chunk. */
const WRITER_OBJECTS_PER_STREAM = 50;

/**
 * Counts the context's indirect objects without materializing them.
 * `enumerateIndirectObjects()` allocates an array and sorts it, which is pure
 * waste when only the count is wanted. pdf-lib keeps the objects in a Map whose
 * `.size` is O(1) but declares the field private, so read it defensively and
 * fall back to the public enumeration if a future build changes that shape.
 */
function countIndirectObjects(context: ObjectNumberContext): number {
    const objects: unknown = (context as unknown as { indirectObjects?: unknown }).indirectObjects;
    if (objects instanceof Map) {
        return objects.size;
    }
    return context.enumerateIndirectObjects().length;
}

/**
 * PDFStreamWriter invents object-stream container and cross-reference-stream
 * references starting at largestObjectNumber + 1, outside checkedRegister. It
 * creates one container per chunk of WRITER_OBJECTS_PER_STREAM compressed saved
 * objects plus one cross-reference stream, then writes /Size one past the
 * highest number it used. Counting every indirect object rather than only the
 * compressed saved subset keeps the bound conservative without walking the
 * snapshot, so proving headroom for (containers + 2) keeps every invented
 * number inside the supported safe-integer range.
 *
 * saveIncremental only reaches that writer when pdfFileDetails.useObjectStreams
 * is set; the classic PDFWriter invents no references at all, and its /Size of
 * largestObjectNumber + 1 is already bounded by MAX_SUPPORTED_OBJECT_NUMBER.
 * Reserving for it too would reject classic updates that remain safe.
 */
export function assertIncrementalWriterHeadroom(
    context: ObjectNumberContext & { pdfFileDetails: { useObjectStreams: boolean } }
): void {
    if (!context.pdfFileDetails.useObjectStreams) {
        return;
    }
    const containers = Math.ceil(countIndirectObjects(context) / WRITER_OBJECTS_PER_STREAM);
    assertSupportedObjectNumber(
        context.largestObjectNumber + containers + 2,
        "PDF incremental save object allocation"
    );
}

/**
 * Bytes of the file tail scanned for the terminal `startxref`. A conforming
 * trailer keeps it within the last few dozen bytes; 2 KiB absorbs generous
 * padding and stray comments without ever walking a large file.
 */
const MAX_PDF_TAIL_SCAN = 2048;

/** Enough bytes at the recorded offset to classify `xref` or an `N G obj` header. */
const MAX_XREF_PROBE_BYTES = 40;

function isXrefKeyword(bytes: Uint8Array): boolean {
    return (
        bytes[0] === 0x78 &&
        bytes[1] === 0x72 &&
        bytes[2] === 0x65 &&
        bytes[3] === 0x66 &&
        isPdfWhitespace(bytes[4])
    );
}

/**
 * Classifies the physical cross-reference section the file's terminal
 * `startxref` points at. Returns undefined whenever the tail cannot be read
 * with confidence -- notably a linearized `startxref 0` sentinel, an offset
 * past the end of the file, or bytes that are neither `xref` nor an object
 * header. This is a compatibility heuristic, not a PDF parse.
 */
function lastRevisionXrefFormat(pdfBytes: Uint8Array): "table" | "stream" | undefined {
    const decoder = new TextDecoder("latin1");
    const tail = pdfBytes.subarray(Math.max(0, pdfBytes.length - MAX_PDF_TAIL_SCAN));
    // Bounded quantifiers: these bytes are untrusted PDF input.
    const matches = [...decoder.decode(tail).matchAll(/startxref\s{1,16}(\d{1,20})/g)];
    const digits = matches.at(-1)?.[1];
    if (digits === undefined) {
        return undefined;
    }

    const offset = Number(digits);
    if (!Number.isSafeInteger(offset) || offset <= 0 || offset >= pdfBytes.length) {
        return undefined;
    }

    const probe = pdfBytes.subarray(offset, offset + MAX_XREF_PROBE_BYTES);
    if (isXrefKeyword(probe)) {
        return "table";
    }
    if (/^\d{1,20}\s{1,4}\d{1,5}\s{1,4}obj/.test(decoder.decode(probe))) {
        return "stream";
    }
    return undefined;
}

/**
 * Chooses the cross-reference format for the next incremental section.
 *
 * pdf-lib sets `pdfFileDetails.useObjectStreams` in the xref-stream parser's
 * constructor, so ANY cross-reference stream anywhere in the file's history
 * turns it on. An update chains to the LAST revision through /Prev, and a
 * section whose /Prev points at the other format is what macOS CoreGraphics
 * and strict Ghostscript refuse to follow. Sniff the physical format at the
 * final startxref offset instead.
 *
 * When the tail cannot be read, fall back to the classic table -- do NOT leave
 * pdf-lib's flag alone. Leaving it is not neutral: for a hybrid-history file
 * (xref-stream base, classic-table last revision, exactly what v0.2.0 itself
 * emitted) the flag is on, so an unreadable tail would append a cross-reference
 * STREAM over a classic TABLE. That is the inverse of the shape this fix
 * removes and strictly worse than v0.2.0, which appended a table there.
 * Clearing the flag reproduces v0.2.0's behaviour exactly for the whole
 * unreadable-tail class, which is what makes "never worse than v0.2.0" a total
 * guarantee. The accepted cost is that a stream-terminated file whose tail we
 * cannot read keeps v0.2.0's macOS bug: not a regression, and better than
 * emitting a shape no reader accepts.
 */
export function applyLastRevisionXrefFormat(
    pdfBytes: Uint8Array,
    context: { pdfFileDetails: { useObjectStreams: boolean } }
): void {
    context.pdfFileDetails.useObjectStreams = lastRevisionXrefFormat(pdfBytes) === "stream";
}

/**
 * Allocate through pdf-lib only while its next object number remains exactly
 * representable. Callers must use this for every mutation-time registration.
 */
export function checkedRegister<T extends PDFObject>(
    context: ObjectNumberContext & { register(object: T): PDFRef },
    object: T
): PDFRef {
    assertSupportedObjectNumber(context.largestObjectNumber, "PDF context object number");
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
