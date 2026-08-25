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
