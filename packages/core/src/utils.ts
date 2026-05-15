import { TimestampError, TimestampErrorCode } from "./types.js";

/**
 * Lookup table mapping ASCII char codes for 0-9, A-F, a-f to their nibble value (0-15).
 * Any other index returns 0 (from Uint8Array initialisation), which matches the prior
 * `parseInt` behaviour for the post-replace() path where only valid hex chars remain.
 */
const NIBBLE_LOOKUP = (() => {
    const t = new Uint8Array(256);
    for (let i = 0; i < 10; i++) t[48 + i] = i; // '0'-'9'
    for (let i = 0; i < 6; i++) {
        t[65 + i] = 10 + i; // 'A'-'F'
        t[97 + i] = 10 + i; // 'a'-'f'
    }
    return t;
})();

/**
 * Converts a hex string to a Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
    // Remove any non-hex characters and handle odd length
    const cleanHex = hex.replace(/[^0-9a-fA-F]/g, "");
    const paddedHex = cleanHex.length % 2 ? "0" + cleanHex : cleanHex;

    const len = paddedHex.length;
    const bytes = new Uint8Array(len / 2);
    for (let i = 0; i < len; i += 2) {
        const hi = NIBBLE_LOOKUP[paddedHex.charCodeAt(i)] ?? 0;
        const lo = NIBBLE_LOOKUP[paddedHex.charCodeAt(i + 1)] ?? 0;
        bytes[i >> 1] = (hi << 4) | lo;
    }
    return bytes;
}

/**
 * Lookup table mapping 0..255 to its 2-char lowercase hex string.
 * Pre-computed once at module load to avoid per-byte `toString(16).padStart(2)` cost.
 */
const HEX_LOOKUP: readonly string[] = Array.from({ length: 256 }, (_, i) =>
    i.toString(16).padStart(2, "0")
);

/**
 * Returns the ArrayBuffer view of a Uint8Array without copying when possible.
 *
 * The library used to write `bytes.slice().buffer` defensively to hand
 * pkijs/asn1js a plain ArrayBuffer, which always allocates and copies.
 * `pkijs.fromBER` and Web Crypto don't mutate the input, so we can hand
 * over the backing buffer directly when the Uint8Array fully owns it.
 * For partial views (created with `new Uint8Array(buffer, offset, length)`
 * or `subarray`), we still slice -- but only the relevant span, not the
 * full backing buffer.
 *
 * L3 from REVIEW-2026-02-09 -- replaces 20+ `.slice().buffer` calls.
 */
export function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
    if (u8.byteOffset === 0 && u8.byteLength === u8.buffer.byteLength) {
        // Uint8Array owns its entire buffer -- return directly, no copy.
        // The SharedArrayBuffer case (Node Worker threads etc.) is handled by
        // the slice fallback above; here, ArrayBuffer is the only path.
        if (u8.buffer instanceof ArrayBuffer) {
            return u8.buffer;
        }
    }
    return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

/**
 * Converts a Uint8Array or ArrayBuffer to a hex string.
 */
export function bytesToHex(bytes: Uint8Array | ArrayBuffer): string {
    const uint8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let hex = "";
    for (const b of uint8) {
        hex += HEX_LOOKUP[b] ?? "";
    }
    return hex;
}

/**
 * Converts a buffer to an uppercase hex string (common for PDF hex strings).
 */
export function bufferToHexUpper(buffer: Uint8Array | ArrayBuffer): string {
    return bytesToHex(buffer).toUpperCase();
}

/**
 * Extracts the bytes from a PDF that are covered by a ByteRange.
 *
 * @param pdfBytes - The full PDF bytes
 * @param byteRange - The [offset1, length1, offset2, length2] array
 * @returns The concatenated bytes covered by the range
 */
export function extractBytesFromByteRange(
    pdfBytes: Uint8Array,
    byteRange: [number, number, number, number]
): Uint8Array {
    const [offset1, length1, offset2, length2] = byteRange;

    // Security check: Verify ranges are within bounds and non-negative to prevent DoS via huge allocations
    if (
        isNaN(offset1) ||
        isNaN(length1) ||
        isNaN(offset2) ||
        isNaN(length2) ||
        offset1 < 0 ||
        length1 < 0 ||
        offset2 < 0 ||
        length2 < 0
    ) {
        throw new TimestampError(
            TimestampErrorCode.PDF_ERROR,
            "Invalid ByteRange: values must be non-negative numbers"
        );
    }

    if (offset1 + length1 > pdfBytes.length) {
        throw new TimestampError(
            TimestampErrorCode.PDF_ERROR,
            `Invalid ByteRange: range 1 [${offset1.toString()}, ${(offset1 + length1).toString()}] out of bounds for PDF of length ${pdfBytes.length.toString()}`
        );
    }
    if (offset2 + length2 > pdfBytes.length) {
        throw new TimestampError(
            TimestampErrorCode.PDF_ERROR,
            `Invalid ByteRange: range 2 [${offset2.toString()}, ${(offset2 + length2).toString()}] out of bounds for PDF of length ${pdfBytes.length.toString()}`
        );
    }
    // A legitimate signed-PDF ByteRange covers everything except the signature hex string,
    // so length1 + length2 <= pdfBytes.length. Reject anything that would allocate more
    // than the PDF itself.
    if (length1 + length2 > pdfBytes.length) {
        throw new TimestampError(
            TimestampErrorCode.PDF_ERROR,
            `Invalid ByteRange: combined length ${(length1 + length2).toString()} exceeds PDF length ${pdfBytes.length.toString()}`
        );
    }

    const result = new Uint8Array(length1 + length2);
    result.set(pdfBytes.subarray(offset1, offset1 + length1), 0);
    result.set(pdfBytes.subarray(offset2, offset2 + length2), length1);

    return result;
}
