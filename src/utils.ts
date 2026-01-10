/**
 * Converts a hex string to a Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
    // Remove any non-hex characters and handle odd length
    const cleanHex = hex.replace(/[^0-9a-fA-F]/g, "");
    const paddedHex = cleanHex.length % 2 ? "0" + cleanHex : cleanHex;

    const bytes = new Uint8Array(paddedHex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(paddedHex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

/**
 * Converts a Uint8Array or ArrayBuffer to a hex string.
 */
export function bytesToHex(bytes: Uint8Array | ArrayBuffer): string {
    const uint8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    return Array.from(uint8)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
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

    // Concatenate the two ranges
    const range1 = pdfBytes.slice(offset1, offset1 + length1);
    const range2 = pdfBytes.slice(offset2, offset2 + length2);

    const result = new Uint8Array(length1 + length2);
    result.set(range1, 0);
    result.set(range2, length1);

    return result;
}
