import type { PreparedPDF } from "./prepare.js";

/**
 * Embeds a timestamp token into a prepared PDF by replacing the placeholder content.
 *
 * @param preparedPdf - The prepared PDF with placeholder
 * @param timestampToken - The DER-encoded timestamp token (ContentInfo with SignedData)
 * @returns The final PDF with embedded timestamp
 */
export function embedTimestampToken(
    preparedPdf: PreparedPDF,
    timestampToken: Uint8Array
): Uint8Array {
    const { bytes, contentsOffset, contentsPlaceholderLength } = preparedPdf;

    // Convert token to hex string
    const tokenHex = bufferToHex(timestampToken);

    // Check if token fits in placeholder
    if (tokenHex.length > contentsPlaceholderLength) {
        throw new Error(
            `Timestamp token (${tokenHex.length.toString()} hex chars) is larger than placeholder (${contentsPlaceholderLength.toString()} hex chars). ` +
                `Increase signatureSize to at least ${Math.ceil(timestampToken.length * 1.1).toString()} bytes.`
        );
    }

    // Pad the token hex to fill the placeholder
    const paddedHex = tokenHex.padEnd(contentsPlaceholderLength, "0");

    // Create new PDF bytes with the token
    const result = new Uint8Array(bytes);

    // Replace the placeholder content with the actual token
    const hexBytes = new TextEncoder().encode(paddedHex);
    for (let i = 0; i < hexBytes.length; i++) {
        const b = hexBytes[i];
        if (b !== undefined) {
            result[contentsOffset + i] = b;
        }
    }

    return result;
}

/**
 * Extracts the bytes that should be hashed for the timestamp.
 * These are the bytes covered by the ByteRange.
 *
 * @param preparedPdf - The prepared PDF
 * @returns The concatenated bytes that should be hashed
 */
export function extractBytesToHash(preparedPdf: PreparedPDF): Uint8Array {
    const { bytes, byteRange } = preparedPdf;
    const [offset1, length1, offset2, length2] = byteRange;

    // Concatenate the two ranges
    const range1 = bytes.slice(offset1, offset1 + length1);
    const range2 = bytes.slice(offset2, offset2 + length2);

    const result = new Uint8Array(length1 + length2);
    result.set(range1, 0);
    result.set(range2, length1);

    return result;
}

/**
 * Converts a buffer to a hex string.
 */
function bufferToHex(buffer: Uint8Array): string {
    return Array.from(buffer)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}
