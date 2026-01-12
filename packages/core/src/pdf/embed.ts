import type { PreparedPDF } from "./prepare.js";
import { bufferToHexUpper, extractBytesFromByteRange } from "../utils.js";

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

    // Convert token to hex string (uppercase as usual in PDF Content)
    const tokenHex = bufferToHexUpper(timestampToken);

    // Check if token fits in placeholder
    if (tokenHex.length > contentsPlaceholderLength) {
        throw new Error(
            `Timestamp token (${tokenHex.length.toString()} hex chars) is larger than placeholder (${contentsPlaceholderLength.toString()} hex chars). ` +
                `Increase signatureSize to at least ${Math.ceil(timestampToken.length * 1.1).toString()} bytes.`
        );
    }

    // Create new PDF bytes with the token
    const result = new Uint8Array(bytes);

    // Pad the token hex to fill the placeholder with zeros.
    const paddedHex = tokenHex.padEnd(contentsPlaceholderLength, "0");

    // Replace the placeholder content with the padded hex token
    const tokenHexBytes = new TextEncoder().encode(paddedHex);
    for (let i = 0; i < tokenHexBytes.length; i++) {
        const b = tokenHexBytes[i];
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
    return extractBytesFromByteRange(preparedPdf.bytes, preparedPdf.byteRange);
}
