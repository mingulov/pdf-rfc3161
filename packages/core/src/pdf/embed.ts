import type { PreparedPDF } from "./prepare.js";
import { bufferToHexUpper, extractBytesFromByteRange } from "../utils.js";
import { TimestampError, TimestampErrorCode } from "../types.js";

function pdfError(message: string): TimestampError {
    return new TimestampError(TimestampErrorCode.PDF_ERROR, message);
}

/**
 * Typed placeholder-too-small failure. Carries the `PDF_ERROR` code like the
 * historical message-only error, so existing code-based handling keeps
 * working, but the `timestampPdf` retry loop matches on this type instead of
 * the message text. `requiredSignatureSize` is a lower bound for the next
 * reservation, in token bytes.
 */
export class PlaceholderTooSmallError extends TimestampError {
    public readonly requiredSignatureSize: number;

    constructor(requiredSignatureSize: number, message: string) {
        super(TimestampErrorCode.PDF_ERROR, message);
        this.name = "PlaceholderTooSmallError";
        this.requiredSignatureSize = requiredSignatureSize;
    }
}

/**
 * Rejects a malformed `PreparedPDF` before any byte is written. Out-of-range
 * typed-array writes are silently ignored, so without these checks a bad
 * offset would produce a truncated token whose failure surfaces much later.
 */
function assertEmbeddablePreparedPdf(preparedPdf: PreparedPDF): void {
    const { bytes, byteRange, contentsOffset, contentsPlaceholderLength } = preparedPdf;
    if (!(bytes instanceof Uint8Array)) {
        throw pdfError("PreparedPDF bytes must be a Uint8Array");
    }
    const [offset1, length1, offset2, length2] = byteRange;
    if (
        !Number.isSafeInteger(offset1) ||
        offset1 < 0 ||
        !Number.isSafeInteger(length1) ||
        length1 < 0 ||
        !Number.isSafeInteger(offset2) ||
        offset2 < 0 ||
        !Number.isSafeInteger(length2) ||
        length2 < 0
    ) {
        throw pdfError("PreparedPDF byteRange must contain four non-negative safe integers");
    }
    if (
        !Number.isSafeInteger(contentsOffset) ||
        contentsOffset < 0 ||
        !Number.isSafeInteger(contentsPlaceholderLength) ||
        contentsPlaceholderLength < 0
    ) {
        throw pdfError("PreparedPDF contents offsets must be non-negative safe integers");
    }
    if (contentsPlaceholderLength % 2 !== 0) {
        throw pdfError(
            "PreparedPDF contents reservation must hold an even number of hex characters"
        );
    }
    // The window needs one byte on each side for the `<` and `>` delimiters.
    // Subtracted form keeps the comparison exact for hostile magnitudes.
    if (contentsOffset < 1 || contentsPlaceholderLength > bytes.length - contentsOffset - 1) {
        throw pdfError("PreparedPDF contents reservation is outside the PDF bytes");
    }
    if (
        bytes[contentsOffset - 1] !== 0x3c ||
        bytes[contentsOffset + contentsPlaceholderLength] !== 0x3e
    ) {
        throw pdfError("PreparedPDF contents reservation is missing its hex string delimiters");
    }
    if (
        offset1 !== 0 ||
        length1 !== contentsOffset - 1 ||
        offset2 !== contentsOffset + contentsPlaceholderLength + 1 ||
        offset2 + length2 !== bytes.length
    ) {
        throw pdfError("PreparedPDF ByteRange hole must exactly exclude its Contents hex string");
    }
}

/**
 * Embeds a timestamp token into a prepared PDF by replacing the placeholder content.
 *
 * @param preparedPdf - The prepared PDF with placeholder
 * @param timestampToken - The DER-encoded timestamp token (ContentInfo with SignedData)
 * @returns The final PDF with embedded timestamp
 * @throws PlaceholderTooSmallError (a `PDF_ERROR` TimestampError carrying
 *   `requiredSignatureSize`) if the timestamp token is larger than the
 *   reserved placeholder. The signing path in `timestampPdf` recognises this
 *   by type and retries with a bigger reservation; if you call
 *   `embedTimestampToken` directly, raise `signatureSize` in
 *   `preparePdfForTimestamp` to the suggested byte count.
 * @throws TimestampError with `PDF_ERROR` if the prepared PDF is malformed.
 */
export function embedTimestampToken(
    preparedPdf: PreparedPDF,
    timestampToken: Uint8Array
): Uint8Array {
    assertEmbeddablePreparedPdf(preparedPdf);
    const { bytes, contentsOffset, contentsPlaceholderLength } = preparedPdf;

    // Convert token to hex string (uppercase as usual in PDF Content)
    const tokenHex = bufferToHexUpper(timestampToken);

    // Check if token fits in placeholder. The retry loop in index.ts matches
    // on the PlaceholderTooSmallError type, never on this message text.
    if (tokenHex.length > contentsPlaceholderLength) {
        const requiredSignatureSize = Math.ceil(timestampToken.length * 1.1);
        throw new PlaceholderTooSmallError(
            requiredSignatureSize,
            `Timestamp token (${tokenHex.length.toString()} hex chars) is larger than placeholder (${contentsPlaceholderLength.toString()} hex chars). ` +
                `Increase signatureSize to at least ${requiredSignatureSize.toString()} bytes.`
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
