import { test, expect, describe } from "vitest";
import {
    hexToBytes,
    bytesToHex,
    bufferToHexUpper,
    extractBytesFromByteRange,
} from "../../../core/src/utils.js";

describe("Utility Functions", () => {
    test("hexToBytes should convert hex string to Uint8Array", () => {
        const hex = "001122aabbCC";
        const bytes = hexToBytes(hex);
        expect(bytes).toEqual(new Uint8Array([0, 17, 34, 170, 187, 204]));
    });

    test("hexToBytes should handle odd length by padding", () => {
        const hex = "123";
        const bytes = hexToBytes(hex);
        expect(bytes).toEqual(new Uint8Array([1, 35])); // '0123'
    });

    test("bytesToHex should convert Uint8Array to hex string", () => {
        const bytes = new Uint8Array([0, 17, 34, 170, 187, 204]);
        expect(bytesToHex(bytes)).toBe("001122aabbcc");
    });

    test("bufferToHexUpper should convert to uppercase hex", () => {
        const bytes = new Uint8Array([0, 17, 255]);
        expect(bufferToHexUpper(bytes)).toBe("0011FF");
    });

    test("extractBytesFromByteRange should extract and concatenate ranges", () => {
        const data = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        const byteRange: [number, number, number, number] = [0, 2, 5, 3];
        const result = extractBytesFromByteRange(data, byteRange);
        // Range 1: [0, 2] -> 0, 1
        // Range 2: [5, 3] -> 5, 6, 7
        expect(result).toEqual(new Uint8Array([0, 1, 5, 6, 7]));
    });

    describe("extractBytesFromByteRange security", () => {
        test("should throw when given large lengths (DoS protection)", () => {
            const data = new Uint8Array(10);
            const hugeLength = 2 * 1024 * 1024 * 1024 - 1; // ~2GB
            const byteRange: [number, number, number, number] = [0, hugeLength, 0, 0];

            expect(() => extractBytesFromByteRange(data, byteRange)).toThrow(/Invalid ByteRange/);
        });

        test("should throw on out of bounds instead of padding", () => {
            const data = new Uint8Array(10);
            const byteRange: [number, number, number, number] = [0, 20, 0, 0];

            expect(() => extractBytesFromByteRange(data, byteRange)).toThrow(/out of bounds/);
        });

        test("should throw on negative values", () => {
            const data = new Uint8Array(10);
            const byteRange: [number, number, number, number] = [0, -1, 0, 0];

            expect(() => extractBytesFromByteRange(data, byteRange)).toThrow(/non-negative numbers/);
        });

        test("should throw on NaN values", () => {
            const data = new Uint8Array(10);
            const byteRange: [number, number, number, number] = [0, NaN, 0, 0];

            expect(() => extractBytesFromByteRange(data, byteRange)).toThrow(/non-negative numbers/);
        });

        test("should throw when combined length exceeds PDF length", () => {
            // Crafted overlap: both ranges are individually valid (within bounds)
            // but together allocate more than the PDF itself.
            const data = new Uint8Array(10);
            const byteRange: [number, number, number, number] = [0, 8, 0, 8];

            expect(() => extractBytesFromByteRange(data, byteRange)).toThrow(/combined length/);
        });
    });
});
