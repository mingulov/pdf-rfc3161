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
});
