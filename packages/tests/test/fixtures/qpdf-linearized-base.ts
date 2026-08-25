import { Buffer } from "node:buffer";

/**
 * A qpdf 11.9.0 --linearize output derived from packages/demo/test.pdf.
 *
 * The source artifact was checked with the pinned qpdf 11.9.0 oracle before
 * encoding. Keeping the fixture in base64 makes ordinary unit tests fully
 * tool-independent while preserving the physical linearization layout.
 */
const QPDF_11_9_LINEARIZED_BASE64 = [
    "JVBERi0xLjQKJb/3ov4KMiAwIG9iago8PCAvTGluZWFyaXplZCAxIC9MIDEwNzkgL0ggWyA1MjkgMTE2IF0gL08gNSAvRSA4NTQg",
    "L04gMSAvVCA5MjEgPj4KZW5kb2JqCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg",
    "ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKeHJlZgoyIDUK",
    "MDAwMDAwMDAxNSAwMDAwMCBuIAowMDAwMDAwNDgwIDAwMDAwIG4gCjAwMDAwMDA1MjkgMDAwMDAgbiAKMDAwMDAwMDY0NSAwMDAw",
    "MCBuIAowMDAwMDAwNzM0IDAwMDAwIG4gCnRyYWlsZXIgPDwgL1Jvb3QgMyAwIFIgL1NpemUgNyAvUHJldiA5MTMgICAgICAgICAg",
    "ICAgICAgICAgL0lEIFs8MGJkMjM4NWVmYjlmMWNlNGQwN2Y4YWY0NDYyZDg1ZGE+PDBiZDIzODVlZmI5ZjFjZTRkMDdmOGFmNDQ2",
    "MmQ4NWRhPl0gPj4Kc3RhcnR4cmVmCjAKJSVFT0YKMyAwIG9iago8PCAvUGFnZXMgMSAwIFIgL1R5cGUgL0NhdGFsb2cgPj4KZW5k",
    "b2JqCjQgMCBvYmoKPDwgL0ZpbHRlciAvRmxhdGVEZWNvZGUgL1MgMzYgL0xlbmd0aCAzOSA+PgpzdHJlYW0KeJxjYGBgAiJBBhC4",
    "yIAAEDZQjoEFSZQJihkYIhlY2Q8wAABRYALnCmVuZHN0cmVhbQplbmRvYmoKNSAwIG9iago8PCAvQ29udGVudHMgNiAwIFIgL01l",
    "ZGlhQm94IFsgMCAwIDYxMiA3OTIgXSAvUGFyZW50IDEgMCBSIC9UeXBlIC9QYWdlID4+CmVuZG9iago2IDAgb2JqCjw8IC9MZW5n",
    "dGggNTAgL0ZpbHRlciAvRmxhdGVEZWNvZGUgPj4Kc3RyZWFtCniccwpR0HczVDAyUQhJUzA0MFAwB+KQFAUNVyNXhZDU4hKFABc3",
    "TYWQLAXXEADd9Ap7ZW5kc3RyZWFtCmVuZG9iagoxIDAgb2JqCjw8IC9Db3VudCAxIC9LaWRzIFsgNSAwIFIgXSAvVHlwZSAvUGFn",
    "ZXMgPj4KZW5kb2JqCnhyZWYKMCAyCjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAwMDg1NCAwMDAwMCBuIAp0cmFpbGVyIDw8IC9T",
    "aXplIDIgL0lEIFs8MGJkMjM4NWVmYjlmMWNlNGQwN2Y4YWY0NDYyZDg1ZGE+PDBiZDIzODVlZmI5ZjFjZTRkMDdmOGFmNDQ2MmQ4",
    "NWRhPl0gPj4Kc3RhcnR4cmVmCjIxNgolJUVPRgo=",
].join("");

export type LinearizedTerminalTarget = "early" | "main";

/**
 * Returns a fresh qpdf-linearized base PDF. The encoded source uses the
 * first-page (early) xref as its terminal pointer. qpdf also accepts the
 * main-xref form, which is represented by an equal-width terminal rewrite.
 */
export function qpdfLinearizedBasePdf(
    terminalTarget: LinearizedTerminalTarget = "early"
): Uint8Array {
    const bytes = new Uint8Array(Buffer.from(QPDF_11_9_LINEARIZED_BASE64, "base64"));
    if (terminalTarget === "early") return bytes;

    const source = "startxref\n216\n%%EOF";
    const replacement = "startxref\n913\n%%EOF";
    const text = Buffer.from(bytes).toString("latin1");
    const offset = text.lastIndexOf(source);
    if (offset < 0) throw new Error("Linearized fixture has no terminal startxref");
    bytes.set(new TextEncoder().encode(replacement), offset);
    return bytes;
}
