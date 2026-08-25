import { MAX_PDF_SIZE } from "../constants.js";

/** A physical indirect-object identity used only for raw signature binding. */
export interface PdfObjectIdentity {
    objectNumber: number;
    generationNumber: number;
}

/** The raw owner and form of a selected signature /Contents value. */
export interface PdfContentsBinding {
    owner: PdfObjectIdentity;
    /** True when the selected signature dictionary is a direct /V value. */
    directValue: boolean;
    /** Archive-only strict discovery requires the exact document-timestamp marker pair. */
    requireDocumentTimestamp?: boolean;
}

type ByteRange = [number, number, number, number];

interface ParsedValue {
    kind: "array" | "dictionary" | "hex" | "literal" | "name" | "number" | "other" | "reference";
    start: number;
    end: number;
    integer?: number;
    name?: string;
    array?: ParsedValue[];
    dictionary?: ParsedDictionary;
}

interface ParsedDictionaryEntry {
    name: string;
    value: ParsedValue;
}

interface ParsedDictionary {
    start: number;
    end: number;
    entries: ParsedDictionaryEntry[];
    directV: boolean;
    root: boolean;
}

interface PdfContentsOccurrence {
    start: number;
    end: number;
    byteRange?: ByteRange;
    rfc3161SubFilter: boolean;
    documentTimestamp: boolean;
    directV: boolean;
    root: boolean;
}

interface PhysicalObjectOccurrence {
    contents: PdfContentsOccurrence[];
    xrefPrevious?: RevisionPrevious;
    hasLinearizedEntry: boolean;
    linearizedLength?: number;
}

interface PhysicalObjectFrame {
    end: number;
    xrefPrevious?: RevisionPrevious;
    hasLinearizedEntry: boolean;
    linearizedLength?: number;
}

interface RevisionPrevious {
    present: boolean;
    valid: boolean;
    value?: number;
}

interface RevisionBoundary {
    markerStart: number;
    xrefOffset: number;
    eofEnd: number;
    end: number;
}

interface ClassicXrefFrame {
    start: number;
    end: number;
    previous: RevisionPrevious;
}

interface FramedRevisionSegment {
    firstObject?: PhysicalObjectFrame;
    linearizedObjectCount: number;
    classicXrefs: ClassicXrefFrame[];
}

interface ParseState {
    bytes: Uint8Array;
    limit: number;
    dictionaries: ParsedDictionary[];
    furthestRead: number;
    retainedStructures: number;
}

interface IndirectObjectHeader extends PdfObjectIdentity {
    bodyStart: number;
}

const PDF_WHITESPACE = new Set([0x00, 0x09, 0x0a, 0x0c, 0x0d, 0x20]);
const MAX_LEXICAL_NESTING = 512;
const MAX_SIGNATURE_OCCURRENCES_PER_OBJECT = 1024;
const MAX_PHYSICAL_OBJECT_ATTEMPTS = 1_000_000;
const MAX_SIGNATURE_LEXICAL_WORK = MAX_PDF_SIZE * 4;
const MAX_RETAINED_PARSE_STRUCTURES_PER_FRAME = 100_000;
const MAX_REVISION_BOUNDARIES = 4_096;

/** Bounded-work observations for the internal physical signature scanner. */
interface PdfSignatureOccurrenceScanStats {
    lexicalBytes: number;
    physicalObjectAttempts: number;
    revisionBoundaryComparisons: number;
}

function observeParse(state: ParseState, position: number): void {
    state.furthestRead = Math.max(state.furthestRead, Math.min(position, state.limit));
}

/**
 * A parsed physical object or classic-xref trailer must not retain attacker-
 * controlled arrays or dictionaries in proportion to the whole PDF. Array
 * elements retain a ParsedValue; dictionary entries retain their key names.
 */
function retainParseStructure(state: ParseState, count = 1): void {
    if (count > MAX_RETAINED_PARSE_STRUCTURES_PER_FRAME - state.retainedStructures) {
        throw new Error("PDF signature occurrence scan exceeds the retained structure limit");
    }
    state.retainedStructures += count;
}

function retainParsedValue(state: ParseState, value: ParsedValue): ParsedValue {
    retainParseStructure(state);
    return value;
}

function isPdfWhitespace(byte: number | undefined): boolean {
    return byte !== undefined && PDF_WHITESPACE.has(byte);
}

function isPdfDelimiter(byte: number | undefined): boolean {
    return (
        byte === undefined ||
        isPdfWhitespace(byte) ||
        byte === 0x28 ||
        byte === 0x29 ||
        byte === 0x3c ||
        byte === 0x3e ||
        byte === 0x5b ||
        byte === 0x5d ||
        byte === 0x7b ||
        byte === 0x7d ||
        byte === 0x2f ||
        byte === 0x25
    );
}

function matchesAscii(bytes: Uint8Array, index: number, text: string): boolean {
    if (index < 0 || index + text.length > bytes.length) return false;
    for (let offset = 0; offset < text.length; offset += 1) {
        if (bytes[index + offset] !== text.charCodeAt(offset)) return false;
    }
    return true;
}

function matchesKeyword(bytes: Uint8Array, index: number, text: string, limit: number): boolean {
    return (
        index >= 0 &&
        index + text.length <= limit &&
        isPdfDelimiter(bytes[index - 1]) &&
        matchesAscii(bytes, index, text) &&
        isPdfDelimiter(bytes[index + text.length])
    );
}

function skipPdfWhitespace(bytes: Uint8Array, index: number, limit: number): number {
    let result = index;
    while (result < limit && isPdfWhitespace(bytes[result])) result += 1;
    return result;
}

/**
 * Classic xref control lines accept horizontal tabs, spaces, carriage returns,
 * line feeds, and form feeds. NUL is not accepted between `xref` and its
 * subsection columns even though it is a generic PDF lexical whitespace byte.
 */
function skipXrefControlWhitespace(bytes: Uint8Array, index: number, limit: number): number {
    let result = index;
    while (
        result < limit &&
        (bytes[result] === 0x09 ||
            bytes[result] === 0x0a ||
            bytes[result] === 0x0c ||
            bytes[result] === 0x0d ||
            bytes[result] === 0x20)
    ) {
        result += 1;
    }
    return result;
}

function skipPdfWhitespaceAndComments(bytes: Uint8Array, index: number, limit: number): number {
    let result = index;
    while (result < limit) {
        if (isPdfWhitespace(bytes[result])) {
            result += 1;
            continue;
        }
        if (bytes[result] !== 0x25) return result;
        result += 1;
        while (result < limit && bytes[result] !== 0x0a && bytes[result] !== 0x0d) {
            result += 1;
        }
    }
    return result;
}

/** Skips offset-line trivia without consuming the following %%EOF marker. */
function skipPdfWhitespaceAndCommentsBeforeEof(
    bytes: Uint8Array,
    index: number,
    limit: number
): number {
    let result = index;
    while (result < limit) {
        if (isPdfWhitespace(bytes[result])) {
            result += 1;
            continue;
        }
        if (matchesAscii(bytes, result, "%%EOF") || bytes[result] !== 0x25) return result;
        result += 1;
        while (result < limit && bytes[result] !== 0x0a && bytes[result] !== 0x0d) {
            result += 1;
        }
    }
    return result;
}

function hexNibble(byte: number | undefined): number | undefined {
    if (byte === undefined) return undefined;
    if (byte >= 0x30 && byte <= 0x39) return byte - 0x30;
    if (byte >= 0x41 && byte <= 0x46) return byte - 0x41 + 10;
    if (byte >= 0x61 && byte <= 0x66) return byte - 0x61 + 10;
    return undefined;
}

function readSafeInteger(bytes: Uint8Array, index: number, limit: number): ParsedValue | undefined {
    let end = index;
    let negative = false;
    if (bytes[end] === 0x2b || bytes[end] === 0x2d) {
        negative = bytes[end] === 0x2d;
        end += 1;
    }
    const first = bytes[end];
    if (first === undefined || first < 0x30 || first > 0x39) return undefined;
    let value = 0;
    while (end < limit) {
        const byte = bytes[end];
        if (byte === undefined || byte < 0x30 || byte > 0x39) break;
        const digit = byte - 0x30;
        if (value > (Number.MAX_SAFE_INTEGER - digit) / 10) return undefined;
        value = value * 10 + digit;
        end += 1;
    }
    return { kind: "number", start: index, end, integer: negative ? -value : value };
}

/**
 * Parses the PDF numeric grammar without coercing decimal values through JS
 * number conversion. Integers retain a checked `integer`; real values are
 * still valid PDF primitives but cannot participate in structural references.
 */
function readPdfNumber(bytes: Uint8Array, index: number, limit: number): ParsedValue | undefined {
    const integer = readSafeInteger(bytes, index, limit);
    if (integer?.end === limit) return integer;

    let position = index;
    if (bytes[position] === 0x2b || bytes[position] === 0x2d) position += 1;
    const wholeStart = position;
    while (position < limit) {
        const byte = bytes[position];
        if (byte === undefined || byte < 0x30 || byte > 0x39) break;
        position += 1;
    }
    const wholeDigits = position - wholeStart;
    if (bytes[position] !== 0x2e) return undefined;
    position += 1;
    const fractionalStart = position;
    while (position < limit) {
        const byte = bytes[position];
        if (byte === undefined || byte < 0x30 || byte > 0x39) break;
        position += 1;
    }
    if (position !== limit || (wholeDigits === 0 && position === fractionalStart)) return undefined;
    return { kind: "number", start: index, end: limit };
}

/** Reads the unsigned grammar required for physical object and xref framing. */
function readUnsignedSafeInteger(
    bytes: Uint8Array,
    index: number,
    limit: number
): ParsedValue | undefined {
    const first = bytes[index];
    if (first === undefined || first < 0x30 || first > 0x39) return undefined;
    let end = index;
    let value = 0;
    while (end < limit) {
        const byte = bytes[end];
        if (byte === undefined || byte < 0x30 || byte > 0x39) break;
        const digit = byte - 0x30;
        if (value > (Number.MAX_SAFE_INTEGER - digit) / 10) return undefined;
        value = value * 10 + digit;
        end += 1;
    }
    return { kind: "number", start: index, end, integer: value };
}

function readBareToken(bytes: Uint8Array, index: number, limit: number): ParsedValue | undefined {
    if (index >= limit || isPdfDelimiter(bytes[index])) return undefined;
    let end = index;
    while (end < limit && !isPdfDelimiter(bytes[end])) end += 1;
    if (end === index) return undefined;

    const number = readPdfNumber(bytes, index, end);
    if (number !== undefined) return number;
    return { kind: "other", start: index, end };
}

function readPdfName(
    bytes: Uint8Array,
    index: number,
    limit: number
): { name: string; end: number } | undefined {
    if (bytes[index] !== 0x2f) return undefined;
    let end = index + 1;
    let name = "";
    let keepName = true;
    while (end < limit && !isPdfDelimiter(bytes[end])) {
        const byte = bytes[end];
        if (byte === 0x23) {
            if (end + 2 >= limit) return undefined;
            const high = hexNibble(bytes[end + 1]);
            const low = hexNibble(bytes[end + 2]);
            if (high === undefined || low === undefined) return undefined;
            const decoded = (high << 4) | low;
            if (decoded === 0) return undefined;
            if (keepName) name += String.fromCharCode(decoded);
            end += 3;
            continue;
        }
        if (keepName) name += String.fromCharCode(byte ?? 0);
        if (name.length > 128) {
            // The binding scanner recognizes only a handful of short standard
            // keys. Avoid allocating attacker-controlled names unnecessarily.
            name = "";
            keepName = false;
        }
        end += 1;
    }
    return { name, end };
}

function skipLiteralString(bytes: Uint8Array, index: number, limit: number): number | undefined {
    if (bytes[index] !== 0x28) return undefined;
    let depth = 1;
    let position = index + 1;
    while (position < limit) {
        const byte = bytes[position];
        if (byte === 0x5c) {
            position += 1;
            if (bytes[position] === 0x0d && bytes[position + 1] === 0x0a) position += 1;
            position += 1;
            continue;
        }
        if (byte === 0x28) {
            depth += 1;
            if (depth > MAX_LEXICAL_NESTING) return undefined;
        } else if (byte === 0x29) {
            depth -= 1;
            if (depth === 0) return position + 1;
        }
        position += 1;
    }
    return undefined;
}

function skipHexString(bytes: Uint8Array, index: number, limit: number): number | undefined {
    if (bytes[index] !== 0x3c || bytes[index + 1] === 0x3c) return undefined;
    let position = index + 1;
    while (position < limit) {
        if (bytes[position] === 0x3e) return position + 1;
        if (!isPdfWhitespace(bytes[position]) && hexNibble(bytes[position]) === undefined) return undefined;
        position += 1;
    }
    return undefined;
}

function isPdfScalarKeyword(bytes: Uint8Array, value: ParsedValue): boolean {
    if (value.kind !== "other") return false;
    const length = value.end - value.start;
    return (
        (length === 4 && matchesAscii(bytes, value.start, "true")) ||
        (length === 5 && matchesAscii(bytes, value.start, "false")) ||
        (length === 4 && matchesAscii(bytes, value.start, "null"))
    );
}

function isUnsignedStructuralInteger(bytes: Uint8Array, value: ParsedValue | undefined): boolean {
    const first = value === undefined ? undefined : bytes[value.start];
    return (
        value?.kind === "number" &&
        value.integer !== undefined &&
        first !== undefined &&
        first >= 0x30 &&
        first <= 0x39
    );
}

function parseValue(state: ParseState, index: number, depth: number): ParsedValue | undefined {
    if (depth >= MAX_LEXICAL_NESTING) return undefined;
    const { bytes, limit } = state;
    const position = skipPdfWhitespaceAndComments(bytes, index, limit);
    observeParse(state, position);
    const byte = bytes[position];
    if (byte === undefined) return undefined;

    if (byte === 0x3c && bytes[position + 1] === 0x3c) {
        const dictionary = parseDictionary(state, position, depth + 1);
        if (dictionary === undefined) return undefined;
        return retainParsedValue(state, {
            kind: "dictionary",
            start: position,
            end: dictionary.end,
            dictionary,
        });
    }
    if (byte === 0x3c) {
        const end = skipHexString(bytes, position, limit);
        if (end === undefined) {
            observeParse(state, limit);
            return undefined;
        }
        observeParse(state, end);
        return retainParsedValue(state, { kind: "hex", start: position, end });
    }
    if (byte === 0x28) {
        const end = skipLiteralString(bytes, position, limit);
        if (end === undefined) {
            observeParse(state, limit);
            return undefined;
        }
        observeParse(state, end);
        return retainParsedValue(state, { kind: "literal", start: position, end });
    }
    if (byte === 0x5b) return parseArray(state, position, depth + 1);
    if (byte === 0x2f) {
        const name = readPdfName(bytes, position, limit);
        if (name === undefined) return undefined;
        observeParse(state, name.end);
        return retainParsedValue(state, {
            kind: "name",
            start: position,
            end: name.end,
            name: name.name,
        });
    }
    if (byte === 0x5d || byte === 0x3e) return undefined;

    const first = readBareToken(bytes, position, limit);
    if (first === undefined) return undefined;
    observeParse(state, first.end);
    if (first.kind !== "number") {
        return isPdfScalarKeyword(bytes, first) ? retainParsedValue(state, first) : undefined;
    }
    if (!isUnsignedStructuralInteger(bytes, first) || first.integer === undefined || first.integer <= 0) {
        return retainParsedValue(state, first);
    }

    const secondStart = skipPdfWhitespaceAndComments(bytes, first.end, limit);
    observeParse(state, secondStart);
    const second = readBareToken(bytes, secondStart, limit);
    if (second === undefined || !isUnsignedStructuralInteger(bytes, second)) {
        return retainParsedValue(state, first);
    }
    observeParse(state, second.end);
    const referenceStart = skipPdfWhitespaceAndComments(bytes, second.end, limit);
    observeParse(state, referenceStart);
    if (!matchesKeyword(bytes, referenceStart, "R", limit)) return retainParsedValue(state, first);
    observeParse(state, referenceStart + 1);
    return retainParsedValue(state, { kind: "reference", start: position, end: referenceStart + 1 });
}

function parseArray(state: ParseState, index: number, depth: number): ParsedValue | undefined {
    const { bytes, limit } = state;
    const values: ParsedValue[] = [];
    let position = index + 1;
    while (position < limit) {
        position = skipPdfWhitespaceAndComments(bytes, position, limit);
        observeParse(state, position);
        if (bytes[position] === 0x5d) {
            observeParse(state, position + 1);
            return retainParsedValue(state, {
                kind: "array",
                start: index,
                end: position + 1,
                array: values,
            });
        }
        const value = parseValue(state, position, depth + 1);
        if (value === undefined) return undefined;
        values.push(value);
        position = value.end;
    }
    return undefined;
}

function parseDictionary(
    state: ParseState,
    index: number,
    depth: number
): ParsedDictionary | undefined {
    const { bytes, limit } = state;
    const dictionary: ParsedDictionary = {
        start: index,
        end: index,
        entries: [],
        directV: false,
        root: false,
    };
    retainParseStructure(state);
    state.dictionaries.push(dictionary);

    let position = index + 2;
    while (position < limit) {
        position = skipPdfWhitespaceAndComments(bytes, position, limit);
        observeParse(state, position);
        if (bytes[position] === 0x3e && bytes[position + 1] === 0x3e) {
            dictionary.end = position + 2;
            observeParse(state, dictionary.end);
            return dictionary;
        }
        const key = readPdfName(bytes, position, limit);
        if (key === undefined) return undefined;
        observeParse(state, key.end);
        const value = parseValue(state, key.end, depth + 1);
        if (value === undefined) return undefined;
        // The value has already been charged as a ParsedValue. The retained
        // entry owns its decoded key name, so charge it before adding either
        // to the dictionary's attacker-controlled entry list.
        retainParseStructure(state);
        dictionary.entries.push({ name: key.name, value });
        if (key.name === "V" && value.dictionary !== undefined) {
            value.dictionary.directV = true;
        }
        position = value.end;
    }
    return undefined;
}

function directEntry(dictionary: ParsedDictionary, name: string): ParsedValue | undefined {
    const entries = dictionary.entries.filter((entry) => entry.name === name);
    if (entries.length !== 1) return undefined;
    return entries[0]?.value;
}

function directUnsignedIntegerEntry(
    bytes: Uint8Array,
    dictionary: ParsedDictionary,
    name: string
): number | undefined {
    const value = directEntry(dictionary, name);
    if (!isUnsignedStructuralInteger(bytes, value) || value?.integer === undefined) return undefined;
    return value.integer;
}

function isPdfNumberExactlyOne(bytes: Uint8Array, value: ParsedValue | undefined): boolean {
    if (value?.kind !== "number") return false;
    let position = value.start;
    if (bytes[position] === 0x2d) return false;
    if (bytes[position] === 0x2b) position += 1;

    let sawWholeDigit = false;
    let sawOne = false;
    while (position < value.end && bytes[position] !== 0x2e) {
        const byte = bytes[position];
        if (byte === undefined || byte < 0x30 || byte > 0x39) return false;
        sawWholeDigit = true;
        if (!sawOne) {
            if (byte === 0x30) {
                position += 1;
                continue;
            }
            if (byte !== 0x31) return false;
            sawOne = true;
            position += 1;
            continue;
        }
        return false;
    }
    if (!sawWholeDigit || !sawOne) return false;
    if (position === value.end) return true;

    position += 1;
    while (position < value.end) {
        if (bytes[position] !== 0x30) return false;
        position += 1;
    }
    return true;
}

function hasEntry(dictionary: ParsedDictionary, name: string): boolean {
    return dictionary.entries.some((entry) => entry.name === name);
}

function directLinearizedLength(
    bytes: Uint8Array,
    dictionary: ParsedDictionary | undefined
): number | undefined {
    if (dictionary === undefined || !isPdfNumberExactlyOne(bytes, directEntry(dictionary, "Linearized"))) {
        return undefined;
    }
    const length = directUnsignedIntegerEntry(bytes, dictionary, "L");
    return length !== undefined && length > 0 ? length : undefined;
}

function directPreviousEntry(bytes: Uint8Array, dictionary: ParsedDictionary): RevisionPrevious {
    const entries = dictionary.entries.filter((entry) => entry.name === "Prev");
    if (entries.length === 0) return { present: false, valid: true };
    const value = entries[0]?.value;
    if (
        entries.length !== 1 ||
        value === undefined ||
        !isUnsignedStructuralInteger(bytes, value) ||
        value.integer === undefined
    ) {
        return { present: true, valid: false };
    }
    return { present: true, valid: true, value: value.integer };
}

function byteRangeForDictionary(dictionary: ParsedDictionary): ByteRange | undefined {
    const entries = dictionary.entries.filter((entry) => entry.name === "ByteRange");
    if (entries.length !== 1) return undefined;
    const values = entries[0]?.value.array;
    if (values?.length !== 4) return undefined;
    const [first, second, third, fourth] = values;
    if (
        first?.integer === undefined ||
        second?.integer === undefined ||
        third?.integer === undefined ||
        fourth?.integer === undefined
    ) {
        return undefined;
    }
    return [first.integer, second.integer, third.integer, fourth.integer];
}

function hasExactNameEntry(dictionary: ParsedDictionary, key: string, expected: string): boolean {
    const entries = dictionary.entries.filter((entry) => entry.name === key);
    return (
        entries.length === 1 &&
        entries[0]?.value.kind === "name" &&
        entries[0].value.name === expected
    );
}

type StreamLength = { kind: "direct"; value: number } | { kind: "indirect" };

function classifyStreamLength(dictionary: ParsedDictionary): StreamLength | undefined {
    const value = directEntry(dictionary, "Length");
    if (value?.kind === "number" && value.integer !== undefined && value.integer >= 0) {
        return { kind: "direct", value: value.integer };
    }
    if (value?.kind === "reference") return { kind: "indirect" };
    return undefined;
}

function skipStream(
    bytes: Uint8Array,
    streamKeywordStart: number,
    limit: number,
    dictionary: ParsedDictionary
): number | undefined {
    let dataStart = streamKeywordStart + "stream".length;
    if (bytes[dataStart] === 0x0d && bytes[dataStart + 1] === 0x0a) {
        dataStart += 2;
    } else if (bytes[dataStart] === 0x0a || bytes[dataStart] === 0x0d) {
        dataStart += 1;
    } else {
        return undefined;
    }

    const length = classifyStreamLength(dictionary);
    if (length === undefined) return undefined;
    if (length.kind === "direct") {
        if (length.value > limit - dataStart) return undefined;
        const endstreamStart = skipPdfWhitespace(bytes, dataStart + length.value, limit);
        if (!matchesKeyword(bytes, endstreamStart, "endstream", limit)) return undefined;
        return endstreamStart + "endstream".length;
    }

    // An exactly-one indirect /Length cannot be resolved without duplicating
    // the PDF loader. This bounded lexical fallback intentionally only
    // resumes the physical scan; malformed direct entries never reach it.
    for (let position = dataStart; position < limit; position += 1) {
        const previous = bytes[position - 1];
        if (
            (previous === 0x0a || previous === 0x0d) &&
            matchesKeyword(bytes, position, "endstream", limit)
        ) {
            return position + "endstream".length;
        }
    }
    return undefined;
}

function parseIndirectObjectHeader(
    bytes: Uint8Array,
    index: number,
    limit: number
): IndirectObjectHeader | undefined {
    if (!isPdfDelimiter(bytes[index - 1])) return undefined;
    const object = readUnsignedSafeInteger(bytes, index, limit);
    if (object === undefined) return undefined;
    const generationStart = skipPdfWhitespaceAndComments(bytes, object.end, limit);
    if (generationStart === object.end) return undefined;
    const generation = readUnsignedSafeInteger(bytes, generationStart, limit);
    if (generation === undefined) return undefined;
    const keywordStart = skipPdfWhitespaceAndComments(bytes, generation.end, limit);
    if (keywordStart === generation.end || !matchesKeyword(bytes, keywordStart, "obj", limit)) {
        return undefined;
    }
    const objectNumber = object.integer;
    const generationNumber = generation.integer;
    // Object zero is the permanently free object in a cross-reference table;
    // do not treat a physical `0 0 obj` spelling as a trusted lexical frame.
    if (objectNumber === undefined || objectNumber <= 0 || generationNumber === undefined) {
        return undefined;
    }
    return {
        objectNumber,
        generationNumber,
        bodyStart: keywordStart + "obj".length,
    };
}

function parsePhysicalObject(
    bytes: Uint8Array,
    header: IndirectObjectHeader
): { end: number; occurrence?: PhysicalObjectOccurrence } {
    const state: ParseState = {
        bytes,
        limit: bytes.length,
        dictionaries: [],
        furthestRead: header.bodyStart,
        retainedStructures: 0,
    };
    const root = parseValue(state, header.bodyStart, 0);
    if (root === undefined) return { end: state.furthestRead };
    if (root.dictionary !== undefined) root.dictionary.root = true;

    let position = skipPdfWhitespaceAndComments(bytes, root.end, bytes.length);
    observeParse(state, position);
    if (root.dictionary !== undefined && matchesKeyword(bytes, position, "stream", bytes.length)) {
        const afterStream = skipStream(bytes, position, bytes.length, root.dictionary);
        if (afterStream === undefined) {
            // The stream fallback has either consumed its complete lexical
            // tail or found a contradictory declared length. Do not retry
            // object headers inside that ambiguous payload.
            observeParse(state, bytes.length);
            return { end: state.furthestRead };
        }
        position = skipPdfWhitespaceAndComments(bytes, afterStream, bytes.length);
        observeParse(state, position);
    }
    if (!matchesKeyword(bytes, position, "endobj", bytes.length)) {
        return { end: state.furthestRead };
    }
    observeParse(state, position + "endobj".length);

    const xrefPrevious =
        root.dictionary !== undefined && hasExactNameEntry(root.dictionary, "Type", "XRef")
            ? directPreviousEntry(bytes, root.dictionary)
            : undefined;
    const hasLinearizedEntry = root.dictionary !== undefined && hasEntry(root.dictionary, "Linearized");
    const linearizedLength = directLinearizedLength(bytes, root.dictionary);
    const contents: PdfContentsOccurrence[] = [];
    for (const dictionary of state.dictionaries) {
        const range = byteRangeForDictionary(dictionary);
        const rfc3161SubFilter = hasExactNameEntry(dictionary, "SubFilter", "ETSI.RFC3161");
        const documentTimestamp =
            rfc3161SubFilter && hasExactNameEntry(dictionary, "Type", "DocTimeStamp");
        for (const entry of dictionary.entries) {
            if (entry.name !== "Contents" || entry.value.kind !== "hex") continue;
            contents.push({
                start: entry.value.start,
                end: entry.value.end,
                byteRange: range,
                rfc3161SubFilter,
                documentTimestamp,
                directV: dictionary.directV,
                root: dictionary.root,
            });
            if (contents.length > MAX_SIGNATURE_OCCURRENCES_PER_OBJECT) {
                return { end: state.furthestRead };
            }
        }
    }
    return {
        end: position + "endobj".length,
        occurrence: { contents, xrefPrevious, hasLinearizedEntry, linearizedLength },
    };
}

function parseRevisionBoundary(
    bytes: Uint8Array,
    index: number,
    limit: number
): RevisionBoundary | undefined {
    if (!matchesKeyword(bytes, index, "startxref", limit)) return undefined;
    let position = skipPdfWhitespaceAndComments(bytes, index + "startxref".length, limit);
    const offset = readUnsignedSafeInteger(bytes, position, limit);
    if (offset === undefined) return undefined;
    // PDF comments are lexical trivia between the offset line and %%EOF, but
    // trailing bytes after %%EOF remain whitespace-only in this boundary.
    position = skipPdfWhitespaceAndCommentsBeforeEof(bytes, offset.end, limit);
    if (!matchesAscii(bytes, position, "%%EOF")) return undefined;
    const eofEnd = position + "%%EOF".length;
    position = skipPdfWhitespace(bytes, eofEnd, limit);
    const xrefOffset = offset.integer;
    if (xrefOffset === undefined) return undefined;
    return { markerStart: index, xrefOffset, eofEnd, end: position };
}

function readFixedDecimal(
    bytes: Uint8Array,
    index: number,
    digits: number,
    limit: number
): { end: number } | undefined {
    if (index + digits > limit) return undefined;
    for (let offset = 0; offset < digits; offset += 1) {
        const byte = bytes[index + offset];
        if (byte === undefined || byte < 0x30 || byte > 0x39) return undefined;
    }
    return { end: index + digits };
}

const MAX_XREF_HORIZONTAL_PADDING = 16;

/**
 * Classic xref entries use horizontal separators. Keep their compatibility
 * allowance deliberately bounded while refusing a line break between the
 * offset, generation, and in-use/free state columns.
 */
function skipXrefHorizontalPadding(
    bytes: Uint8Array,
    index: number,
    limit: number,
    required: boolean
): number | undefined {
    let position = index;
    while (
        position < limit &&
        position - index < MAX_XREF_HORIZONTAL_PADDING &&
        (bytes[position] === 0x20 || bytes[position] === 0x09)
    ) {
        position += 1;
    }
    if (position - index >= MAX_XREF_HORIZONTAL_PADDING && (bytes[position] === 0x20 || bytes[position] === 0x09)) {
        return undefined;
    }
    return required && position === index ? undefined : position;
}

function readXrefLineTerminator(bytes: Uint8Array, index: number, limit: number): number | undefined {
    const lineEnd = skipXrefHorizontalPadding(bytes, index, limit, false);
    if (lineEnd === undefined) return undefined;
    if (bytes[lineEnd] === 0x0a) return lineEnd + 1;
    if (bytes[lineEnd] === 0x0d) {
        return bytes[lineEnd + 1] === 0x0a ? lineEnd + 2 : lineEnd + 1;
    }
    return undefined;
}

function readClassicXrefEntry(
    bytes: Uint8Array,
    index: number,
    limit: number
): number | undefined {
    const offset = readFixedDecimal(bytes, index, 10, limit);
    if (offset === undefined) return undefined;
    const generationStart = skipXrefHorizontalPadding(bytes, offset.end, limit, true);
    if (generationStart === undefined) return undefined;
    const generation = readFixedDecimal(bytes, generationStart, 5, limit);
    if (generation === undefined) return undefined;
    const stateStart = skipXrefHorizontalPadding(bytes, generation.end, limit, true);
    if (stateStart === undefined) return undefined;
    const state = bytes[stateStart];
    if (state !== 0x6e && state !== 0x66) {
        return undefined;
    }
    return readXrefLineTerminator(bytes, stateStart + 1, limit);
}

function parseClassicXrefSection(
    bytes: Uint8Array,
    index: number,
    limit: number
): { end: number; previous: RevisionPrevious } | undefined {
    if (!matchesKeyword(bytes, index, "xref", limit)) return undefined;
    let position = skipXrefControlWhitespace(bytes, index + "xref".length, limit);
    let sawSubsection = false;
    while (position < limit && !matchesKeyword(bytes, position, "trailer", limit)) {
        const first = readUnsignedSafeInteger(bytes, position, limit);
        if (first?.integer === undefined) return undefined;
        position = skipXrefControlWhitespace(bytes, first.end, limit);
        const count = readUnsignedSafeInteger(bytes, position, limit);
        if (count?.integer === undefined || count.integer <= 0) return undefined;
        const firstEntry = readXrefLineTerminator(bytes, count.end, limit);
        if (firstEntry === undefined) return undefined;
        position = firstEntry;
        const maximumEntries = Math.floor((limit - position) / 19);
        if (count.integer > maximumEntries) return undefined;
        for (let entry = 0; entry < count.integer; entry += 1) {
            const end = readClassicXrefEntry(bytes, position, limit);
            if (end === undefined) return undefined;
            position = end;
        }
        sawSubsection = true;
        position = skipPdfWhitespaceAndComments(bytes, position, limit);
    }
    if (!sawSubsection || !matchesKeyword(bytes, position, "trailer", limit)) return undefined;
    const state: ParseState = {
        bytes,
        limit,
        dictionaries: [],
        furthestRead: position + "trailer".length,
        retainedStructures: 0,
    };
    const trailer = parseValue(state, position + "trailer".length, 0);
    if (trailer?.dictionary === undefined || trailer.end > limit) return undefined;
    return { end: trailer.end, previous: directPreviousEntry(bytes, trailer.dictionary) };
}

/**
 * Parses one physical revision segment without resolving xref entries. The
 * caller chooses the allowed frame topology; this helper only proves that no
 * free-form bytes occur between complete objects, classic xref frames, and
 * the following startxref marker.
 */
function scanFramedRevisionSegment(
    bytes: Uint8Array,
    start: number,
    markerStart: number,
    physicalObjects: ReadonlyMap<number, PhysicalObjectFrame>
): FramedRevisionSegment | undefined {
    if (start < 0 || start > markerStart || markerStart > bytes.length) return undefined;
    let firstObject: PhysicalObjectFrame | undefined;
    let linearizedObjectCount = 0;
    const classicXrefs: ClassicXrefFrame[] = [];
    let position = start;
    while (position < markerStart) {
        position = skipPdfWhitespaceAndComments(bytes, position, markerStart);
        if (position === markerStart) break;

        // Like an ordinary incremental revision, a selected classic xref
        // frame is the final non-trivia construct before its startxref.
        // Linearized bases are a narrowly accepted topology, not an excuse
        // to accept a physical object appended after either table.
        if (classicXrefs.length !== 0) return undefined;

        if (matchesKeyword(bytes, position, "xref", markerStart)) {
            const classic = parseClassicXrefSection(bytes, position, markerStart);
            if (classic === undefined || classic.end > markerStart) return undefined;
            classicXrefs.push({ start: position, end: classic.end, previous: classic.previous });
            position = classic.end;
            continue;
        }

        const physical = physicalObjects.get(position);
        if (physical === undefined || physical.end > markerStart) return undefined;
        firstObject ??= physical;
        if (physical.hasLinearizedEntry) {
            linearizedObjectCount += 1;
            if (linearizedObjectCount > 1) return undefined;
        }
        position = physical.end;
    }
    return { firstObject, linearizedObjectCount, classicXrefs };
}

/**
 * Recognizes the one special two-section layout permitted for a linearized
 * base PDF. This is intentionally a lexical framing proof, not an xref
 * resolver: it accepts only the exact classic-xref topology emitted by
 * linearizers and collapses it to the terminal base boundary.
 */
function validateLinearizedBase(
    bytes: Uint8Array,
    earlyBoundary: RevisionBoundary,
    terminalBoundary: RevisionBoundary,
    physicalObjects: ReadonlyMap<number, PhysicalObjectFrame>
): RevisionBoundary | undefined {
    if (earlyBoundary.xrefOffset !== 0 || earlyBoundary.end > terminalBoundary.markerStart) {
        return undefined;
    }
    const early = scanFramedRevisionSegment(
        bytes,
        0,
        earlyBoundary.markerStart,
        physicalObjects
    );
    const main = scanFramedRevisionSegment(
        bytes,
        earlyBoundary.end,
        terminalBoundary.markerStart,
        physicalObjects
    );
    if (early === undefined || main === undefined) return undefined;
    if (early.classicXrefs.length !== 1 || main.classicXrefs.length !== 1) return undefined;

    const firstPhysical = early.firstObject;
    const baseEnd = firstPhysical?.linearizedLength;
    if (
        baseEnd === undefined ||
        baseEnd < terminalBoundary.eofEnd ||
        baseEnd > terminalBoundary.end ||
        early.linearizedObjectCount + main.linearizedObjectCount !== 1
    ) {
        return undefined;
    }

    const earlyXref = early.classicXrefs[0];
    const mainXref = main.classicXrefs[0];
    if (earlyXref === undefined || mainXref === undefined) return undefined;
    if (
        !earlyXref.previous.valid ||
        !earlyXref.previous.present ||
        earlyXref.previous.value !== mainXref.start
    ) {
        return undefined;
    }
    if (!mainXref.previous.valid || mainXref.previous.present) return undefined;
    if (
        terminalBoundary.xrefOffset !== earlyXref.start &&
        terminalBoundary.xrefOffset !== mainXref.start
    ) {
        return undefined;
    }
    // The incremental writer may add separator whitespace after the original
    // linearized `/L` boundary. Keep `/L` as the collapsed base end so a
    // later revision starts from the actual base length, while the ordinary
    // segment scanner still permits that separator as trivia.
    return { ...terminalBoundary, end: baseEnd };
}

function validateRevisionSegment(
    bytes: Uint8Array,
    start: number,
    boundary: RevisionBoundary,
    physicalObjects: ReadonlyMap<number, PhysicalObjectFrame>
): RevisionPrevious | undefined {
    if (boundary.xrefOffset < start || boundary.xrefOffset >= boundary.markerStart) return undefined;
    let position = start;
    let previous: RevisionPrevious | undefined;
    while (position < boundary.markerStart) {
        position = skipPdfWhitespaceAndComments(bytes, position, boundary.markerStart);
        if (position === boundary.markerStart) break;
        // The selected xref frame must be the final non-trivia construct in
        // its revision. A later object would be outside the framed revision
        // even if the earlier xref itself was syntactically valid.
        if (previous !== undefined) return undefined;

        if (position === boundary.xrefOffset && matchesKeyword(bytes, position, "xref", boundary.markerStart)) {
            const classic = parseClassicXrefSection(bytes, position, boundary.markerStart);
            if (classic === undefined) return undefined;
            previous = classic.previous;
            position = classic.end;
            continue;
        }

        const physical = physicalObjects.get(position);
        if (physical === undefined) return undefined;
        if (position === boundary.xrefOffset) {
            if (physical.xrefPrevious === undefined) return undefined;
            previous = physical.xrefPrevious;
        }
        position = physical.end;
    }
    return previous;
}

function ownerKey(owner: PdfObjectIdentity): string {
    return `${owner.objectNumber.toString()} ${owner.generationNumber.toString()}`;
}

function sameByteRange(left: ByteRange | undefined, right: ByteRange): boolean {
    return (
        left?.[0] === right[0] &&
        left[1] === right[1] &&
        left[2] === right[2] &&
        left[3] === right[3]
    );
}

function hexStringEquals(bytes: Uint8Array, start: number, end: number, expected: Uint8Array): boolean {
    let expectedIndex = 0;
    let highNibble: number | undefined;
    for (let position = start + 1; position < end - 1; position += 1) {
        const byte = bytes[position];
        if (isPdfWhitespace(byte)) continue;
        const nibble = hexNibble(byte);
        if (nibble === undefined) return false;
        if (highNibble === undefined) {
            highNibble = nibble;
            continue;
        }
        if (expected[expectedIndex] !== ((highNibble << 4) | nibble)) return false;
        expectedIndex += 1;
        highNibble = undefined;
    }
    if (highNibble !== undefined) {
        if (expected[expectedIndex] !== (highNibble << 4)) return false;
        expectedIndex += 1;
    }
    return expectedIndex === expected.length;
}

/**
 * A monotonic lexical pass over physical PDF objects plus bounded revision
 * framing checks. It is deliberately not an xref resolver or replacement
 * parser: it observes only physical objects and dictionary values needed to
 * bind a selected signature /Contents gap. Comments, literal strings, hex
 * strings, and stream payloads are skipped before headers or keys are used.
 */
export class PdfSignatureOccurrenceIndex {
    private readonly latestObjects = new Map<string, PhysicalObjectOccurrence>();
    private readonly revisionBoundaries: RevisionBoundary[] = [];
    private readonly hasTerminalRevisionBoundary: boolean;
    private lexicalBytes = 0;
    private physicalObjectAttempts = 0;
    private revisionBoundaryComparisons = 0;

    private consumeLexicalWork(bytes: number): void {
        this.lexicalBytes += bytes;
        if (this.lexicalBytes > MAX_SIGNATURE_LEXICAL_WORK) {
            throw new Error("PDF signature occurrence scan exceeds the lexical work limit");
        }
    }

    constructor(pdfBytes: Uint8Array, wantedOwners: Iterable<PdfObjectIdentity>) {
        if (pdfBytes.length > MAX_PDF_SIZE) {
            throw new Error(
                `PDF signature occurrence scan exceeds the ${MAX_PDF_SIZE.toString()} byte limit`
            );
        }

        const wanted = new Set<string>();
        for (const owner of wantedOwners) wanted.add(ownerKey(owner));

        const physicalObjects = new Map<number, PhysicalObjectFrame>();
        const revisions: RevisionBoundary[] = [];
        let position = 0;
        const advanceTo = (next: number): void => {
            const bounded = Math.min(pdfBytes.length, Math.max(position + 1, next));
            this.consumeLexicalWork(bounded - position);
            position = bounded;
        };
        while (position < pdfBytes.length) {
            const afterTrivia = skipPdfWhitespaceAndComments(pdfBytes, position, pdfBytes.length);
            if (afterTrivia !== position) advanceTo(afterTrivia);
            if (position >= pdfBytes.length) break;

            const boundary = parseRevisionBoundary(pdfBytes, position, pdfBytes.length);
            if (boundary !== undefined) {
                if (revisions.length >= MAX_REVISION_BOUNDARIES) {
                    throw new Error("PDF signature occurrence scan exceeds the revision marker limit");
                }
                revisions.push(boundary);
                advanceTo(boundary.end);
                continue;
            }

            const header = parseIndirectObjectHeader(pdfBytes, position, pdfBytes.length);
            if (header !== undefined) {
                this.physicalObjectAttempts += 1;
                if (this.physicalObjectAttempts > MAX_PHYSICAL_OBJECT_ATTEMPTS) {
                    throw new Error("PDF signature occurrence scan exceeds the physical object limit");
                }
                const physical = parsePhysicalObject(pdfBytes, header);
                if (physical.occurrence !== undefined) {
                    physicalObjects.set(position, {
                        end: physical.end,
                        xrefPrevious: physical.occurrence.xrefPrevious,
                        hasLinearizedEntry: physical.occurrence.hasLinearizedEntry,
                        linearizedLength: physical.occurrence.linearizedLength,
                    });
                    const key = ownerKey(header);
                    if (wanted.has(key)) this.latestObjects.set(key, physical.occurrence);
                    advanceTo(physical.end);
                    continue;
                }
                // A failed candidate is still a lexically consumed unit. Its
                // parser-provided resume offset skips strings, hex data, and
                // stream payloads already examined by that speculative parse.
                advanceTo(Math.max(header.bodyStart, physical.end));
                continue;
            }

            // Outside a parsed object, skip structured lexical atoms as well
            // so fake headers or startxref markers in malformed free text do
            // not become trusted markers later in this bounded scan.
            if (pdfBytes[position] === 0x28) {
                const end = skipLiteralString(pdfBytes, position, pdfBytes.length);
                if (end !== undefined) {
                    advanceTo(end);
                    continue;
                }
            }
            if (pdfBytes[position] === 0x3c && pdfBytes[position + 1] !== 0x3c) {
                const end = skipHexString(pdfBytes, position, pdfBytes.length);
                if (end !== undefined) {
                    advanceTo(end);
                    continue;
                }
            }
            if (pdfBytes[position] === 0x2f) {
                const name = readPdfName(pdfBytes, position, pdfBytes.length);
                if (name !== undefined) {
                    advanceTo(name.end);
                    continue;
                }
            }
            const token = readBareToken(pdfBytes, position, pdfBytes.length);
            // eslint-disable-next-line security/detect-possible-timing-attacks -- lexical token kind is public PDF syntax.
            if (token !== undefined) {
                advanceTo(token.end);
                continue;
            }
            advanceTo(position + 1);
        }

        let previousBoundary: RevisionBoundary | undefined;
        let revisionIndex = 0;
        const earlyLinearizedBoundary = revisions[0];
        const terminalLinearizedBoundary = revisions[1];
        if (
            earlyLinearizedBoundary?.xrefOffset === 0 &&
            terminalLinearizedBoundary !== undefined &&
            earlyLinearizedBoundary.end <= terminalLinearizedBoundary.markerStart
        ) {
            // A linearized base has a first-page `startxref 0` section before
            // its terminal section. Charge both bounded lexical scans, then
            // accept only the exact two-classic-xref topology below.
            this.consumeLexicalWork(earlyLinearizedBoundary.markerStart);
            this.consumeLexicalWork(
                terminalLinearizedBoundary.markerStart - earlyLinearizedBoundary.end
            );
            const linearizedBase = validateLinearizedBase(
                pdfBytes,
                earlyLinearizedBoundary,
                terminalLinearizedBoundary,
                physicalObjects
            );
            if (linearizedBase !== undefined) {
                this.revisionBoundaries.push(linearizedBase);
                previousBoundary = linearizedBase;
                revisionIndex = 2;
            }
        }

        for (; revisionIndex < revisions.length; revisionIndex += 1) {
            const revision = revisions[revisionIndex];
            if (revision === undefined) break;
            const segmentStart = previousBoundary?.end ?? 0;
            this.consumeLexicalWork(revision.markerStart - segmentStart);
            const previous = validateRevisionSegment(
                pdfBytes,
                segmentStart,
                revision,
                physicalObjects
            );
            if (!previous?.valid) break;
            if (previousBoundary === undefined && previous.present) break;
            if (
                previousBoundary !== undefined &&
                (!previous.present || previous.value !== previousBoundary.xrefOffset)
            ) {
                break;
            }
            this.revisionBoundaries.push(revision);
            previousBoundary = revision;
        }
        this.hasTerminalRevisionBoundary = previousBoundary?.end === pdfBytes.length;
    }

    /** @internal Bounded-work diagnostics used by source-level regressions. */
    get scanStats(): Readonly<PdfSignatureOccurrenceScanStats> {
        return {
            lexicalBytes: this.lexicalBytes,
            physicalObjectAttempts: this.physicalObjectAttempts,
            revisionBoundaryComparisons: this.revisionBoundaryComparisons,
        };
    }

    isRevisionBoundary(endpoint: number, pdfLength: number): boolean {
        if (!this.hasTerminalRevisionBoundary) return false;
        let lower = 0;
        let upper = this.revisionBoundaries.length;
        while (lower < upper) {
            const middle = lower + Math.floor((upper - lower) / 2);
            const boundary = this.revisionBoundaries[middle];
            this.revisionBoundaryComparisons += 1;
            if (boundary !== undefined && boundary.eofEnd <= endpoint) {
                lower = middle + 1;
            } else {
                upper = middle;
            }
        }
        const boundary = this.revisionBoundaries[lower - 1];
        if (boundary === undefined || endpoint > boundary.end) return false;
        // The current document must end at the valid boundary's trailing
        // whitespace. Earlier revisions may end immediately after %%EOF
        // or at any following whitespace byte before their next update.
        return endpoint !== pdfLength || boundary.end === pdfLength;
    }

    hasSelectedContents(
        binding: PdfContentsBinding | undefined,
        gapStart: number,
        gapEnd: number,
        contents: Uint8Array,
        byteRange: ByteRange,
        pdfBytes: Uint8Array
    ): boolean {
        if (binding === undefined) return false;
        const object = this.latestObjects.get(ownerKey(binding.owner));
        if (object === undefined) return false;

        const matching = object.contents.filter((candidate) => {
            const isSelectedForm = binding.directValue ? candidate.directV : candidate.root;
            const matchesRequiredMarkers = binding.directValue
                ? candidate.rfc3161SubFilter &&
                  (!binding.requireDocumentTimestamp || candidate.documentTimestamp)
                : !binding.requireDocumentTimestamp || candidate.documentTimestamp;
            return (
                isSelectedForm &&
                matchesRequiredMarkers &&
                sameByteRange(candidate.byteRange, byteRange) &&
                hexStringEquals(pdfBytes, candidate.start, candidate.end, contents)
            );
        });
        return (
            matching.length === 1 &&
            matching[0]?.start === gapStart &&
            matching[0].end === gapEnd
        );
    }
}
