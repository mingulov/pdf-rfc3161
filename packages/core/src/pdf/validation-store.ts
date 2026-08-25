import {
    PDFArray,
    decodePDFRawStream,
    PDFDict,
    PDFDocument,
    PDFHexString,
    PDFName,
    PDFObject,
    PDFRawStream,
    PDFRef,
    PDFString,
} from "pdf-lib-incremental-save";
import { TimestampError, TimestampErrorCode, type ExtractOptions } from "../types.js";
import { bytesToHex, toArrayBuffer } from "../utils.js";
import { ensureWebCrypto } from "../utils/web-crypto.js";
import type { LTVData } from "./ltv.js";
import { checkedRegister, preflightPdfXref, restoreLargestObjectNumber } from "./internals.js";

export interface ValidationStoreUpdate {
    validationData?: LTVData;
    vri?: VriMutation;
}

type ValidationArrayKey = "Certs" | "CRLs" | "OCSPs";

const MAX_FIELD_PARENT_DEPTH = 256;

interface ValidationArray {
    array: PDFArray;
    ref?: PDFRef;
}

interface ValidationArrayUpdate {
    key: ValidationArrayKey;
    bytes: Uint8Array[];
}

interface ResolvedPdfValue<T extends PDFObject> {
    value: T;
    ref?: PDFRef;
}

interface VriMutation {
    fieldName: string;
    validationData: LTVData;
}

function validationStoreError(message: string, cause?: unknown): TimestampError {
    return new TimestampError(TimestampErrorCode.PDF_ERROR, message, cause);
}

function resolvePdfValue<T extends PDFObject>(
    context: PDFDocument["context"],
    rawValue: PDFObject | undefined,
    isExpectedType: (value: PDFObject) => value is T,
    description: string,
    expectedType: string
): ResolvedPdfValue<T> | undefined {
    if (rawValue === undefined) {
        return undefined;
    }

    const ref = rawValue instanceof PDFRef ? rawValue : undefined;
    const value = ref === undefined ? rawValue : context.lookup(ref);
    if (value === undefined || !isExpectedType(value)) {
        throw validationStoreError(`${description} must be a ${expectedType}`);
    }

    return ref === undefined ? { value } : { value, ref };
}

function resolveDss(pdfDoc: PDFDocument): { dss: PDFDict; ref?: PDFRef } {
    const context = pdfDoc.context;
    const dssName = PDFName.of("DSS");
    const resolved = resolvePdfValue(
        context,
        pdfDoc.catalog.get(dssName),
        (value): value is PDFDict => value instanceof PDFDict,
        "DSS entry",
        "PDF dictionary"
    );

    if (resolved !== undefined) {
        return { dss: resolved.value, ref: resolved.ref };
    }

    const dss = context.obj({ Type: PDFName.of("DSS") });
    const ref = checkedRegister(context, dss);
    pdfDoc.catalog.set(dssName, ref);
    return { dss, ref };
}

function findExistingDss(pdfDoc: PDFDocument): ResolvedPdfValue<PDFDict> | undefined {
    return resolvePdfValue(
        pdfDoc.context,
        pdfDoc.catalog.get(PDFName.of("DSS")),
        (value): value is PDFDict => value instanceof PDFDict,
        "DSS entry",
        "PDF dictionary"
    );
}

function resolveValidationArray(
    context: PDFDocument["context"],
    dss: PDFDict,
    key: ValidationArrayKey,
    createIfMissing: boolean
): ValidationArray | undefined {
    const keyName = PDFName.of(key);
    const resolved = resolvePdfValue(
        context,
        dss.get(keyName),
        (value): value is PDFArray => value instanceof PDFArray,
        `${key} entry`,
        "PDF array"
    );

    if (resolved !== undefined) {
        return { array: resolved.value, ref: resolved.ref };
    }

    if (!createIfMissing) {
        return undefined;
    }

    const array = PDFArray.withContext(context);
    dss.set(keyName, array);
    return { array };
}

function existingStreamRefs(
    context: PDFDocument["context"],
    array: PDFArray,
    key: ValidationArrayKey
): Map<string, PDFRef> {
    const refs = new Map<string, PDFRef>();

    for (let index = 0; index < array.size(); index++) {
        const ref = array.get(index);
        if (!(ref instanceof PDFRef)) {
            throw validationStoreError(`${key} entries must be indirect PDF raw streams`);
        }

        const stream = context.lookup(ref);
        if (!(stream instanceof PDFRawStream)) {
            throw validationStoreError(`${key} entries must reference PDF raw streams`);
        }

        try {
            refs.set(bytesToHex(decodePDFRawStream(stream).decode()), ref);
        } catch (error) {
            throw validationStoreError(`${key} stream could not be decoded`, error);
        }
    }

    return refs;
}

function appendValidationData(
    context: PDFDocument["context"],
    snapshot: ReturnType<PDFDocument["takeSnapshot"]>,
    validationArray: ValidationArray | undefined,
    update: ValidationArrayUpdate
): PDFRef[] {
    if (validationArray === undefined) {
        return [];
    }

    const refs = existingStreamRefs(context, validationArray.array, update.key);
    const selectedRefs: PDFRef[] = [];
    const selectedKeys = new Set<string>();
    let changed = false;

    for (const bytes of update.bytes) {
        const byteKey = bytesToHex(bytes);
        let ref = refs.get(byteKey);
        if (ref === undefined) {
            const stream = PDFRawStream.of(PDFDict.withContext(context), bytes);
            ref = checkedRegister(context, stream);
            validationArray.array.push(ref);
            refs.set(byteKey, ref);
            snapshot.markRefForSave(ref);
            changed = true;
        }

        if (!selectedKeys.has(byteKey)) {
            selectedKeys.add(byteKey);
            selectedRefs.push(ref);
        }
    }

    if (changed && validationArray.ref) {
        snapshot.markRefForSave(validationArray.ref);
    }

    return selectedRefs;
}

function resolvePdfString(
    context: PDFDocument["context"],
    rawValue: PDFObject | undefined,
    description: string
): string | undefined {
    if (rawValue === undefined) {
        return undefined;
    }

    const value = rawValue instanceof PDFRef ? context.lookup(rawValue) : rawValue;
    if (!(value instanceof PDFString) && !(value instanceof PDFHexString)) {
        throw validationStoreError(`${description} must be a PDF string`);
    }
    return value.decodeText();
}

function resolveSignatureField(pdfDoc: PDFDocument, fieldName: string): ResolvedPdfValue<PDFDict> {
    const context = pdfDoc.context;
    const acroForm = resolvePdfValue(
        context,
        pdfDoc.catalog.get(PDFName.of("AcroForm")),
        (value): value is PDFDict => value instanceof PDFDict,
        "AcroForm",
        "PDF dictionary"
    );
    if (acroForm === undefined) {
        throw validationStoreError(`Signature field "${fieldName}" was not found`);
    }

    const fields = resolvePdfValue(
        context,
        acroForm.value.get(PDFName.of("Fields")),
        (value): value is PDFArray => value instanceof PDFArray,
        "AcroForm /Fields",
        "PDF array"
    );
    if (fields === undefined) {
        throw validationStoreError(`Signature field "${fieldName}" was not found`);
    }

    const matches: ResolvedPdfValue<PDFDict>[] = [];
    const ancestors = new Set<PDFObject>();
    const visited = new Set<PDFObject>();

    const visitField = (
        rawField: PDFObject,
        parentName: string | undefined,
        expectedParent: PDFRef | undefined
    ): void => {
        const field = resolvePdfValue(
            context,
            rawField,
            (value): value is PDFDict => value instanceof PDFDict,
            "Field",
            "PDF dictionary"
        );
        if (field === undefined) {
            throw validationStoreError("Field must be a PDF dictionary");
        }

        const identity = field.ref ?? field.value;
        if (ancestors.has(identity)) {
            throw validationStoreError("Field hierarchy contains a cycle");
        }
        if (visited.has(identity)) {
            throw validationStoreError("Field hierarchy reuses a field node");
        }
        ancestors.add(identity);
        visited.add(identity);

        const rawParent = field.value.get(PDFName.of("Parent"));
        const parent = resolvePdfValue(
            context,
            rawParent,
            (value): value is PDFDict => value instanceof PDFDict,
            "Field /Parent",
            "PDF dictionary"
        );
        if (expectedParent === undefined) {
            if (parent !== undefined) {
                throw validationStoreError("AcroForm root field must not have a /Parent");
            }
        } else if (parent !== undefined) {
            if (
                !(rawParent instanceof PDFRef) ||
                parent.ref === undefined ||
                rawParent.objectNumber !== expectedParent.objectNumber ||
                rawParent.generationNumber !== expectedParent.generationNumber
            ) {
                throw validationStoreError(
                    "Field /Parent must be the exact indirect containing /Kids field"
                );
            }
        }

        const partialName = resolvePdfString(context, field.value.get(PDFName.of("T")), "Field /T");
        if (partialName === undefined) {
            const subtype = resolvePdfValue(
                context,
                field.value.get(PDFName.of("Subtype")),
                (value): value is PDFName => value instanceof PDFName,
                "Unnamed field /Subtype",
                "PDF name"
            );
            if (subtype?.value.toString() !== "/Widget") {
                throw validationStoreError("Unnamed field node must be a widget annotation");
            }
            ancestors.delete(identity);
            return;
        }
        const qualifiedName =
            parentName === undefined ? partialName : `${parentName}.${partialName}`;
        if (qualifiedName === fieldName) {
            matches.push(field);
        }

        const kids = resolvePdfValue(
            context,
            field.value.get(PDFName.of("Kids")),
            (value): value is PDFArray => value instanceof PDFArray,
            "Field /Kids",
            "PDF array"
        );
        if (kids !== undefined) {
            for (let index = 0; index < kids.value.size(); index++) {
                visitField(kids.value.get(index), qualifiedName, field.ref);
            }
        }

        ancestors.delete(identity);
    };

    for (let index = 0; index < fields.value.size(); index++) {
        visitField(fields.value.get(index), undefined, undefined);
    }

    if (matches.length === 0) {
        throw validationStoreError(`Signature field "${fieldName}" was not found`);
    }
    if (matches.length !== 1) {
        throw validationStoreError(`Signature field "${fieldName}" is ambiguous`);
    }

    const field = matches[0];
    if (field === undefined) {
        throw validationStoreError(`Signature field "${fieldName}" was not found`);
    }
    const inheritedFieldValue = (key: string): PDFObject | undefined => {
        const identities = new Set<PDFObject>();
        let current = field;
        for (let depth = 0; depth < MAX_FIELD_PARENT_DEPTH; depth++) {
            const identity = current.ref ?? current.value;
            if (identities.has(identity)) {
                throw validationStoreError(`Field "${fieldName}" /Parent chain contains a cycle`);
            }
            identities.add(identity);

            const value = current.value.get(PDFName.of(key));
            if (value !== undefined) {
                return value;
            }
            const rawParent = current.value.get(PDFName.of("Parent"));
            const parent = resolvePdfValue(
                context,
                rawParent,
                (value): value is PDFDict => value instanceof PDFDict,
                `Field "${fieldName}" /Parent`,
                "PDF dictionary"
            );
            if (parent === undefined) {
                return undefined;
            }
            if (!(rawParent instanceof PDFRef) || parent.ref === undefined || current.ref === undefined) {
                throw validationStoreError(
                    `Field "${fieldName}" /Parent must be an exact indirect field reference`
                );
            }
            current = parent;
        }
        throw validationStoreError(
            `Field "${fieldName}" /Parent chain exceeds the supported depth`
        );
    };
    const fieldType = resolvePdfValue(
        context,
        inheritedFieldValue("FT"),
        (value): value is PDFName => value instanceof PDFName,
        `Field "${fieldName}" /FT`,
        "PDF name"
    );
    if (fieldType?.value.toString() !== "/Sig") {
        throw validationStoreError(`Field "${fieldName}" must have /FT /Sig`);
    }
    return field;
}

async function vriKeyForSignatureField(pdfDoc: PDFDocument, fieldName: string): Promise<PDFName> {
    const field = resolveSignatureField(pdfDoc, fieldName);
    const signature = resolvePdfValue(
        pdfDoc.context,
        (() => {
            const parentValues = new Set<PDFObject>();
            let current = field;
            for (let depth = 0; depth < MAX_FIELD_PARENT_DEPTH; depth++) {
                const identity = current.ref ?? current.value;
                if (parentValues.has(identity)) {
                    throw validationStoreError(
                        `Signature field "${fieldName}" /Parent chain contains a cycle`
                    );
                }
                parentValues.add(identity);
                const value = current.value.get(PDFName.of("V"));
                if (value !== undefined) {
                    return value;
                }
                const rawParent = current.value.get(PDFName.of("Parent"));
                const parent = resolvePdfValue(
                    pdfDoc.context,
                    rawParent,
                    (value): value is PDFDict => value instanceof PDFDict,
                    `Signature field "${fieldName}" /Parent`,
                    "PDF dictionary"
                );
                if (parent === undefined) {
                    return undefined;
                }
                if (
                    !(rawParent instanceof PDFRef) ||
                    parent.ref === undefined ||
                    current.ref === undefined
                ) {
                    throw validationStoreError(
                        `Signature field "${fieldName}" /Parent must be an exact indirect field reference`
                    );
                }
                current = parent;
            }
            throw validationStoreError(
                `Signature field "${fieldName}" /Parent chain exceeds the supported depth`
            );
        })(),
        (value): value is PDFDict => value instanceof PDFDict,
        `Signature field "${fieldName}" /V`,
        "PDF dictionary"
    );
    if (signature === undefined) {
        throw validationStoreError(`Signature field "${fieldName}" is unsigned`);
    }

    const contents = resolvePdfValue(
        pdfDoc.context,
        signature.value.get(PDFName.of("Contents")),
        (value): value is PDFHexString => value instanceof PDFHexString,
        `Signature field "${fieldName}" /Contents`,
        "PDF hex string"
    );
    if (contents === undefined) {
        throw validationStoreError(
            `Signature field "${fieldName}" /Contents must be a PDF hex string`
        );
    }

    const contentsValueBytes = contents.value.asBytes();
    await ensureWebCrypto();
    const hash = new Uint8Array(
        await crypto.subtle.digest("SHA-1", toArrayBuffer(contentsValueBytes))
    );
    return PDFName.of(bytesToHex(hash).toUpperCase());
}

function resolveVriDictionary(
    context: PDFDocument["context"],
    dss: PDFDict
): ResolvedPdfValue<PDFDict> {
    const existing = resolvePdfValue(
        context,
        dss.get(PDFName.of("VRI")),
        (value): value is PDFDict => value instanceof PDFDict,
        "DSS /VRI",
        "PDF dictionary"
    );
    if (existing !== undefined) {
        return existing;
    }

    const vri = context.obj({});
    dss.set(PDFName.of("VRI"), vri);
    return { value: vri };
}

function resolveVriEntry(
    context: PDFDocument["context"],
    vri: PDFDict,
    key: PDFName
): ResolvedPdfValue<PDFDict> {
    const existing = resolvePdfValue(
        context,
        vri.get(key),
        (value): value is PDFDict => value instanceof PDFDict,
        `VRI entry ${key.decodeText()}`,
        "PDF dictionary"
    );
    if (existing !== undefined) {
        return existing;
    }

    const entry = context.obj({ Type: PDFName.of("VRI") });
    vri.set(key, entry);
    return { value: entry };
}

const VRI_VALIDATION_KEYS = [
    { vri: "Cert", dss: "Certs" },
    { vri: "CRL", dss: "CRLs" },
    { vri: "OCSP", dss: "OCSPs" },
] as const;

interface ExistingVriEntry {
    entry: ResolvedPdfValue<PDFDict>;
    vri: ResolvedPdfValue<PDFDict>;
}

function globalValidationReferences(
    context: PDFDocument["context"],
    dss: PDFDict,
    key: ValidationArrayKey
): Set<string> {
    const validationArray = resolveValidationArray(context, dss, key, false);
    const references = new Set<string>();
    if (validationArray === undefined) {
        return references;
    }

    for (let index = 0; index < validationArray.array.size(); index++) {
        const ref = validationArray.array.get(index);
        if (!(ref instanceof PDFRef)) {
            throw validationStoreError(`${key} entries must be indirect PDF raw streams`);
        }
        if (!(context.lookup(ref) instanceof PDFRawStream)) {
            throw validationStoreError(`${key} entries must reference PDF raw streams`);
        }
        references.add(ref.toString());
    }
    return references;
}

function validateExistingVriReferences(
    context: PDFDocument["context"],
    dss: PDFDict
): ExistingVriEntry[] {
    const vri = resolvePdfValue(
        context,
        dss.get(PDFName.of("VRI")),
        (value): value is PDFDict => value instanceof PDFDict,
        "DSS /VRI",
        "PDF dictionary"
    );
    if (vri === undefined) {
        return [];
    }

    const globalReferences: Record<ValidationArrayKey, Set<string>> = {
        Certs: globalValidationReferences(context, dss, "Certs"),
        CRLs: globalValidationReferences(context, dss, "CRLs"),
        OCSPs: globalValidationReferences(context, dss, "OCSPs"),
    };

    const entriesWithoutType: ExistingVriEntry[] = [];
    for (const [entryKey, rawEntry] of vri.value.entries()) {
        const entry = resolvePdfValue(
            context,
            rawEntry,
            (value): value is PDFDict => value instanceof PDFDict,
            `VRI entry ${entryKey.decodeText()}`,
            "PDF dictionary"
        );
        if (entry === undefined) {
            throw validationStoreError(`VRI entry ${entryKey.decodeText()} is missing`);
        }
        const type = resolvePdfValue(
            context,
            entry.value.get(PDFName.of("Type")),
            (value): value is PDFName => value instanceof PDFName,
            `VRI entry ${entryKey.decodeText()} /Type`,
            "PDF name"
        );
        if (type !== undefined && type.value.toString() !== "/VRI") {
            throw validationStoreError(`VRI entry ${entryKey.decodeText()} /Type must be /VRI`);
        }
        if (type === undefined) {
            entriesWithoutType.push({ entry, vri });
        }

        for (const { vri: vriKey, dss: dssKey } of VRI_VALIDATION_KEYS) {
            const validationArray = resolvePdfValue(
                context,
                entry.value.get(PDFName.of(vriKey)),
                (value): value is PDFArray => value instanceof PDFArray,
                `VRI /${vriKey}`,
                "PDF array"
            );
            if (validationArray === undefined) {
                continue;
            }

            for (let index = 0; index < validationArray.value.size(); index++) {
                const ref = validationArray.value.get(index);
                if (!(ref instanceof PDFRef)) {
                    throw validationStoreError(`VRI /${vriKey} entries must be PDF references`);
                }
                if (!globalReferences[dssKey].has(ref.toString())) {
                    throw validationStoreError(
                        `VRI /${vriKey} reference is not present in DSS /${dssKey}`
                    );
                }
            }
        }
    }
    return entriesWithoutType;
}

function normalizeExistingVriEntryTypes(
    snapshot: ReturnType<PDFDocument["takeSnapshot"]>,
    dss: ResolvedPdfValue<PDFDict>,
    entries: ExistingVriEntry[]
): void {
    for (const { entry, vri } of entries) {
        entry.value.set(PDFName.of("Type"), PDFName.of("VRI"));
        if (entry.ref !== undefined) {
            snapshot.markRefForSave(entry.ref);
        } else if (vri.ref !== undefined) {
            snapshot.markRefForSave(vri.ref);
        } else if (dss.ref !== undefined) {
            snapshot.markRefForSave(dss.ref);
        }
    }
}

function mergeVriReferences(
    context: PDFDocument["context"],
    snapshot: ReturnType<PDFDocument["takeSnapshot"]>,
    entry: ResolvedPdfValue<PDFDict>,
    key: "Cert" | "CRL" | "OCSP",
    refs: PDFRef[]
): void {
    if (refs.length === 0) {
        return;
    }

    const keyName = PDFName.of(key);
    const existing = resolvePdfValue(
        context,
        entry.value.get(keyName),
        (value): value is PDFArray => value instanceof PDFArray,
        `VRI /${key}`,
        "PDF array"
    );
    const array = existing?.value ?? PDFArray.withContext(context);
    if (existing === undefined) {
        entry.value.set(keyName, array);
    }

    const knownRefs = new Set<string>();
    for (let index = 0; index < array.size(); index++) {
        const current = array.get(index);
        if (!(current instanceof PDFRef)) {
            throw validationStoreError(`VRI /${key} entries must be PDF references`);
        }
        knownRefs.add(current.toString());
    }

    let changed = existing === undefined;
    for (const ref of refs) {
        const refKey = ref.toString();
        if (!knownRefs.has(refKey)) {
            knownRefs.add(refKey);
            array.push(ref);
            changed = true;
        }
    }

    if (changed && existing?.ref) {
        snapshot.markRefForSave(existing.ref);
    }
    if (changed && entry.ref) {
        snapshot.markRefForSave(entry.ref);
    }
}

function updateVri(
    pdfDoc: PDFDocument,
    snapshot: ReturnType<PDFDocument["takeSnapshot"]>,
    dss: PDFDict,
    key: PDFName,
    references: Record<ValidationArrayKey, PDFRef[]>
): void {
    const vri = resolveVriDictionary(pdfDoc.context, dss);
    const entry = resolveVriEntry(pdfDoc.context, vri.value, key);

    mergeVriReferences(pdfDoc.context, snapshot, entry, "Cert", references.Certs);
    mergeVriReferences(pdfDoc.context, snapshot, entry, "CRL", references.CRLs);
    mergeVriReferences(pdfDoc.context, snapshot, entry, "OCSP", references.OCSPs);

    if (vri.ref) {
        snapshot.markRefForSave(vri.ref);
    }
    if (entry.ref) {
        snapshot.markRefForSave(entry.ref);
    }
}

/**
 * Adds validation material to a PDF Document Security Store without replacing
 * existing DSS entries or VRI data.
 */
export async function updateValidationStore(
    pdfBytes: Uint8Array,
    update: ValidationStoreUpdate,
    options?: ExtractOptions
): Promise<Uint8Array> {
    try {
        // The pre-load proof must reject malformed metadata and decompression
        // bombs before the dependency is allowed to parse PDF streams.
        const xrefProof = preflightPdfXref(pdfBytes);
        const pdfDoc = await PDFDocument.load(pdfBytes, {
            updateMetadata: false,
            ignoreEncryption: options?.ignoreEncryption ?? false,
        });
        const context = pdfDoc.context;
        restoreLargestObjectNumber(pdfBytes, context, xrefProof);
        if (update.vri !== undefined && pdfDoc.catalog.has(PDFName.of("VRI"))) {
            throw validationStoreError(
                "Catalog /VRI is not permitted; VRI must be stored under DSS"
            );
        }
        let vriKey: PDFName | undefined;
        const existingDss = findExistingDss(pdfDoc);
        let existingVriEntriesWithoutType: ExistingVriEntry[] = [];
        if (existingDss !== undefined) {
            // Validate every pre-existing VRI relationship before an incoming stream
            // can make a dangling reference appear valid.
            existingVriEntriesWithoutType = validateExistingVriReferences(
                context,
                existingDss.value
            );
        }
        if (update.vri !== undefined) {
            // Validate all existing references before any call can allocate a new
            // object or make an incoming stream satisfy a previously dangling ref.
            vriKey = await vriKeyForSignatureField(pdfDoc, update.vri.fieldName);
        }
        const snapshot = pdfDoc.takeSnapshot();
        if (existingDss !== undefined) {
            normalizeExistingVriEntryTypes(snapshot, existingDss, existingVriEntriesWithoutType);
        }
        const { dss, ref: dssRef } = resolveDss(pdfDoc);

        const validationData = update.vri?.validationData ?? update.validationData;
        const arrayUpdates: ValidationArrayUpdate[] = [
            { key: "Certs", bytes: validationData?.certificates ?? [] },
            { key: "CRLs", bytes: validationData?.crls ?? [] },
            { key: "OCSPs", bytes: validationData?.ocspResponses ?? [] },
        ];
        const references: Record<ValidationArrayKey, PDFRef[]> = {
            Certs: [],
            CRLs: [],
            OCSPs: [],
        };

        for (const arrayUpdate of arrayUpdates) {
            const validationArray = resolveValidationArray(
                context,
                dss,
                arrayUpdate.key,
                arrayUpdate.bytes.length > 0
            );
            references[arrayUpdate.key] = appendValidationData(
                context,
                snapshot,
                validationArray,
                arrayUpdate
            );
        }

        if (update.vri !== undefined) {
            if (vriKey === undefined) {
                throw validationStoreError("VRI key could not be resolved");
            }
            updateVri(pdfDoc, snapshot, dss, vriKey, references);
        }

        if (dssRef) {
            snapshot.markRefForSave(dssRef);
        }

        const catalogRef = context.trailerInfo.Root;
        if (catalogRef instanceof PDFRef) {
            snapshot.markRefForSave(catalogRef);
        }

        // PDFStreamWriter invents object-stream and xref-stream references outside
        // checkedRegister. The classic incremental writer allocates none of those.
        context.pdfFileDetails.useObjectStreams = false;
        const incrementalBytes = await pdfDoc.saveIncremental(snapshot);
        const finalBytes = new Uint8Array(pdfBytes.length + incrementalBytes.length);
        finalBytes.set(pdfBytes, 0);
        finalBytes.set(incrementalBytes, pdfBytes.length);
        return finalBytes;
    } catch (error) {
        if (error instanceof TimestampError) {
            throw error;
        }
        throw validationStoreError(
            `Failed to update PDF validation store: ${error instanceof Error ? error.message : String(error)}`,
            error
        );
    }
}
