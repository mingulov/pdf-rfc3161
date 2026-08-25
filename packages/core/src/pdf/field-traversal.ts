import {
    PDFArray,
    PDFDict,
    PDFDocument,
    PDFHexString,
    PDFName,
    type PDFObject,
    PDFRef,
    PDFString,
} from "pdf-lib-incremental-save";

export const MAX_FIELD_HIERARCHY_DEPTH = 256;
export const MAX_FIELD_HIERARCHY_NODES = 10_000;

export interface ResolvedAcroFormField {
    field: PDFDict;
    ref?: PDFRef;
    /** Fully qualified field name, undefined for unnamed widget nodes. */
    fieldName?: string;
    /** True for an unnamed widget annotation, never a distinct form field. */
    isWidget: boolean;
    /** Values inherited through the AcroForm /Kids hierarchy, nearest first. */
    inheritedValue(key: string): PDFObject | undefined;
    /** Indirect object that physically owns an inherited value, when one exists. */
    inheritedOwnerRef(key: string): PDFRef | undefined;
}

export interface FieldTraversalOptions {
    /** Enforce the strict /Parent references required by VRI mutation. */
    strictParentLinks?: boolean;
    /** Continue with independent field-tree branches after a malformed node. */
    continueOnError?: boolean;
    /** Receives the best available name for a skipped malformed field branch. */
    onMalformedField?: (fieldName: string | undefined) => void;
}

interface ResolvedPdfValue<T extends PDFObject> {
    value: T;
    ref?: PDFRef;
}

interface FieldLineageNode {
    field: PDFDict;
    /**
     * The nearest indirect object that serializes this direct or indirect
     * field dictionary. This is not necessarily the field's own reference:
     * a direct child can be serialized inside an indirect parent or /Kids
     * array object.
     */
    ownerRef?: PDFRef;
}

function resolvePdfValue<T extends PDFObject>(
    context: PDFDocument["context"],
    rawValue: PDFObject | undefined,
    isExpectedType: (value: PDFObject) => value is T,
    description: string,
    expectedType: string
): ResolvedPdfValue<T> | undefined {
    if (rawValue === undefined) return undefined;
    const ref = rawValue instanceof PDFRef ? rawValue : undefined;
    const value = ref === undefined ? rawValue : context.lookup(ref);
    if (value === undefined || !isExpectedType(value)) {
        throw new Error(`${description} must be a ${expectedType}`);
    }
    return ref === undefined ? { value } : { value, ref };
}

function resolveFieldName(
    context: PDFDocument["context"],
    rawValue: PDFObject | undefined
): string | undefined {
    if (rawValue === undefined) return undefined;
    const value = rawValue instanceof PDFRef ? context.lookup(rawValue) : rawValue;
    if (!(value instanceof PDFString) && !(value instanceof PDFHexString)) {
        throw new Error("Field /T must be a PDF string");
    }
    return value.decodeText();
}

function sameReference(left: PDFRef, right: PDFRef): boolean {
    return (
        left.objectNumber === right.objectNumber && left.generationNumber === right.generationNumber
    );
}

/**
 * Resolves the AcroForm field tree once, including direct and indirect
 * entries. The traversal is bounded and rejects cycles or a field node reused
 * through more than one /Kids path. Consumers that need mutation-grade
 * invariants can additionally require exact indirect /Parent links.
 */
export function collectAcroFormFields(
    pdfDoc: PDFDocument,
    options: FieldTraversalOptions = {}
): ResolvedAcroFormField[] {
    const context = pdfDoc.context;
    const acroForm = resolvePdfValue(
        context,
        pdfDoc.catalog.get(PDFName.of("AcroForm")),
        (value): value is PDFDict => value instanceof PDFDict,
        "AcroForm",
        "PDF dictionary"
    );
    if (acroForm === undefined) return [];

    const fields = resolvePdfValue(
        context,
        acroForm.value.get(PDFName.of("Fields")),
        (value): value is PDFArray => value instanceof PDFArray,
        "AcroForm /Fields",
        "PDF array"
    );
    if (fields === undefined) return [];

    const result: ResolvedAcroFormField[] = [];
    const ancestors = new Set<PDFObject>();
    const visited = new Set<PDFObject>();
    const catalogRef = context.getObjectRef(pdfDoc.catalog);

    const visitField = (
        rawField: PDFObject,
        parentName: string | undefined,
        expectedParent: PDFRef | undefined,
        isRootField: boolean,
        containingRef: PDFRef | undefined,
        inheritance: readonly FieldLineageNode[],
        depth: number
    ): void => {
        let identity: PDFObject | undefined;
        let fieldName = parentName;
        try {
            if (depth >= MAX_FIELD_HIERARCHY_DEPTH) {
                throw new Error("Field hierarchy exceeds the supported depth");
            }
            if (visited.size >= MAX_FIELD_HIERARCHY_NODES) {
                throw new Error("Field hierarchy exceeds the supported node count");
            }
            const resolved = resolvePdfValue(
                context,
                rawField,
                (value): value is PDFDict => value instanceof PDFDict,
                "Field",
                "PDF dictionary"
            );
            if (resolved === undefined) throw new Error("Field must be a PDF dictionary");

            identity = resolved.ref ?? resolved.value;
            if (ancestors.has(identity)) throw new Error("Field hierarchy contains a cycle");
            if (visited.has(identity)) throw new Error("Field hierarchy reuses a field node");
            ancestors.add(identity);
            visited.add(identity);

            const partialName = resolveFieldName(context, resolved.value.get(PDFName.of("T")));
            if (options.strictParentLinks) {
                const rawParent = resolved.value.get(PDFName.of("Parent"));
                const parent = resolvePdfValue(
                    context,
                    rawParent,
                    (value): value is PDFDict => value instanceof PDFDict,
                    "Field /Parent",
                    "PDF dictionary"
                );
                if (isRootField) {
                    if (parent !== undefined) {
                        throw new Error("AcroForm root field must not have a /Parent");
                    }
                } else if (
                    expectedParent === undefined ||
                    parent === undefined ||
                    !(rawParent instanceof PDFRef) ||
                    parent.ref === undefined ||
                    !sameReference(rawParent, expectedParent)
                ) {
                    throw new Error("Field /Parent must be the exact indirect containing /Kids field");
                }
            }

            fieldName =
                partialName === undefined
                    ? undefined
                    : parentName === undefined
                      ? partialName
                      : `${parentName}.${partialName}`;
            const isWidget = partialName === undefined;
            if (isWidget) {
                const subtype = resolvePdfValue(
                    context,
                    resolved.value.get(PDFName.of("Subtype")),
                    (value): value is PDFName => value instanceof PDFName,
                    "Unnamed field /Subtype",
                    "PDF name"
                );
                if (subtype?.value.toString() !== "/Widget") {
                    throw new Error("Unnamed field node must be a widget annotation");
                }
            }

            // A direct field is serialized in its nearest indirect container. Keep
            // that ref with inherited values so raw /Contents ByteRange validation
            // can bind a direct /V dictionary to the selected field, rather than
            // accepting an identical token from another object.
            const ownerRef = resolved.ref ?? containingRef;

            const lineage: readonly FieldLineageNode[] = [
                { field: resolved.value, ownerRef },
                ...inheritance,
            ];
            result.push({
                field: resolved.value,
                ref: resolved.ref,
                fieldName,
                isWidget,
                inheritedValue: (key: string): PDFObject | undefined => {
                    const keyName = PDFName.of(key);
                    for (const node of lineage) {
                        const value = node.field.get(keyName);
                        if (value !== undefined) return value;
                    }
                    return undefined;
                },
                inheritedOwnerRef: (key: string): PDFRef | undefined => {
                    const keyName = PDFName.of(key);
                    for (const node of lineage) {
                        if (node.field.get(keyName) !== undefined) return node.ownerRef;
                    }
                    return undefined;
                },
            });

            const kids = resolvePdfValue(
                context,
                resolved.value.get(PDFName.of("Kids")),
                (value): value is PDFArray => value instanceof PDFArray,
                "Field /Kids",
                "PDF array"
            );
            if (kids !== undefined) {
                const nextParentName = fieldName ?? parentName;
                const kidsContainingRef = kids.ref ?? ownerRef;
                for (let index = 0; index < kids.value.size(); index += 1) {
                    visitField(
                        kids.value.get(index),
                        nextParentName,
                        resolved.ref,
                        false,
                        kidsContainingRef,
                        lineage,
                        depth + 1
                    );
                }
            }
        } catch (error) {
            if (!options.continueOnError) throw error;
            options.onMalformedField?.(fieldName);
        } finally {
            if (identity !== undefined) ancestors.delete(identity);
        }
    };

    for (let index = 0; index < fields.value.size(); index += 1) {
        visitField(
            fields.value.get(index),
            undefined,
            undefined,
            true,
            fields.ref ?? acroForm.ref ?? catalogRef,
            [],
            0
        );
    }
    return result;
}
