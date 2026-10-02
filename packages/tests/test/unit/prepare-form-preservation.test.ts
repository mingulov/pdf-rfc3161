import { describe, expect, it } from "vitest";
import {
    PDFArray,
    PDFDict,
    PDFDocument,
    PDFName,
    PDFNumber,
    type PDFObject,
    PDFRef,
    PDFString,
} from "pdf-lib-incremental-save";
import { TimestampErrorCode } from "../../../core/src/index.js";
import { preparePdfForTimestamp } from "../../../core/src/pdf/prepare.js";

interface FormFixtureOptions {
    indirectAcroForm: boolean;
    indirectFields: boolean;
    indirectAnnots: boolean;
}

interface FormFixture {
    input: Uint8Array;
    oldFieldRef: PDFRef;
    oldWidgetRef: PDFRef;
}

function rectangle(context: PDFDict["context"]): PDFArray {
    const rect = PDFArray.withContext(context);
    rect.push(PDFNumber.of(0));
    rect.push(PDFNumber.of(0));
    rect.push(PDFNumber.of(10));
    rect.push(PDFNumber.of(10));
    return rect;
}

async function createFormFixture(options: FormFixtureOptions): Promise<FormFixture> {
    const document = await PDFDocument.create();
    const page = document.addPage([100, 100]);
    const context = document.context;

    const oldWidget = context.obj({
        Type: PDFName.of("Annot"),
        Subtype: PDFName.of("Widget"),
        Rect: rectangle(page.node.context),
    });
    const oldField = context.obj({
        FT: PDFName.of("Tx"),
        T: PDFString.of("Existing"),
        Kids: PDFArray.withContext(context),
    });
    const oldFieldRef = context.register(oldField);
    const oldWidgetRef = context.register(oldWidget);
    oldWidget.set(PDFName.of("Parent"), oldFieldRef);
    (oldField.get(PDFName.of("Kids")) as PDFArray).push(oldWidgetRef);

    const fields = PDFArray.withContext(context);
    fields.push(oldFieldRef);
    const fieldsValue = options.indirectFields ? context.register(fields) : fields;
    const acroForm = context.obj({ Fields: fieldsValue });
    document.catalog.set(
        PDFName.of("AcroForm"),
        options.indirectAcroForm ? context.register(acroForm) : acroForm
    );

    const annots = PDFArray.withContext(context);
    annots.push(oldWidgetRef);
    page.node.set(PDFName.of("Annots"), options.indirectAnnots ? context.register(annots) : annots);

    return {
        input: await document.save({ useObjectStreams: false }),
        oldFieldRef,
        oldWidgetRef,
    };
}

function resolveArray(context: PDFDict["context"], value: PDFArray | PDFRef): PDFArray {
    return value instanceof PDFRef ? context.lookup(value, PDFArray) : value;
}

function resolveDict(context: PDFDict["context"], value: PDFDict | PDFRef): PDFDict {
    return value instanceof PDFRef ? context.lookup(value, PDFDict) : value;
}

function fieldName(context: PDFDict["context"], fieldRef: PDFRef): string | undefined {
    const field = context.lookup(fieldRef, PDFDict);
    const name = field.get(PDFName.of("T"));
    return name instanceof PDFString ? name.decodeText() : undefined;
}

async function repeatedKidsDagPdf(depth = 20): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    let child = context.register(context.obj({ T: PDFString.of("Leaf") }));
    for (let index = 0; index < depth; index += 1) {
        child = context.register(
            context.obj({
                T: PDFString.of(`N${index.toString()}`),
                Kids: context.obj([child, child]),
            })
        );
    }
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: context.obj([child]) }));
    return document.save({ useObjectStreams: false });
}

async function deepFieldHierarchyPdf(depth = 257): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    let child = context.register(context.obj({}));
    for (let index = 1; index < depth; index += 1) {
        child = context.register(context.obj({ Kids: context.obj([child]) }));
    }
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: context.obj([child]) }));
    return document.save({ useObjectStreams: false });
}

async function oversizedFieldHierarchyPdf(nodeCount = 10_001): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const fields = PDFArray.withContext(document.context);
    for (let index = 0; index < nodeCount; index += 1) {
        fields.push(document.context.register(document.context.obj({})));
    }
    document.catalog.set(PDFName.of("AcroForm"), document.context.obj({ Fields: fields }));
    return document.save({ useObjectStreams: false });
}

async function prepareError(pdf: Uint8Array): Promise<unknown> {
    try {
        await preparePdfForTimestamp(pdf);
        return undefined;
    } catch (error) {
        return error;
    }
}

describe("preparePdfForTimestamp form preservation", () => {
    it.each([
        { indirectAcroForm: false, indirectFields: false, indirectAnnots: false },
        { indirectAcroForm: false, indirectFields: false, indirectAnnots: true },
        { indirectAcroForm: false, indirectFields: true, indirectAnnots: false },
        { indirectAcroForm: false, indirectFields: true, indirectAnnots: true },
        { indirectAcroForm: true, indirectFields: false, indirectAnnots: false },
        { indirectAcroForm: true, indirectFields: false, indirectAnnots: true },
        { indirectAcroForm: true, indirectFields: true, indirectAnnots: false },
        { indirectAcroForm: true, indirectFields: true, indirectAnnots: true },
    ])("preserves existing form references for %#", async (options: FormFixtureOptions) => {
        // A missed mark-for-save on an indirect array drops the appended widget/field.
        const fixture = await createFormFixture(options);

        const prepared = await preparePdfForTimestamp(fixture.input);
        const document = await PDFDocument.load(prepared.bytes, { updateMetadata: false });
        const page = document.getPages()[0];
        expect(page).toBeDefined();

        const acroFormValue = document.catalog.get(PDFName.of("AcroForm"));
        expect(acroFormValue).toBeDefined();
        const acroForm = resolveDict(document.context, acroFormValue as PDFDict | PDFRef);
        const fields = resolveArray(
            document.context,
            acroForm.get(PDFName.of("Fields")) as PDFArray | PDFRef
        );
        const annots = resolveArray(
            document.context,
            page?.node.get(PDFName.of("Annots")) as PDFArray | PDFRef
        );

        expect(prepared.bytes.slice(0, fixture.input.length)).toEqual(fixture.input);
        expect(fields.size()).toBe(2);
        expect(annots.size()).toBe(2);
        expect(fields.get(0)).toEqual(fixture.oldFieldRef);
        expect(annots.get(0)).toEqual(fixture.oldWidgetRef);
        expect(fields.get(1)).toEqual(annots.get(1));

        const newField = document.context.lookup(fields.get(1) as PDFRef, PDFDict);
        const newSignature = document.context.lookup(
            newField.get(PDFName.of("V")) as PDFRef,
            PDFDict
        );
        expect(newSignature.get(PDFName.of("Type"))?.toString()).toBe("/DocTimeStamp");
    });

    it.each(["AcroForm", "Fields", "Annots"] as const)(
        "rejects a present malformed /%s value",
        async (malformedValue: "AcroForm" | "Fields" | "Annots") => {
            // Replacing a malformed object graph silently discards form content.
            const document = await PDFDocument.create();
            const page = document.addPage([100, 100]);
            const context = document.context;

            if (malformedValue === "AcroForm") {
                document.catalog.set(PDFName.of("AcroForm"), PDFString.of("malformed"));
            } else {
                const acroForm = context.obj({ Fields: PDFArray.withContext(context) });
                document.catalog.set(PDFName.of("AcroForm"), acroForm);
                if (malformedValue === "Fields") {
                    acroForm.set(PDFName.of("Fields"), PDFString.of("malformed"));
                } else {
                    page.node.set(PDFName.of("Annots"), PDFString.of("malformed"));
                }
            }

            const input = await document.save({ useObjectStreams: false });
            await expect(preparePdfForTimestamp(input)).rejects.toMatchObject({
                code: TimestampErrorCode.PDF_ERROR,
            });
        }
    );

    it("allocates incrementing default names across sequential preparations", async () => {
        // Reusing Timestamp would make a PDF with multiple timestamps ambiguous.
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        let prepared = await document.save({ useObjectStreams: false });

        for (const expectedName of ["Timestamp", "Timestamp_2", "Timestamp_3"]) {
            prepared = (await preparePdfForTimestamp(prepared)).bytes;
            const reloaded = await PDFDocument.load(prepared, { updateMetadata: false });
            const acroForm = reloaded.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
            const fields = acroForm.lookup(PDFName.of("Fields"), PDFArray);
            expect(fieldName(reloaded.context, fields.get(fields.size() - 1) as PDFRef)).toBe(
                expectedName
            );
        }
    });

    it("fills the first available suffix for a requested base name", async () => {
        // Skipping a free suffix needlessly makes output names non-deterministic.
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const context = document.context;
        const fields = PDFArray.withContext(context);
        for (const name of ["Custom", "Custom_2", "Custom_4"]) {
            fields.push(
                context.register(context.obj({ FT: PDFName.of("Tx"), T: PDFString.of(name) }))
            );
        }
        document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));

        const prepared = await preparePdfForTimestamp(
            await document.save({ useObjectStreams: false }),
            {
                signatureFieldName: "Custom",
            }
        );
        const reloaded = await PDFDocument.load(prepared.bytes, { updateMetadata: false });
        const acroForm = reloaded.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
        const reloadedFields = acroForm.lookup(PDFName.of("Fields"), PDFArray);

        expect(fieldName(reloaded.context, reloadedFields.get(3) as PDFRef)).toBe("Custom_3");
    });

    it.each([
        { indirectChild: false, indirectKids: false },
        { indirectChild: false, indirectKids: true },
        { indirectChild: true, indirectKids: false },
        { indirectChild: true, indirectKids: true },
    ])(
        "uses fully qualified names from direct and indirect /Kids entries when allocating a name",
        async ({ indirectChild, indirectKids }: { indirectChild: boolean; indirectKids: boolean }) => {
            // Omitting a nested field would duplicate its fully qualified name.
            const document = await PDFDocument.create();
            document.addPage([100, 100]);
            const context = document.context;
            const child = context.obj({ FT: PDFName.of("Tx"), T: PDFString.of("Timestamp") });
            const childValue = indirectChild ? context.register(child) : child;
            const kidsArray = context.obj([childValue]);
            const parent = context.obj({
                T: PDFString.of("Group"),
                Kids: indirectKids ? context.register(kidsArray) : kidsArray,
            });
            const parentRef = context.register(parent);
            const fields = context.obj([parentRef]);
            document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));

            const prepared = await preparePdfForTimestamp(
                await document.save({ useObjectStreams: false }),
                { signatureFieldName: "Group.Timestamp" }
            );
            const reloaded = await PDFDocument.load(prepared.bytes, { updateMetadata: false });
            const acroForm = reloaded.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
            const reloadedFields = acroForm.lookup(PDFName.of("Fields"), PDFArray);
            const existingParent = reloaded.context.lookup(
                reloadedFields.get(0) as PDFRef,
                PDFDict
            );
            const kids = existingParent.lookup(PDFName.of("Kids"), PDFArray);
            const existingChild = resolveDict(reloaded.context, kids.get(0) as PDFDict | PDFRef);

            expect((existingParent.get(PDFName.of("T")) as PDFString).decodeText()).toBe("Group");
            expect((existingChild.get(PDFName.of("T")) as PDFString).decodeText()).toBe(
                "Timestamp"
            );
            expect(fieldName(reloaded.context, reloadedFields.get(1) as PDFRef)).toBe(
                "Group.Timestamp_2"
            );
        }
    );

    it("rejects a reused /Kids field node before traversing an exponential DAG", async () => {
        await expect(prepareError(await repeatedKidsDagPdf())).resolves.toMatchObject({
            code: TimestampErrorCode.PDF_ERROR,
        });
    });

    it("rejects a field hierarchy deeper than the shared traversal limit", async () => {
        await expect(prepareError(await deepFieldHierarchyPdf())).resolves.toMatchObject({
            code: TimestampErrorCode.PDF_ERROR,
        });
    });

    it("rejects more unique field nodes than the shared traversal limit", async () => {
        await expect(prepareError(await oversizedFieldHierarchyPdf())).resolves.toMatchObject({
            code: TimestampErrorCode.PDF_ERROR,
        });
    });
});

interface SigFlagsFixtureOptions {
    indirectAcroForm: boolean;
    indirectSigFlags: boolean;
}

async function createSigFlagsFixture(
    sigFlags: PDFObject | undefined,
    options: SigFlagsFixtureOptions
): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const acroForm = context.obj({ Fields: PDFArray.withContext(context) });
    if (sigFlags !== undefined) {
        acroForm.set(
            PDFName.of("SigFlags"),
            options.indirectSigFlags ? context.register(sigFlags) : sigFlags
        );
    }
    document.catalog.set(
        PDFName.of("AcroForm"),
        options.indirectAcroForm ? context.register(acroForm) : acroForm
    );
    return document.save({ useObjectStreams: false });
}

async function readSigFlags(bytes: Uint8Array): Promise<PDFObject | undefined> {
    const document = await PDFDocument.load(bytes, { updateMetadata: false });
    const acroFormValue = document.catalog.get(PDFName.of("AcroForm"));
    if (!(acroFormValue instanceof PDFDict) && !(acroFormValue instanceof PDFRef)) {
        throw new Error("AcroForm is missing from the prepared PDF");
    }
    const acroForm = resolveDict(document.context, acroFormValue);
    const raw = acroForm.get(PDFName.of("SigFlags"));
    if (raw === undefined) return undefined;
    return raw instanceof PDFRef ? document.context.lookup(raw) : raw;
}

async function expectSigFlags(bytes: Uint8Array, expected: number): Promise<void> {
    const value = await readSigFlags(bytes);
    expect(value).toBeInstanceOf(PDFNumber);
    expect((value as PDFNumber).asNumber()).toBe(expected);
}

describe("preparePdfForTimestamp SigFlags handling (T10 R14)", () => {
    it("sets SigFlags to 3 when the key is absent", async () => {
        const prepared = await preparePdfForTimestamp(
            await createSigFlagsFixture(undefined, {
                indirectAcroForm: false,
                indirectSigFlags: false,
            })
        );

        await expectSigFlags(prepared.bytes, 3);
    });

    it.each([0, 1, 2])("upgrades a direct SigFlags %i to 3", async (initial: number) => {
        const prepared = await preparePdfForTimestamp(
            await createSigFlagsFixture(PDFNumber.of(initial), {
                indirectAcroForm: false,
                indirectSigFlags: false,
            })
        );

        await expectSigFlags(prepared.bytes, 3);
    });

    it.each([
        { initial: 4, expected: 7 },
        { initial: 8, expected: 11 },
        { initial: 12, expected: 15 },
    ])(
        "retains unrelated SigFlags bits ($initial becomes $expected)",
        async ({ initial, expected }: { initial: number; expected: number }) => {
            const prepared = await preparePdfForTimestamp(
                await createSigFlagsFixture(PDFNumber.of(initial), {
                    indirectAcroForm: false,
                    indirectSigFlags: false,
                })
            );

            await expectSigFlags(prepared.bytes, expected);
        }
    );

    it("leaves an already conformant SigFlags 3 untouched", async () => {
        const input = await createSigFlagsFixture(PDFNumber.of(3), {
            indirectAcroForm: false,
            indirectSigFlags: false,
        });

        const prepared = await preparePdfForTimestamp(input);

        await expectSigFlags(prepared.bytes, 3);
        expect(prepared.bytes.subarray(0, input.length)).toEqual(input);
    });

    it("leaves an indirect already conformant SigFlags 3 untouched without rewrite", async () => {
        const input = await createSigFlagsFixture(PDFNumber.of(3), {
            indirectAcroForm: false,
            indirectSigFlags: true,
        });

        const prepared = await preparePdfForTimestamp(input);

        await expectSigFlags(prepared.bytes, 3);
        expect(prepared.bytes.subarray(0, input.length)).toEqual(input);
        const reloaded = await PDFDocument.load(prepared.bytes, { updateMetadata: false });
        const acroFormValue = reloaded.catalog.get(PDFName.of("AcroForm"));
        expect(acroFormValue).toBeDefined();
        const acroForm = resolveDict(reloaded.context, acroFormValue as PDFDict | PDFRef);
        expect(acroForm.get(PDFName.of("SigFlags"))).toBeInstanceOf(PDFRef);
    });

    it.each([true, false])(
        "upgrades an indirect SigFlags through %s AcroForm storage",
        async (indirectAcroForm: boolean) => {
            const prepared = await preparePdfForTimestamp(
                await createSigFlagsFixture(PDFNumber.of(1), {
                    indirectAcroForm,
                    indirectSigFlags: true,
                })
            );

            await expectSigFlags(prepared.bytes, 3);
        }
    );

    it.each([true, false])(
        "upgrades a direct SigFlags through %s AcroForm storage",
        async (indirectAcroForm: boolean) => {
            const prepared = await preparePdfForTimestamp(
                await createSigFlagsFixture(PDFNumber.of(2), {
                    indirectAcroForm,
                    indirectSigFlags: false,
                })
            );

            await expectSigFlags(prepared.bytes, 3);
        }
    );

    it.each([
        { label: "string", indirect: false },
        { label: "array", indirect: false },
        { label: "non-integer number", indirect: false },
        { label: "negative number", indirect: false },
        { label: "indirect string", indirect: true },
    ])("rejects a malformed $label SigFlags value", async ({ label, indirect }: { label: string; indirect: boolean }) => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const context = document.context;
        const malformed: PDFObject =
            label === "string" || label === "indirect string"
                ? PDFString.of("3")
                : label === "array"
                  ? PDFArray.withContext(context)
                  : label === "non-integer number"
                    ? PDFNumber.of(1.5)
                    : PDFNumber.of(-1);
        const acroForm = context.obj({ Fields: PDFArray.withContext(context) });
        acroForm.set(
            PDFName.of("SigFlags"),
            indirect ? context.register(malformed) : malformed
        );
        document.catalog.set(PDFName.of("AcroForm"), acroForm);
        const input = await document.save({ useObjectStreams: false });

        await expect(preparePdfForTimestamp(input)).rejects.toMatchObject({
            code: TimestampErrorCode.PDF_ERROR,
        });
    });
});

describe("preparePdfForTimestamp certification policy preservation (T10)", () => {
    it("preserves DocMDP/FieldMDP policy dictionaries byte-identically; authorization is unsupported", async () => {
        // Certification authorization (whether timestamping is permitted under
        // the DocMDP/FieldMDP policy, and whether this update keeps the
        // certification valid) is explicitly unsupported: the library performs
        // no policy evaluation. This pins the structural guarantee only: the
        // policy dictionaries survive preparation byte-identically because the
        // original revision is never rewritten.
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const context = document.context;
        const docMdpReference = context.obj({
            Type: PDFName.of("SigRef"),
            TransformMethod: PDFName.of("DocMDP"),
            TransformParams: context.obj({
                Type: PDFName.of("TransformParams"),
                P: PDFNumber.of(2),
                V: PDFName.of("1.2"),
            }),
        });
        const fieldMdpReference = context.obj({
            Type: PDFName.of("SigRef"),
            TransformMethod: PDFName.of("FieldMDP"),
            TransformParams: context.obj({
                Type: PDFName.of("TransformParams"),
                P: PDFNumber.of(2),
                Fields: context.obj(["Existing"]),
            }),
        });
        const perms = context.obj({
            DocMDP: context.register(
                context.obj({
                    Type: PDFName.of("Sig"),
                    Filter: PDFName.of("Adobe.PPKLite"),
                    SubFilter: PDFName.of("adbe.pkcs7.detached"),
                    Reference: context.obj([docMdpReference]),
                })
            ),
            FieldMDP: context.register(
                context.obj({
                    Type: PDFName.of("Sig"),
                    Filter: PDFName.of("Adobe.PPKLite"),
                    SubFilter: PDFName.of("adbe.pkcs7.detached"),
                    Reference: context.obj([fieldMdpReference]),
                })
            ),
        });
        document.catalog.set(PDFName.of("Perms"), context.register(perms));
        const input = await document.save({ useObjectStreams: false });

        const prepared = await preparePdfForTimestamp(input);

        expect(prepared.bytes.subarray(0, input.length)).toEqual(input);
        const reloaded = await PDFDocument.load(prepared.bytes, { updateMetadata: false });
        const reloadedPerms = reloaded.catalog.lookup(PDFName.of("Perms"), PDFDict);
        const docMdp = reloadedPerms.lookup(PDFName.of("DocMDP"), PDFDict);
        const docMdpReferences = docMdp.lookup(PDFName.of("Reference"), PDFArray);
        const docMdpParams = (
            resolveDict(reloaded.context, docMdpReferences.get(0) as PDFDict | PDFRef).lookup(
                PDFName.of("TransformParams"),
                PDFDict
            )
        ).lookup(PDFName.of("P"), PDFNumber);
        expect(docMdpParams.asNumber()).toBe(2);
        const fieldMdp = reloadedPerms.lookup(PDFName.of("FieldMDP"), PDFDict);
        const fieldMdpReferences = fieldMdp.lookup(PDFName.of("Reference"), PDFArray);
        expect(fieldMdpReferences.size()).toBe(1);
    });
});
