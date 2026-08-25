import { describe, expect, it } from "vitest";
import {
    PDFArray,
    PDFDict,
    PDFDocument,
    PDFName,
    PDFNumber,
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
    ])("preserves existing form references for %#", async (options) => {
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
        async (malformedValue) => {
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
        async ({ indirectChild, indirectKids }) => {
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
});
