import { beforeEach, describe, expect, it, vi } from "vitest";
import {
    PDFArray,
    PDFDict,
    PDFDocument,
    PDFHexString,
    PDFName,
    PDFString,
} from "pdf-lib-incremental-save";
import { archiveTimestamp } from "../../../core/src/pdf/archive.js";
import { discoverArchiveTimestamps, extractTimestamps } from "../../../core/src/pdf/extract.js";
import { getDSSInfo } from "../../../core/src/pdf/ltv.js";
import {
    TimestampError,
    TimestampErrorCode,
    type TimestampOptions,
} from "../../../core/src/types.js";
import { createRFC3161TokenFixture } from "../fixtures/rfc3161-token.js";

vi.mock("../../../core/src/index.js", () => ({ timestampPdf: vi.fn() }));

const warnSpy = vi.fn();
vi.mock("../../../core/src/utils/logger.js", async (importOriginal: <T = unknown>() => Promise<T>) => {
    const mod = await importOriginal<typeof import("../../../core/src/utils/logger.js")>();
    return {
        ...mod,
        getLogger: () => ({
            debug: vi.fn(),
            info: vi.fn(),
            warn: warnSpy,
            error: vi.fn(),
        }),
    };
});

import { timestampPdf } from "../../../core/src/index.js";

type MalformedDocumentTimestampShape =
    | "all-zero-placeholder"
    | "invalid-token"
    | "missing-contents"
    | "non-hex-contents"
    | "missing-byte-range"
    | "wrong-byte-range"
    | "short-byte-range"
    | "missing-value"
    | "wrong-value";

const malformedDocumentTimestampCases: {
    label: string;
    shape: MalformedDocumentTimestampShape;
}[] = [
    { label: "all-zero Contents placeholder", shape: "all-zero-placeholder" },
    { label: "invalid token", shape: "invalid-token" },
    { label: "missing Contents", shape: "missing-contents" },
    { label: "non-hex Contents", shape: "non-hex-contents" },
    { label: "missing ByteRange", shape: "missing-byte-range" },
    { label: "wrong ByteRange", shape: "wrong-byte-range" },
    { label: "short ByteRange", shape: "short-byte-range" },
    { label: "missing V dictionary", shape: "missing-value" },
    { label: "wrong V dictionary", shape: "wrong-value" },
];

const SCANNER_RETAINED_STRUCTURE_CAP = 100_000;

let validTimestampContentsPromise: Promise<string> | undefined;

function validTimestampContents(): Promise<string> {
    validTimestampContentsPromise ??= createRFC3161TokenFixture().then((fixture) =>
        Array.from(fixture.rawToken, (byte) => byte.toString(16).padStart(2, "0")).join("")
    );
    return validTimestampContentsPromise;
}

function withByteRangeCoveringContents(pdf: Uint8Array): Uint8Array {
    const result = new Uint8Array(pdf);
    const text = new TextDecoder("latin1").decode(result);
    const contentsKey = text.lastIndexOf("/Contents");
    if (contentsKey < 0) throw new Error("Test PDF has no Contents key");
    const contentsStart = text.indexOf("<", contentsKey);
    const contentsEnd = text.indexOf(">", contentsStart);
    if (contentsStart < 0 || contentsEnd < 0) throw new Error("Test PDF has no Contents hex string");

    const byteRangeStart = text.lastIndexOf("/ByteRange");
    const byteRangeEnd = text.indexOf("]", byteRangeStart);
    if (byteRangeStart < 0 || byteRangeEnd < 0) throw new Error("Test PDF has no ByteRange");
    const replacement = `/ByteRange [0 ${String(contentsStart)} ${String(contentsEnd + 1)} ${String(
        result.length - (contentsEnd + 1)
    )}]`;
    const originalLength = byteRangeEnd + 1 - byteRangeStart;
    if (replacement.length > originalLength) throw new Error("Test ByteRange placeholder is too small");
    result.set(new TextEncoder().encode(replacement.padEnd(originalLength, " ")), byteRangeStart);
    return result;
}

async function malformedDocTimeStampPdf(shape: MalformedDocumentTimestampShape): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = PDFDict.withContext(context);
    signature.set(PDFName.of("Type"), PDFName.of("DocTimeStamp"));
    signature.set(PDFName.of("SubFilter"), PDFName.of("ETSI.RFC3161"));
    if (shape === "all-zero-placeholder") {
        signature.set(PDFName.of("Contents"), PDFHexString.of("00000000"));
    }
    if (shape === "invalid-token") signature.set(PDFName.of("Contents"), PDFHexString.of("3001"));
    if (shape === "non-hex-contents") {
        signature.set(PDFName.of("Contents"), PDFString.of("not-a-hex-string"));
    }
    if (
        shape !== "missing-contents" &&
        shape !== "all-zero-placeholder" &&
        shape !== "invalid-token" &&
        shape !== "non-hex-contents"
    ) {
        signature.set(PDFName.of("Contents"), PDFHexString.of(await validTimestampContents()));
    }
    if (shape === "wrong-byte-range") {
        signature.set(PDFName.of("ByteRange"), PDFString.of("not-an-array"));
    } else if (shape === "short-byte-range") {
        signature.set(PDFName.of("ByteRange"), context.obj([0, 0, 0]));
    } else if (shape !== "missing-byte-range") {
        signature.set(PDFName.of("ByteRange"), context.obj([0, 0, 0, 0]));
    }
    const signatureRef = context.register(signature);

    const field = PDFDict.withContext(context);
    field.set(PDFName.of("FT"), PDFName.of("Sig"));
    field.set(PDFName.of("T"), PDFString.of("MalformedDocTimeStamp"));
    if (shape === "missing-value" || shape === "wrong-value") {
        // Retain a malformed field-level marker when /V cannot identify the
        // intended RFC 3161 document timestamp.
        field.set(PDFName.of("SubFilter"), PDFName.of("ETSI.RFC3161"));
    }
    if (shape === "wrong-value") {
        field.set(PDFName.of("V"), PDFString.of("not-a-signature-dictionary"));
    } else if (shape !== "missing-value") {
        field.set(PDFName.of("V"), signatureRef);
    }
    const fields = PDFArray.withContext(context);
    fields.push(context.register(field));
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));

    return document.save({ useObjectStreams: false });
}

async function nestedAllZeroDocumentTimestampPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = context.obj({
        Type: PDFName.of("DocTimeStamp"),
        SubFilter: PDFName.of("ETSI.RFC3161"),
        Contents: PDFHexString.of("00000000"),
        ByteRange: context.obj([0, 0, 0, 0]),
    });
    const signatureRef = context.register(signature);
    const child = PDFDict.withContext(context);
    const childRef = context.register(child);
    const kids = PDFArray.withContext(context);
    kids.push(childRef);
    const parent = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("Parent"),
        Kids: kids,
    });
    const parentRef = context.register(parent);
    child.set(PDFName.of("T"), PDFString.of("Timestamp"));
    child.set(PDFName.of("Parent"), parentRef);
    child.set(PDFName.of("V"), signatureRef);

    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: context.obj([parentRef]) }));
    return document.save({ useObjectStreams: false });
}

async function validTimestampWithMalformedTextSiblingPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = context.register(
        context.obj({
            Type: PDFName.of("DocTimeStamp"),
            SubFilter: PDFName.of("ETSI.RFC3161"),
            Contents: PDFHexString.of(await validTimestampContents()),
            ByteRange: context.obj([0, 111111111111, 111111111111, 111111111111]),
        })
    );
    const validField = context.register(
        context.obj({
            FT: PDFName.of("Sig"),
            T: PDFString.of("ValidTimestamp"),
            V: signature,
        })
    );
    const malformedTextField = context.register(
        context.obj({
            FT: PDFName.of("Tx"),
            T: PDFString.of("BrokenText"),
            Kids: PDFString.of("not-an-array"),
        })
    );
    document.catalog.set(
        PDFName.of("AcroForm"),
        context.obj({ Fields: context.obj([validField, malformedTextField]) })
    );
    return withByteRangeCoveringContents(await document.save({ useObjectStreams: false }));
}

async function cyclicAcroFormTimestampPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = context.obj({
        Type: PDFName.of("DocTimeStamp"),
        SubFilter: PDFName.of("ETSI.RFC3161"),
        Contents: PDFHexString.of("00000000"),
        ByteRange: context.obj([0, 0, 0, 0]),
    });
    const field = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("Cyclic"),
        V: context.register(signature),
    });
    const fieldRef = context.register(field);
    field.set(PDFName.of("Kids"), context.obj([fieldRef]));
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: context.obj([fieldRef]) }));
    return document.save({ useObjectStreams: false });
}

type TimestampMarker = "exact" | "absent" | "wrong";

interface ResolvedValueMarkerCase {
    label: string;
    type: TimestampMarker;
    subFilter: TimestampMarker;
    fieldType?: TimestampMarker;
    fieldSubFilter?: TimestampMarker;
    archiveMalformed: boolean;
    archiveCount: number;
    publicCount: number;
}

const resolvedValueMarkerCases: ResolvedValueMarkerCase[] = [
    {
        label: "exact Type and SubFilter",
        type: "exact",
        subFilter: "exact",
        archiveMalformed: false,
        archiveCount: 1,
        publicCount: 1,
    },
    {
        label: "exact Type with absent SubFilter",
        type: "exact",
        subFilter: "absent",
        archiveMalformed: true,
        archiveCount: 0,
        publicCount: 0,
    },
    {
        label: "exact Type with wrong SubFilter",
        type: "exact",
        subFilter: "wrong",
        archiveMalformed: true,
        archiveCount: 0,
        publicCount: 0,
    },
    {
        label: "exact SubFilter with absent Type",
        type: "absent",
        subFilter: "exact",
        archiveMalformed: true,
        archiveCount: 0,
        publicCount: 1,
    },
    {
        label: "exact SubFilter with wrong Type",
        type: "wrong",
        subFilter: "exact",
        archiveMalformed: true,
        archiveCount: 0,
        publicCount: 1,
    },
    {
        label: "ordinary resolved signature despite exact field markers",
        type: "absent",
        subFilter: "absent",
        fieldType: "exact",
        fieldSubFilter: "exact",
        archiveMalformed: false,
        archiveCount: 0,
        publicCount: 0,
    },
    {
        label: "invalid resolved value despite misleading non-timestamp field markers",
        type: "exact",
        subFilter: "wrong",
        fieldType: "wrong",
        fieldSubFilter: "wrong",
        archiveMalformed: true,
        archiveCount: 0,
        publicCount: 0,
    },
];

function setTimestampMarker(
    dictionary: PDFDict,
    name: "Type" | "SubFilter",
    marker: TimestampMarker,
    exactValue: string,
    wrongValue: string
): void {
    if (marker === "exact") dictionary.set(PDFName.of(name), PDFName.of(exactValue));
    if (marker === "wrong") dictionary.set(PDFName.of(name), PDFName.of(wrongValue));
}

async function resolvedValueMarkerPdf(markerCase: ResolvedValueMarkerCase): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = PDFDict.withContext(context);
    setTimestampMarker(signature, "Type", markerCase.type, "DocTimeStamp", "NotDocTimeStamp");
    setTimestampMarker(signature, "SubFilter", markerCase.subFilter, "ETSI.RFC3161", "NotRFC3161");
    signature.set(PDFName.of("Contents"), PDFHexString.of(await validTimestampContents()));
    signature.set(
        PDFName.of("ByteRange"),
        context.obj([0, 111111111111, 111111111111, 111111111111])
    );
    const signatureRef = context.register(signature);

    const field = PDFDict.withContext(context);
    field.set(PDFName.of("FT"), PDFName.of("Sig"));
    field.set(PDFName.of("T"), PDFString.of("ResolvedValueMarkers"));
    field.set(PDFName.of("V"), signatureRef);
    if (markerCase.fieldType) {
        setTimestampMarker(field, "Type", markerCase.fieldType, "DocTimeStamp", "NotDocTimeStamp");
    }
    if (markerCase.fieldSubFilter) {
        setTimestampMarker(
            field,
            "SubFilter",
            markerCase.fieldSubFilter,
            "ETSI.RFC3161",
            "NotRFC3161"
        );
    }

    const fields = PDFArray.withContext(context);
    fields.push(context.register(field));
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));
    return withByteRangeCoveringContents(await document.save({ useObjectStreams: false }));
}

async function directSubFilterOnlyTimestampPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const field = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("DirectLegacyTimestamp"),
        V: context.obj({
            SubFilter: PDFName.of("ETSI.RFC3161"),
            Contents: PDFHexString.of(await validTimestampContents()),
            ByteRange: context.obj([0, 111111111111, 111111111111, 111111111111]),
        }),
    });
    document.catalog.set(
        PDFName.of("AcroForm"),
        context.obj({ Fields: context.obj([context.register(field)]) })
    );
    return withByteRangeCoveringContents(await document.save({ useObjectStreams: false }));
}

function addScannerCapExceedingUnrelatedObject(document: PDFDocument): void {
    const values = PDFArray.withContext(document.context);
    for (let index = 0; index <= SCANNER_RETAINED_STRUCTURE_CAP; index += 1) {
        values.push(document.context.obj(0));
    }
    document.catalog.set(PDFName.of("Unrelated"), values);
}

async function inheritedFtAndValueTimestampPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signatureRef = context.register(
        context.obj({
            Type: PDFName.of("DocTimeStamp"),
            SubFilter: PDFName.of("ETSI.RFC3161"),
            Contents: PDFHexString.of(await validTimestampContents()),
            ByteRange: context.obj([0, 111111111111, 111111111111, 111111111111]),
        })
    );
    const child = context.obj({ T: PDFString.of("InheritedTimestamp") });
    const childRef = context.register(child);
    const parent = context.obj({
        FT: PDFName.of("Sig"),
        V: signatureRef,
        Subtype: PDFName.of("Widget"),
        Kids: context.obj([childRef]),
    });
    const parentRef = context.register(parent);
    child.set(PDFName.of("Parent"), parentRef);
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: context.obj([parentRef]) }));

    return withByteRangeCoveringContents(await document.save({ useObjectStreams: false }));
}

async function ordinaryValuesWithScannerCapObjectPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const ordinarySignature = context.register(
        context.obj({
            FT: PDFName.of("Sig"),
            T: PDFString.of("OrdinaryApproval"),
            V: context.obj({
                Type: PDFName.of("Sig"),
                SubFilter: PDFName.of("adbe.pkcs7.detached"),
            }),
        })
    );
    const ordinaryText = context.register(
        context.obj({
            FT: PDFName.of("Tx"),
            T: PDFString.of("TextWithStructuredValue"),
            V: context.obj({ Type: PDFName.of("Example") }),
        })
    );
    document.catalog.set(
        PDFName.of("AcroForm"),
        context.obj({ Fields: context.obj([ordinarySignature, ordinaryText]) })
    );
    addScannerCapExceedingUnrelatedObject(document);
    return document.save({ useObjectStreams: false });
}

async function noFieldsWithScannerCapObjectPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: context.obj([]) }));
    addScannerCapExceedingUnrelatedObject(document);
    return document.save({ useObjectStreams: false });
}

type PrepassMalformedSignatureShape = "missing-value" | "non-dictionary-value" | "value-marker-xor";

async function prepassMalformedSignaturePdf(
    shape: PrepassMalformedSignatureShape
): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const field = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("PrepassMalformed"),
        ...(shape === "value-marker-xor"
            ? {
                  V: context.obj({ Type: PDFName.of("DocTimeStamp") }),
              }
            : {
                  Type: PDFName.of("DocTimeStamp"),
                  SubFilter: PDFName.of("ETSI.RFC3161"),
                  ...(shape === "non-dictionary-value" && {
                      V: PDFString.of("not-a-signature-dictionary"),
                  }),
              }),
    });
    document.catalog.set(
        PDFName.of("AcroForm"),
        context.obj({ Fields: context.obj([context.register(field)]) })
    );
    addScannerCapExceedingUnrelatedObject(document);
    return document.save({ useObjectStreams: false });
}

describe("archive malformed document-timestamp discovery", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.mocked(timestampPdf).mockImplementation(async (options: TimestampOptions) => ({
            pdf: options.pdf,
            timestamp: {
                genTime: new Date("2024-01-01T00:00:00Z"),
                policy: "1.2.3.4.5",
                serialNumber: "01",
                hashAlgorithm: "SHA-256",
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                messageDigest: "00",
                hasCertificate: true,
            },
        }));
    });

    it.each(malformedDocumentTimestampCases)(
        "keeps public extractTimestamps compatible by skipping $label",
        async ({ shape }: { shape: MalformedDocumentTimestampShape }) => {
            await expect(extractTimestamps(await malformedDocTimeStampPdf(shape))).resolves.toEqual([]);
        }
    );

    it.each(malformedDocumentTimestampCases)(
        "warns exactly once and collects no $label material by default",
        async ({ shape }: { shape: MalformedDocumentTimestampShape }) => {
            const pdf = await malformedDocTimeStampPdf(shape);

            const result = await archiveTimestamp({ pdf, tsa: { url: "https://tsa.example.test" } });

            expect(warnSpy).toHaveBeenCalledTimes(1);
            expect(warnSpy).toHaveBeenCalledWith(
                "Existing RFC 3161 document timestamp 'MalformedDocTimeStamp' is malformed and cannot be verified"
            );
            await expect(getDSSInfo(result.pdf)).resolves.toEqual({ certs: 0, crls: 0, ocsps: 0 });
        }
    );

    it.each(malformedDocumentTimestampCases)(
        "throws before timestamping for malformed $label in strict mode",
        async ({ shape }: { shape: MalformedDocumentTimestampShape }) => {
            const pdf = await malformedDocTimeStampPdf(shape);

            await expect(
                archiveTimestamp({
                    pdf,
                    tsa: { url: "https://tsa.example.test" },
                    strictExistingVerification: true,
                })
            ).rejects.toMatchObject({
                code: TimestampErrorCode.VERIFICATION_FAILED,
                message:
                    "Existing RFC 3161 document timestamp 'MalformedDocTimeStamp' is malformed and cannot be verified",
            } satisfies Partial<TimestampError>);
            expect(vi.mocked(timestampPdf)).not.toHaveBeenCalled();
        }
    );
});

describe("archive nested document-timestamp discovery", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.mocked(timestampPdf).mockImplementation(async (options: TimestampOptions) => ({
            pdf: options.pdf,
            timestamp: {
                genTime: new Date("2024-01-01T00:00:00Z"),
                policy: "1.2.3.4.5",
                serialNumber: "01",
                hashAlgorithm: "SHA-256",
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                messageDigest: "00",
                hasCertificate: true,
            },
        }));
    });

    it("reports a nested all-zero document timestamp by its fully qualified field name", async () => {
        const pdf = await nestedAllZeroDocumentTimestampPdf();

        await expect(extractTimestamps(pdf)).resolves.toEqual([]);
        await expect(discoverArchiveTimestamps(pdf)).resolves.toMatchObject({
            timestamps: [],
            malformedFieldNames: ["Parent.Timestamp"],
        });
    });

    it("warns for a nested malformed document timestamp by default", async () => {
        await archiveTimestamp({
            pdf: await nestedAllZeroDocumentTimestampPdf(),
            tsa: { url: "https://tsa.example.test" },
        });

        expect(warnSpy).toHaveBeenCalledWith(
            "Existing RFC 3161 document timestamp 'Parent.Timestamp' is malformed and cannot be verified"
        );
    });

    it("rejects a nested malformed document timestamp in strict mode", async () => {
        await expect(
            archiveTimestamp({
                pdf: await nestedAllZeroDocumentTimestampPdf(),
                tsa: { url: "https://tsa.example.test" },
                strictExistingVerification: true,
            })
        ).rejects.toMatchObject({
            code: TimestampErrorCode.VERIFICATION_FAILED,
            message:
                "Existing RFC 3161 document timestamp 'Parent.Timestamp' is malformed and cannot be verified",
        } satisfies Partial<TimestampError>);
        expect(vi.mocked(timestampPdf)).not.toHaveBeenCalled();
    });
});

describe("archive malformed AcroForm discovery", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.mocked(timestampPdf).mockImplementation(async (options: TimestampOptions) => ({
            pdf: options.pdf,
            timestamp: {
                genTime: new Date("2024-01-01T00:00:00Z"),
                policy: "1.2.3.4.5",
                serialNumber: "01",
                hashAlgorithm: "SHA-256",
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                messageDigest: "00",
                hasCertificate: true,
            },
        }));
    });

    it("warns for a cyclic AcroForm field graph instead of silently ignoring it", async () => {
        const pdf = await cyclicAcroFormTimestampPdf();

        await expect(extractTimestamps(pdf)).resolves.toEqual([]);
        await expect(discoverArchiveTimestamps(pdf)).resolves.toMatchObject({
            timestamps: [],
            malformedFieldNames: ["Cyclic"],
        });

        await archiveTimestamp({ pdf, tsa: { url: "https://tsa.example.test" } });
        expect(warnSpy).toHaveBeenCalledWith(
            "Existing RFC 3161 document timestamp 'Cyclic' is malformed and cannot be verified"
        );
    });

    it("rejects a cyclic AcroForm field graph in strict archive mode", async () => {
        await expect(
            archiveTimestamp({
                pdf: await cyclicAcroFormTimestampPdf(),
                tsa: { url: "https://tsa.example.test" },
                strictExistingVerification: true,
            })
        ).rejects.toMatchObject({
            code: TimestampErrorCode.VERIFICATION_FAILED,
            message:
                "Existing RFC 3161 document timestamp 'Cyclic' is malformed and cannot be verified",
        } satisfies Partial<TimestampError>);
        expect(vi.mocked(timestampPdf)).not.toHaveBeenCalled();
    });

    it("keeps a valid timestamp when an unrelated text-field branch is malformed", async () => {
        const pdf = await validTimestampWithMalformedTextSiblingPdf();

        await expect(extractTimestamps(pdf)).resolves.toMatchObject([
            { fieldName: "ValidTimestamp" },
        ]);
        await expect(discoverArchiveTimestamps(pdf)).resolves.toMatchObject({
            timestamps: [expect.objectContaining({ fieldName: "ValidTimestamp" })],
            malformedFieldNames: ["BrokenText"],
        });
    });
});

describe("archive resolved signature-value document-timestamp markers", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.mocked(timestampPdf).mockImplementation(async (options: TimestampOptions) => ({
            pdf: options.pdf,
            timestamp: {
                genTime: new Date("2024-01-01T00:00:00Z"),
                policy: "1.2.3.4.5",
                serialNumber: "01",
                hashAlgorithm: "SHA-256",
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                messageDigest: "00",
                hasCertificate: true,
            },
        }));
    });

    it.each(resolvedValueMarkerCases)(
        "classifies $label from the resolved signature value while preserving public extraction",
        async (markerCase: ResolvedValueMarkerCase) => {
            const pdf = await resolvedValueMarkerPdf(markerCase);
            const discovery = await discoverArchiveTimestamps(pdf);

            expect(discovery.timestamps).toHaveLength(markerCase.archiveCount);
            expect(discovery.malformedFieldNames).toEqual(
                markerCase.archiveMalformed ? ["ResolvedValueMarkers"] : []
            );
            await expect(extractTimestamps(pdf)).resolves.toHaveLength(markerCase.publicCount);
        }
    );

    it.each(resolvedValueMarkerCases.filter((markerCase) => markerCase.archiveMalformed))(
        "warns once without collecting $label by default",
        async (markerCase: ResolvedValueMarkerCase) => {
            const result = await archiveTimestamp({
                pdf: await resolvedValueMarkerPdf(markerCase),
                tsa: { url: "https://tsa.example.test" },
            });

            expect(warnSpy).toHaveBeenCalledTimes(1);
            await expect(getDSSInfo(result.pdf)).resolves.toEqual({ certs: 0, crls: 0, ocsps: 0 });
        }
    );

    it.each(resolvedValueMarkerCases.filter((markerCase) => markerCase.archiveMalformed))(
        "throws before timestamping for malformed $label in strict mode",
        async (markerCase: ResolvedValueMarkerCase) => {
            await expect(
                archiveTimestamp({
                    pdf: await resolvedValueMarkerPdf(markerCase),
                    tsa: { url: "https://tsa.example.test" },
                    strictExistingVerification: true,
                })
            ).rejects.toMatchObject({ code: TimestampErrorCode.VERIFICATION_FAILED });
            expect(vi.mocked(timestampPdf)).not.toHaveBeenCalled();
        }
    );

    it("keeps a direct SubFilter-only legacy timestamp public but blocks strict archive mutation", async () => {
        const pdf = await directSubFilterOnlyTimestampPdf();

        await expect(extractTimestamps(pdf)).resolves.toMatchObject([
            { fieldName: "DirectLegacyTimestamp" },
        ]);
        await expect(discoverArchiveTimestamps(pdf)).resolves.toMatchObject({
            timestamps: [],
            malformedFieldNames: ["DirectLegacyTimestamp"],
        });
        await expect(
            archiveTimestamp({
                pdf,
                tsa: { url: "https://tsa.example.test" },
                strictExistingVerification: true,
            })
        ).rejects.toMatchObject({
            code: TimestampErrorCode.VERIFICATION_FAILED,
            message:
                "Existing RFC 3161 document timestamp 'DirectLegacyTimestamp' is malformed and cannot be verified",
        } satisfies Partial<TimestampError>);
        expect(vi.mocked(timestampPdf)).not.toHaveBeenCalled();
    });
});

describe("timestamp discovery prefiltering", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.mocked(timestampPdf).mockImplementation(async (options: TimestampOptions) => ({
            pdf: options.pdf,
            timestamp: {
                genTime: new Date("2024-01-01T00:00:00Z"),
                policy: "1.2.3.4.5",
                serialNumber: "01",
                hashAlgorithm: "SHA-256",
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                messageDigest: "00",
                hasCertificate: true,
            },
        }));
    });

    it("keeps a timestamp whose FT and V are inherited through a widget parent", async () => {
        const pdf = await inheritedFtAndValueTimestampPdf();

        await expect(extractTimestamps(pdf)).resolves.toMatchObject([
            { fieldName: "InheritedTimestamp" },
        ]);
        await expect(discoverArchiveTimestamps(pdf)).resolves.toMatchObject({
            timestamps: [expect.objectContaining({ fieldName: "InheritedTimestamp" })],
            malformedFieldNames: [],
        });
    });

    it.each([
        "missing-value",
        "non-dictionary-value",
        "value-marker-xor",
    ] as const)(
        "reports %s before scanning unrelated physical objects",
        async (shape: PrepassMalformedSignatureShape) => {
            const pdf = await prepassMalformedSignaturePdf(shape);

            await expect(extractTimestamps(pdf)).resolves.toEqual([]);
            await expect(discoverArchiveTimestamps(pdf)).resolves.toEqual({
                timestamps: [],
                malformedFieldNames: ["PrepassMalformed"],
            });
            await expect(
                archiveTimestamp({
                    pdf,
                    tsa: { url: "https://tsa.example.test" },
                    strictExistingVerification: true,
                })
            ).rejects.toMatchObject({
                code: TimestampErrorCode.VERIFICATION_FAILED,
                message:
                    "Existing RFC 3161 document timestamp 'PrepassMalformed' is malformed and cannot be verified",
            } satisfies Partial<TimestampError>);
            expect(vi.mocked(timestampPdf)).not.toHaveBeenCalled();
        }
    );

    it("does not scan ordinary form values when no RFC 3161 descriptor exists", async () => {
        const pdf = await ordinaryValuesWithScannerCapObjectPdf();

        await expect(extractTimestamps(pdf)).resolves.toEqual([]);
        await expect(discoverArchiveTimestamps(pdf)).resolves.toEqual({
            timestamps: [],
            malformedFieldNames: [],
        });
        await expect(
            archiveTimestamp({
                pdf,
                tsa: { url: "https://tsa.example.test" },
                strictExistingVerification: true,
            })
        ).resolves.toMatchObject({ pdf: expect.any(Uint8Array) });
        expect(timestampPdf).toHaveBeenCalledTimes(1);
        expect(warnSpy).not.toHaveBeenCalled();
    });

    it("returns before indexing an AcroForm with no fields", async () => {
        const pdf = await noFieldsWithScannerCapObjectPdf();

        await expect(extractTimestamps(pdf)).resolves.toEqual([]);
        await expect(discoverArchiveTimestamps(pdf)).resolves.toEqual({
            timestamps: [],
            malformedFieldNames: [],
        });
    });
});
