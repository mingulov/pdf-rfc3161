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
    { label: "invalid token", shape: "invalid-token" },
    { label: "missing Contents", shape: "missing-contents" },
    { label: "non-hex Contents", shape: "non-hex-contents" },
    { label: "missing ByteRange", shape: "missing-byte-range" },
    { label: "wrong ByteRange", shape: "wrong-byte-range" },
    { label: "short ByteRange", shape: "short-byte-range" },
    { label: "missing V dictionary", shape: "missing-value" },
    { label: "wrong V dictionary", shape: "wrong-value" },
];

let validTimestampContentsPromise: Promise<string> | undefined;

function validTimestampContents(): Promise<string> {
    validTimestampContentsPromise ??= createRFC3161TokenFixture().then((fixture) =>
        Array.from(fixture.rawToken, (byte) => byte.toString(16).padStart(2, "0")).join("")
    );
    return validTimestampContentsPromise;
}

async function malformedDocTimeStampPdf(shape: MalformedDocumentTimestampShape): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = PDFDict.withContext(context);
    signature.set(PDFName.of("Type"), PDFName.of("DocTimeStamp"));
    signature.set(PDFName.of("SubFilter"), PDFName.of("ETSI.RFC3161"));
    if (shape === "invalid-token") signature.set(PDFName.of("Contents"), PDFHexString.of("3001"));
    if (shape === "non-hex-contents") {
        signature.set(PDFName.of("Contents"), PDFString.of("not-a-hex-string"));
    }
    if (shape !== "missing-contents" && shape !== "invalid-token" && shape !== "non-hex-contents") {
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
    signature.set(PDFName.of("ByteRange"), context.obj([0, 0, 0, 0]));
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
});
