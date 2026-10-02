/**
 * Tests for RFC 5544 TimeStampedData support
 */

import { describe, it, expect } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
    createTimeStampedData,
    parseTimeStampedData,
    extractDataFromEnvelope,
    extractTimestampsFromEnvelope,
    verifyTimeStampedDataEnvelope,
    addTimestampsToEnvelope,
} from "../../../core/src/rfcs/rfc5544.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";

// Mock timestamp token for testing
function createMockTimestampToken(): Uint8Array {
    // Create a minimal valid ContentInfo structure for testing
    // This is simplified - in real usage, this would be a proper RFC 3161 token
    const mockData = new Uint8Array([
        0x30,
        0x0f, // SEQUENCE
        0x06,
        0x0b,
        0x2a,
        0x86,
        0x48,
        0x86,
        0xf7,
        0x0d,
        0x01,
        0x07,
        0x02, // contentType OID (signedData)
        0xa0,
        0x00, // content [0] (empty for mock)
    ]);
    return mockData;
}

describe("RFC 5544 TimeStampedData", () => {
    const mockToken = createMockTimestampToken();
    const testData = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    const testDataUri = "http://example.com/document.pdf";

    describe("createTimeStampedData", () => {
        it("should create a TimeStampedData envelope with data", () => {
            const envelope = createTimeStampedData(mockToken, {
                data: testData,
                fileName: "test.pdf",
                mediaType: "application/pdf",
            });

            expect(envelope).toBeInstanceOf(Uint8Array);
            expect(envelope.length).toBeGreaterThan(0);
        });

        it("should create a TimeStampedData envelope with dataUri", () => {
            const envelope = createTimeStampedData(mockToken, {
                dataUri: testDataUri,
                fileName: "test.pdf",
            });

            expect(envelope).toBeInstanceOf(Uint8Array);
            expect(envelope.length).toBeGreaterThan(0);
        });

        it("should create a TimeStampedData envelope with metadata", () => {
            const envelope = createTimeStampedData(mockToken, {
                data: testData,
                fileName: "test.pdf",
                mediaType: "application/pdf",
                otherMetaData: {
                    "1.2.3.4": ["custom", "metadata"],
                },
            });

            expect(envelope).toBeInstanceOf(Uint8Array);
        });
    });

    describe("parseTimeStampedData", () => {
        it("should parse a TimeStampedData envelope with data", () => {
            const envelope = createTimeStampedData(mockToken, {
                data: testData,
                fileName: "test.pdf",
                mediaType: "application/pdf",
            });

            const parsed = parseTimeStampedData(envelope);

            expect(parsed.version).toBe(1);
            expect(parsed.data).toEqual(testData);
            expect(parsed.metaData?.fileName).toBe("test.pdf");
            expect(parsed.metaData?.mediaType).toBe("application/pdf");
            expect(parsed.timestampTokens).toHaveLength(1);
        });

        it("should parse a TimeStampedData envelope with dataUri", () => {
            const envelope = createTimeStampedData(mockToken, {
                dataUri: testDataUri,
                fileName: "test.pdf",
            });

            const parsed = parseTimeStampedData(envelope);

            expect(parsed.version).toBe(1);
            expect(parsed.dataUri).toBe(testDataUri);
            expect(parsed.data).toBeUndefined();
            expect(parsed.metaData?.fileName).toBe("test.pdf");
            expect(parsed.timestampTokens).toHaveLength(1);
        });

        it("should parse a TimeStampedData envelope with custom metadata", () => {
            const envelope = createTimeStampedData(mockToken, {
                data: testData,
                otherMetaData: {
                    "1.2.3.4": ["custom", "metadata"],
                },
            });

            const parsed = parseTimeStampedData(envelope);

            expect(parsed.metaData?.otherMetaData?.["1.2.3.4"]).toEqual(["custom", "metadata"]);
        });

        it("should throw TimestampError when parsing an invalid envelope", () => {
            const invalidEnvelope = new Uint8Array([0x00, 0x01, 0x02, 0x03]);

            expect(() => parseTimeStampedData(invalidEnvelope)).toThrow(TimestampError);
            try {
                parseTimeStampedData(invalidEnvelope);
            } catch (error) {
                expect(error).toBeInstanceOf(TimestampError);
                expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
                expect((error as TimestampError).message).toContain(
                    "Failed to parse TimeStampedData"
                );
            }
        });
    });

    describe("extractDataFromEnvelope", () => {
        it("should extract embedded data", () => {
            const envelope = createTimeStampedData(mockToken, {
                data: testData,
            });

            const extracted = extractDataFromEnvelope(envelope);
            expect(extracted).toEqual(testData);
        });

        it("should return null when no data is embedded", () => {
            const envelope = createTimeStampedData(mockToken, {
                dataUri: testDataUri,
                // No data field - should return null
            });

            const extracted = extractDataFromEnvelope(envelope);
            expect(extracted).toBeNull();
        });
    });

    describe("extractTimestampsFromEnvelope", () => {
        it("should extract timestamp tokens", () => {
            const envelope = createTimeStampedData(mockToken, {
                data: testData,
            });

            const tokens = extractTimestampsFromEnvelope(envelope);
            expect(tokens).toHaveLength(1);
            expect(tokens[0]).toEqual(mockToken);
        });
    });

    describe("verifyTimeStampedDataEnvelope", () => {
        it("should verify valid envelopes", () => {
            const envelope = createTimeStampedData(mockToken, {
                data: testData,
            });

            const isValid = verifyTimeStampedDataEnvelope(envelope);
            expect(isValid).toBe(true);
        });

        it("should reject invalid envelopes", () => {
            const invalidEnvelope = new Uint8Array([0x00, 0x01, 0x02]);
            const isValid = verifyTimeStampedDataEnvelope(invalidEnvelope);
            expect(isValid).toBe(false);
        });
    });

    describe("addTimestampsToEnvelope", () => {
        it("should add additional timestamps to envelope", () => {
            const envelope = createTimeStampedData(mockToken, {
                data: testData,
            });

            const additionalToken = createMockTimestampToken();
            const updatedEnvelope = addTimestampsToEnvelope(envelope, [additionalToken]);

            const parsed = parseTimeStampedData(updatedEnvelope);
            expect(parsed.timestampTokens).toHaveLength(2);
            expect(parsed.data).toEqual(testData);
        });
    });

    describe("TimeStampedData OID", () => {
        it("should use the correct RFC 5544 OID", () => {
            // The OID 1.2.840.113549.1.9.16.1.31 should be present in the envelope
            const envelope = createTimeStampedData(mockToken, {
                data: testData,
            });

            // Check that the OID bytes are present in the envelope
            const oidBytes = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x1f];

            for (const byte of oidBytes) {
                expect(envelope).toContain(byte);
            }
        });
    });

    // Audit D: regression-protect the Task 4.9 disambiguator fix in
    // `parseTimeStampedData`. RFC 5544 lets `metaData` and `temporalEvidence`
    // both appear as Sequence-typed children at the same nesting level; the
    // parser distinguishes by checking the FIRST CHILD of the candidate
    // Sequence -- metaData starts with a Boolean (hashProtected) while
    // temporalEvidence starts with a context-specific tag for the CHOICE
    // between tstEvidence and ersEvidence. Before the fix the parser would
    // treat the temporalEvidence Sequence as a malformed metaData.
    // T11 (R9): hostile-schema inputs must reject deterministically --
    // stable INVALID_RESPONSE code and message (never engine-specific
    // TypeError text), with the original failure retained as `cause`.
    // A non-INTEGER version must reject instead of parsing as undefined.
    // Malformed otherMetaData attributes follow the established skip
    // policy instead of crashing or coercing to null.
    describe("deterministic schema rejection (T11/R9)", () => {
        const TSD_OID = "1.2.840.113549.1.9.16.1.31";
        const STABLE_MESSAGE = "Failed to parse TimeStampedData envelope";

        function temporalEvidence(): asn1js.Sequence {
            return new asn1js.Sequence({
                value: [
                    new asn1js.Constructed({
                        idBlock: { tagClass: 3, tagNumber: 0 },
                        value: [new asn1js.Sequence({ value: [] })],
                    }),
                ],
            });
        }

        function envelopeWithInner(inner: asn1js.AsnType): Uint8Array {
            const contentInfo = new pkijs.ContentInfo({
                contentType: TSD_OID,
                content: new asn1js.OctetString({ valueHex: inner.toBER(false) }),
            });
            return new Uint8Array(contentInfo.toSchema().toBER(false));
        }

        function expectStableRejection(envelope: Uint8Array): TimestampError {
            let thrown: unknown;
            try {
                parseTimeStampedData(envelope);
            } catch (error) {
                thrown = error;
            }
            expect(thrown).toBeInstanceOf(TimestampError);
            const timestampError = thrown as TimestampError;
            expect(timestampError.code).toBe(TimestampErrorCode.INVALID_RESPONSE);
            expect(timestampError.message).toBe(STABLE_MESSAGE);
            return timestampError;
        }

        it("rejects a non-SEQUENCE TimeStampedData with the stable message", () => {
            expectStableRejection(envelopeWithInner(new asn1js.Integer({ value: 1 })));
        });

        it("rejects an empty TimeStampedData SEQUENCE with the stable message", () => {
            expectStableRejection(envelopeWithInner(new asn1js.Sequence({ value: [] })));
        });

        it("rejects a non-INTEGER version instead of parsing it as undefined", () => {
            const envelope = envelopeWithInner(
                new asn1js.Sequence({
                    value: [new asn1js.Utf8String({ value: "x" }), temporalEvidence()],
                })
            );
            let thrown: unknown;
            try {
                parseTimeStampedData(envelope);
            } catch (error) {
                thrown = error;
            }
            expect(thrown).toBeInstanceOf(TimestampError);
            expect((thrown as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
            expect((thrown as TimestampError).message).toBe(
                "TimeStampedData version must be an INTEGER"
            );
        });

        it("rejects an ENUMERATED version even when its value is 1 (T11 fix round 1)", () => {
            // ENUMERATED decodes to a numeric valueDec, so a value-only
            // guard accepts it; the parser must require the INTEGER tag.
            // (instanceof asn1js.Integer alone is insufficient because
            // asn1js Enumerated extends Integer.)
            const envelope = envelopeWithInner(
                new asn1js.Sequence({
                    value: [new asn1js.Enumerated({ value: 1 }), temporalEvidence()],
                })
            );
            let thrown: unknown;
            try {
                parseTimeStampedData(envelope);
            } catch (error) {
                thrown = error;
            }
            expect(thrown).toBeInstanceOf(TimestampError);
            expect((thrown as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
            expect((thrown as TimestampError).message).toBe(
                "TimeStampedData version must be an INTEGER"
            );
        });

        it("rejects an ENUMERATED version with a non-1 value via the tag check (T11 fix round 1)", () => {
            // Variant: numeric valueDec (2) would also pass a value-only
            // guard, so rejection proves the tag check fires rather than
            // any value comparison.
            const envelope = envelopeWithInner(
                new asn1js.Sequence({
                    value: [new asn1js.Enumerated({ value: 2 }), temporalEvidence()],
                })
            );
            let thrown: unknown;
            try {
                parseTimeStampedData(envelope);
            } catch (error) {
                thrown = error;
            }
            expect(thrown).toBeInstanceOf(TimestampError);
            expect((thrown as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
            expect((thrown as TimestampError).message).toBe(
                "TimeStampedData version must be an INTEGER"
            );
        });

        it("rejects a missing temporalEvidence with the stable message", () => {
            expectStableRejection(
                envelopeWithInner(new asn1js.Sequence({ value: [new asn1js.Integer({ value: 1 })] }))
            );
        });

        it("rejects a non-SEQUENCE temporalEvidence with the stable message", () => {
            expectStableRejection(
                envelopeWithInner(
                    new asn1js.Sequence({
                        value: [new asn1js.Integer({ value: 1 }), new asn1js.Integer({ value: 2 })],
                    })
                )
            );
        });

        it("rejects a missing ContentInfo content with the stable message", () => {
            const raw = new asn1js.Sequence({
                value: [new asn1js.ObjectIdentifier({ value: TSD_OID })],
            });
            expectStableRejection(new Uint8Array(raw.toBER(false)));
        });

        it("retains the original failure as cause on schema crashes", () => {
            const timestampError = expectStableRejection(
                envelopeWithInner(new asn1js.Integer({ value: 1 }))
            );
            expect(timestampError.cause).toBeInstanceOf(Error);
        });

        it("skips malformed otherMetaData attributes instead of crashing", () => {
            const envelope = envelopeWithInner(
                new asn1js.Sequence({
                    value: [
                        new asn1js.Integer({ value: 1 }),
                        new asn1js.Sequence({
                            value: [
                                new asn1js.Boolean({ value: true }),
                                new asn1js.Sequence({
                                    value: [
                                        new asn1js.Sequence({
                                            value: [
                                                new asn1js.ObjectIdentifier({ value: "1.2.3.4" }),
                                                new asn1js.Integer({ value: 9 }),
                                            ],
                                        }),
                                    ],
                                }),
                            ],
                        }),
                        temporalEvidence(),
                    ],
                })
            );
            const parsed = parseTimeStampedData(envelope);
            expect(parsed.version).toBe(1);
            expect(parsed.metaData?.otherMetaData ?? {}).toEqual({});
        });

        it("skips non-Utf8String otherMetaData values instead of coercing to null", () => {
            const envelope = envelopeWithInner(
                new asn1js.Sequence({
                    value: [
                        new asn1js.Integer({ value: 1 }),
                        new asn1js.Sequence({
                            value: [
                                new asn1js.Boolean({ value: true }),
                                new asn1js.Sequence({
                                    value: [
                                        new asn1js.Sequence({
                                            value: [
                                                new asn1js.ObjectIdentifier({ value: "1.2.3.4" }),
                                                new asn1js.Set({
                                                    value: [new asn1js.Integer({ value: 9 })],
                                                }),
                                            ],
                                        }),
                                    ],
                                }),
                            ],
                        }),
                        temporalEvidence(),
                    ],
                })
            );
            const parsed = parseTimeStampedData(envelope);
            expect(parsed.metaData?.otherMetaData ?? {}).toEqual({});
        });
    });

    describe("metaData/temporalEvidence disambiguator (audit D)", () => {
        it("envelope without metaData parses temporalEvidence cleanly (dataUri-only)", () => {
            // Reproduces the Task 4.9 regression: only dataUri set, no
            // metaData, no embedded data. Before the fix, the parser
            // mis-identified the temporalEvidence Sequence as a malformed
            // metaData and threw "Cannot read properties of undefined
            // (reading 'valueBlock')".
            const envelope = createTimeStampedData(mockToken, {
                dataUri: testDataUri,
            });

            const parsed = parseTimeStampedData(envelope);

            expect(parsed.version).toBe(1);
            expect(parsed.dataUri).toBe(testDataUri);
            expect(parsed.metaData).toBeUndefined();
            expect(parsed.timestampTokens).toHaveLength(1);
        });

        it("envelope with metaData AND temporalEvidence parses both correctly", () => {
            // metaData is present (because fileName -> hashProtected
            // Boolean as first child). temporalEvidence follows. The
            // disambiguator must direct each Sequence to the right parser.
            const envelope = createTimeStampedData(mockToken, {
                data: testData,
                fileName: "test.pdf",
                mediaType: "application/pdf",
            });

            const parsed = parseTimeStampedData(envelope);

            expect(parsed.version).toBe(1);
            expect(parsed.metaData).toBeDefined();
            expect(parsed.metaData?.fileName).toBe("test.pdf");
            expect(parsed.metaData?.mediaType).toBe("application/pdf");
            expect(parsed.timestampTokens).toHaveLength(1);
            expect(parsed.data).toEqual(testData);
        });

        it("envelope with metaData only (no data, no dataUri) still parses", () => {
            // Edge case: metaData present, no data, no dataUri. The
            // disambiguator must correctly route the Sequence to metaData
            // even when the next Sequence (temporalEvidence) follows
            // immediately.
            const envelope = createTimeStampedData(mockToken, {
                fileName: "marker.txt",
            });

            const parsed = parseTimeStampedData(envelope);

            expect(parsed.metaData).toBeDefined();
            expect(parsed.metaData?.fileName).toBe("marker.txt");
            expect(parsed.data).toBeUndefined();
            expect(parsed.dataUri).toBeUndefined();
            expect(parsed.timestampTokens).toHaveLength(1);
        });
    });
});
