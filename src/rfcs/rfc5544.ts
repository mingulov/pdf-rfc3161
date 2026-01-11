/**
 * RFC 5544 - Syntax for Binding Documents with Time-Stamps
 *
 * This module implements TimeStampedData - a CMS content type that binds
 * arbitrary data to RFC 3161 timestamps without modifying the original file.
 *
 * Use cases:
 * - Archival systems
 * - Evidence preservation
 * - Detached timestamping
 * - Legal document timestamping
 */

import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { TimestampError, TimestampErrorCode } from "../types.js";

// RFC 5544 OID: id-ct-timestampedData
const TIMESTAMPED_DATA_OID = "1.2.840.113549.1.9.16.1.31";

/**
 * Options for creating TimeStampedData
 */
export interface TimeStampedDataOptions {
    /** Original data to timestamp (optional - if not provided, only hash is stored) */
    data?: Uint8Array;
    /** Data URI for detached timestamping */
    dataUri?: string;
    /** File name metadata */
    fileName?: string;
    /** MIME type metadata */
    mediaType?: string;
    /** Additional custom metadata */
    otherMetaData?: Record<string, string[]>;
    /** Whether the data hash is protected (default: true) */
    hashProtected?: boolean;
}

/**
 * Parsed TimeStampedData structure
 */
export interface ParsedTimeStampedData {
    /** Version (currently 1) */
    version: number;
    /** Original data if embedded */
    data?: Uint8Array;
    /** Data URI if specified */
    dataUri?: string;
    /** Metadata */
    metaData?: {
        hashProtected: boolean;
        fileName?: string;
        mediaType?: string;
        otherMetaData?: Record<string, string[]>;
    };
    /** Timestamp tokens */
    timestampTokens: Uint8Array[];
}

/**
 * Creates a TimeStampedData envelope containing data bound to timestamps.
 *
 * @param timestampTokens - DER-encoded RFC 3161 timestamp token(s)
 * @param options - Additional options for the envelope
 * @returns DER-encoded TimeStampedData CMS content
 */
export function createTimeStampedData(
    timestampTokens: Uint8Array | Uint8Array[],
    options: TimeStampedDataOptions = {}
): Uint8Array {
    const tokens = Array.isArray(timestampTokens) ? timestampTokens : [timestampTokens];
    // Create TimeStampedData structure
    const timeStampedDataItems: asn1js.AsnType[] = [
        // version INTEGER { v1(1) }
        new asn1js.Integer({ value: 1 }),
    ];

    // dataUri IA5String OPTIONAL
    if (options.dataUri) {
        timeStampedDataItems.push(new asn1js.IA5String({ value: options.dataUri }));
    }

    // metaData MetaData OPTIONAL
    const metaData = createMetaData(options);
    if (metaData) {
        timeStampedDataItems.push(metaData);
    }

    // content OCTET STRING OPTIONAL
    if (options.data) {
        timeStampedDataItems.push(new asn1js.OctetString({ valueHex: options.data }));
    }

    // temporalEvidence Evidence
    timeStampedDataItems.push(createTemporalEvidence(tokens));

    const timeStampedData = new asn1js.Sequence({
        value: timeStampedDataItems,
    });

    // Wrap in CMS ContentInfo
    const contentInfo = new pkijs.ContentInfo({
        contentType: TIMESTAMPED_DATA_OID,
        content: new asn1js.OctetString({ valueHex: timeStampedData.toBER(false) }),
    });

    return new Uint8Array(contentInfo.toSchema().toBER(false));
}

/**
 * Adds additional timestamp(s) to an existing TimeStampedData envelope.
 *
 * @param envelope - Existing TimeStampedData envelope
 * @param newTokens - Additional timestamp tokens to add
 * @returns Updated TimeStampedData envelope
 */
export function addTimestampsToEnvelope(envelope: Uint8Array, newTokens: Uint8Array[]): Uint8Array {
    const parsed = parseTimeStampedData(envelope);
    const allTokens = [...parsed.timestampTokens, ...newTokens];

    // Reconstruct with additional tokens
    const options: TimeStampedDataOptions = {
        data: parsed.data,
        dataUri: parsed.dataUri,
        fileName: parsed.metaData?.fileName,
        mediaType: parsed.metaData?.mediaType,
        otherMetaData: parsed.metaData?.otherMetaData,
        hashProtected: parsed.metaData?.hashProtected,
    };

    if (parsed.data) {
        options.data = parsed.data;
    }
    return createTimeStampedData(allTokens, options);
}

/**
 * Parses a TimeStampedData envelope and extracts its contents.
 *
 * @param envelope - DER-encoded TimeStampedData CMS content
 * @returns Parsed TimeStampedData structure
 */
export function parseTimeStampedData(envelope: Uint8Array): ParsedTimeStampedData {
    try {
        // Parse CMS ContentInfo
        const asn1 = asn1js.fromBER(envelope.slice().buffer);
        if (asn1.offset === -1) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Failed to parse TimeStampedData envelope"
            );
        }

        const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });

        // Verify content type
        if (contentInfo.contentType !== TIMESTAMPED_DATA_OID) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                `Invalid content type: expected ${TIMESTAMPED_DATA_OID}, got ${contentInfo.contentType}`
            );
        }

        // Parse TimeStampedData
        const timeStampedDataAsn1 = asn1js.fromBER(
            (contentInfo.content as asn1js.OctetString).valueBlock.valueHexView
        );

        if (timeStampedDataAsn1.offset === -1) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Failed to parse TimeStampedData content"
            );
        }

        const timeStampedDataSeq = timeStampedDataAsn1.result as asn1js.Sequence;
        const values = timeStampedDataSeq.valueBlock.value;

        let index = 0;

        // Parse version
        const version = (values[index++] as asn1js.Integer).valueBlock.valueDec;

        // Parse dataUri (optional)
        let dataUri: string | undefined;
        if (values[index] instanceof asn1js.IA5String) {
            dataUri = (values[index++] as asn1js.IA5String).valueBlock.value;
        }

        // Parse metaData (optional)
        let metaData: ParsedTimeStampedData["metaData"];
        if (values[index] instanceof asn1js.Sequence) {
            metaData = parseMetaData(values[index++] as asn1js.Sequence);
        }

        // Parse content (optional) or temporalEvidence
        let data: Uint8Array | undefined;
        let temporalEvidence: asn1js.Sequence;

        if (values[index] instanceof asn1js.OctetString) {
            data = new Uint8Array((values[index++] as asn1js.OctetString).valueBlock.valueHexView);
            temporalEvidence = values[index] as asn1js.Sequence;
        } else {
            // No content field, temporalEvidence is next
            temporalEvidence = values[index] as asn1js.Sequence;
        }

        const timestampTokens = parseTemporalEvidence(temporalEvidence);

        return {
            version,
            dataUri,
            metaData,
            data,
            timestampTokens,
        };
    } catch (error) {
        if (error instanceof TimestampError) {
            throw error;
        }
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            `Failed to parse TimeStampedData: ${error instanceof Error ? error.message : String(error)}`
        );
    }
}

/**
 * Extracts original data from a TimeStampedData envelope.
 *
 * @param envelope - TimeStampedData envelope
 * @returns Original data if embedded, null otherwise
 */
export function extractDataFromEnvelope(envelope: Uint8Array): Uint8Array | null {
    const parsed = parseTimeStampedData(envelope);
    return parsed.data ?? null;
}

/**
 * Extracts timestamp tokens from a TimeStampedData envelope.
 *
 * @param envelope - TimeStampedData envelope
 * @returns Array of DER-encoded timestamp tokens
 */
export function extractTimestampsFromEnvelope(envelope: Uint8Array): Uint8Array[] {
    const parsed = parseTimeStampedData(envelope);
    return parsed.timestampTokens;
}

/**
 * Verifies that a TimeStampedData envelope is properly structured.
 *
 * @param envelope - TimeStampedData envelope to verify
 * @returns True if envelope is valid
 */
export function verifyTimeStampedDataEnvelope(envelope: Uint8Array): boolean {
    try {
        const parsed = parseTimeStampedData(envelope);
        return parsed.version === 1 && parsed.timestampTokens.length > 0;
    } catch {
        return false;
    }
}

// Helper functions

function createMetaData(options: TimeStampedDataOptions): asn1js.Sequence | undefined {
    if (!options.fileName && !options.mediaType && !options.otherMetaData) {
        return undefined;
    }

    const metaDataItems: asn1js.AsnType[] = [
        // hashProtected BOOLEAN
        new asn1js.Boolean({ value: options.hashProtected ?? true }),
    ];

    // fileName Utf8String OPTIONAL
    if (options.fileName) {
        metaDataItems.push(new asn1js.Utf8String({ value: options.fileName }));
    }

    // mediaType IA5String OPTIONAL
    if (options.mediaType) {
        metaDataItems.push(new asn1js.IA5String({ value: options.mediaType }));
    }

    // otherMetaData Attributes OPTIONAL
    if (options.otherMetaData) {
        const attributes: asn1js.Sequence[] = [];
        for (const [key, values] of Object.entries(options.otherMetaData)) {
            const attrValues = values.map((value: string) => new asn1js.Utf8String({ value }));
            attributes.push(
                new asn1js.Sequence({
                    value: [
                        new asn1js.ObjectIdentifier({ value: key }),
                        new asn1js.Set({ value: attrValues }),
                    ],
                })
            );
        }
        metaDataItems.push(new asn1js.Sequence({ value: attributes }));
    }

    return new asn1js.Sequence({ value: metaDataItems });
}

function createTemporalEvidence(tokens: Uint8Array[]): asn1js.Sequence {
    // For simplicity, we'll implement basic TimeStampTokenEvidence
    // Full RFC 5544 support would include ERS evidence as well
    const timeStampAndCRLs: asn1js.Sequence[] = tokens.map(
        (token) =>
            new asn1js.Sequence({
                value: [
                    new asn1js.OctetString({ valueHex: token }),
                    // CRL is optional, omit for now
                ],
            })
    );

    return new asn1js.Sequence({
        value: [
            // CHOICE: tstEvidence [0] TimeStampTokenEvidence
            new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 0 }, // context-specific [0]
                value: [new asn1js.Sequence({ value: timeStampAndCRLs })],
            }),
        ],
    });
}

function parseMetaData(metaDataSeq: asn1js.Sequence): ParsedTimeStampedData["metaData"] {
    const values = metaDataSeq.valueBlock.value;
    let index = 0;

    const hashProtected = (values[index++] as asn1js.Boolean).valueBlock.value;

    let fileName: string | undefined;
    if (values[index] instanceof asn1js.Utf8String) {
        fileName = (values[index++] as asn1js.Utf8String).valueBlock.value;
    }

    let mediaType: string | undefined;
    if (values[index] instanceof asn1js.IA5String) {
        mediaType = (values[index++] as asn1js.IA5String).valueBlock.value;
    }

    let otherMetaData: Record<string, string[]> | undefined;
    if (values[index] instanceof asn1js.Sequence) {
        otherMetaData = {};
        const attributes = (values[index] as asn1js.Sequence).valueBlock.value;
        for (const attr of attributes) {
            if (attr instanceof asn1js.Sequence) {
                const attrValues = attr.valueBlock.value;
                if (attrValues.length >= 2) {
                    const oid = (attrValues[0] as asn1js.ObjectIdentifier).valueBlock.toString();
                    const values = (attrValues[1] as asn1js.Set).valueBlock.value;
                    otherMetaData[oid] = values.map(
                        (v: asn1js.AsnType) => (v as asn1js.Utf8String).valueBlock.value
                    );
                }
            }
        }
    }

    return {
        hashProtected,
        fileName,
        mediaType,
        otherMetaData,
    };
}

function parseTemporalEvidence(evidenceSeq: asn1js.Sequence): Uint8Array[] {
    const values = evidenceSeq.valueBlock.value;
    const tokens: Uint8Array[] = [];

    // Parse tstEvidence [0] TimeStampTokenEvidence
    if (values[0] instanceof asn1js.Constructed) {
        const tstEvidence = values[0];
        if (tstEvidence.valueBlock.value[0] instanceof asn1js.Sequence) {
            const timeStampTokenEvidence = tstEvidence.valueBlock.value[0];
            for (const item of timeStampTokenEvidence.valueBlock.value) {
                if (
                    item instanceof asn1js.Sequence &&
                    item.valueBlock.value[0] instanceof asn1js.OctetString
                ) {
                    const token = item.valueBlock.value[0];
                    tokens.push(new Uint8Array(token.valueBlock.valueHexView));
                }
            }
        }
    }

    return tokens;
}
