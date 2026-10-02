import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { getLogger } from "../utils/logger.js";
import { TimestampError, TimestampErrorCode } from "../types.js";
import { parseCanonicalDERValue, type DerDecodeBudget } from "./der-utils.js";
import {
    hasSplitDirectoryNameWrapper,
    isUndecidableGeneralNameWrapper,
    isWellFormedName,
} from "./name-grammar.js";

/**
 * Extracts CRL Distribution Points (URLs) from a certificate's extension.
 *
 * @param cert - The certificate to inspect
 * @returns Array of CRL URLs found
 */
export function getCRLDistributionPoints(cert: pkijs.Certificate): string[] {
    const urls: string[] = [];

    if (!cert.extensions) {
        return urls;
    }

    // OID for CRL Distribution Points is 2.5.29.31
    const crlExt = cert.extensions.find((ext) => ext.extnID === "2.5.29.31");

    if (!crlExt?.extnValue) {
        return urls;
    }

    // Parse the extension value
    let distributionPoints: pkijs.DistributionPoint[] = [];

    if (crlExt.parsedValue) {
        if (crlExt.parsedValue instanceof pkijs.CRLDistributionPoints) {
            distributionPoints = crlExt.parsedValue.distributionPoints;
        } else {
            const parsed = crlExt.parsedValue as unknown as {
                distributionPoints?: pkijs.DistributionPoint[];
            };
            if (Array.isArray(parsed.distributionPoints)) {
                distributionPoints = parsed.distributionPoints;
            }
        }
    } else {
        // Manually parse if not auto-parsed
        const asn1 = asn1js.fromBER(crlExt.extnValue.valueBlock.valueHexView);
        if (asn1.offset !== -1) {
            try {
                const crlPoints = new pkijs.CRLDistributionPoints({ schema: asn1.result });
                distributionPoints = crlPoints.distributionPoints;
            } catch (e) {
                // Failed to parse CRLDistributionPoints manually, ignore
                getLogger().warn("[LTV-Utils] Failed to parse CRLDistributionPoints manually:", e);
            }
        }
    }

    for (const dp of distributionPoints) {
        if (!dp.distributionPoint) {
            continue;
        }

        let generalNames: unknown[] = [];
        const distPoint = dp.distributionPoint as unknown;

        if (distPoint && typeof distPoint === "object") {
            const dpObj = distPoint as Record<string, unknown>;
            if (Array.isArray(dpObj.names)) {
                generalNames = dpObj.names;
            } else if (typeof dpObj.value === "string") {
                generalNames = [distPoint];
            } else if (dpObj["0"] && typeof dpObj["0"] === "object") {
                const choice = dpObj["0"];
                if (Array.isArray(choice)) {
                    generalNames = choice;
                } else {
                    const choiceObj = choice as Record<string, unknown>;
                    if (Array.isArray(choiceObj.names)) {
                        generalNames = choiceObj.names;
                    } else {
                        generalNames = [choice];
                    }
                }
            }
        }

        for (const name of generalNames) {
            if (!name) continue;

            // Use type assertion to access properties safely
            const n = name as unknown as { type: number; value: unknown };
            if (n.type === 6 && typeof n.value === "string") {
                urls.push(n.value);
            }
        }
    }

    return urls;
}

/** Maximum distribution points inspected on one certificate. */
const MAX_CDP_DISTRIBUTION_POINTS = 64;

/** Maximum GeneralNames walked in one distribution point or cRLIssuer field. */
const MAX_CDP_GENERAL_NAMES = 64;

/**
 * Structured CRL distribution-point metadata for one DistributionPoint
 * (RFC 5280 5.1.1.3). The URL collector above stays for collection
 * compatibility; strict CRL validation binds scope through this shape.
 */
export interface DistributionPointMetadata {
    /** URIs collected from fullName GeneralNames (type uniformResourceIdentifier). */
    urls: string[];
    /** True when the point uses nameRelativeToCRLIssuer (unsupported naming). */
    hasRelativeName: boolean;
    /**
     * Raw [1] IMPLICIT ReasonFlags content (unused-bits count octet
     * first) when the reasons field is present, else null. Grammar-
     * validated on read; the strict validator treats reasons as
     * verdict-neutral (a full CRL covers every reason flag).
     */
    reasons: Uint8Array | null;
    /** Encoded-name hex of the directoryName cRLIssuer entries. */
    crlIssuerDirectoryNames: string[];
    /**
     * Retained for API compatibility; always false from this reader.
     * Non-directoryName cRLIssuer entries used to set it, but RFC 5280
     * 4.2.1.13 restricts cRLIssuer to DNs, so they now throw as
     * malformed instead (T07 fix round 2).
     */
    hasUnbindableCrlIssuer: boolean;
}

function invalidDistributionPoints(message: string): TimestampError {
    return new TimestampError(TimestampErrorCode.INVALID_RESPONSE, message);
}

/**
 * Inspects the structured CRLDistributionPoints extension of a
 * certificate. The extension value gets its own canonical framing and
 * complete-consumption gate (the outer certificate parse cannot see
 * inside the OCTET STRING), then each DistributionPoint contributes its
 * URLs plus the scope fields the strict CRL validator binds: relative
 * names, reasons, and cRLIssuer. Every point also passes the raw
 * DistributionPoint grammar (RFC 5280 4.2.1.13 presence rule,
 * member order/uniqueness, single-choice [0] framing, GeneralName
 * wrapper completeness, GeneralNames cardinality, directoryName
 * grammar, implicit ReasonFlags encoding) before scope evaluation,
 * so malformed metadata can never supply a default in-scope
 * verdict. Throws
 * INVALID_RESPONSE on malformed input or over-limit lists; callers
 * fail closed. Returns an empty array when the certificate carries no
 * distribution-points extension. Pass `options.budget` to bound the
 * nested parse against a shared allowance (T03 F6 aggregation) instead
 * of a fresh budget.
 */
export function getCRLDistributionPointMetadata(
    cert: pkijs.Certificate,
    options: { budget?: DerDecodeBudget } = {}
): DistributionPointMetadata[] {
    const crlExt = cert.extensions?.find((ext) => ext.extnID === "2.5.29.31");
    const extnValue = crlExt?.extnValue.valueBlock.valueHexView;
    if (!crlExt || !extnValue) {
        return [];
    }
    const description = "certificate CRL distribution points";
    let parsed: asn1js.BaseBlock;
    try {
        parsed = parseCanonicalDERValue(new Uint8Array(extnValue), description, {
            budget: options.budget,
        });
    } catch (error) {
        throw invalidDistributionPoints(
            error instanceof Error ? error.message : `${description} are malformed`
        );
    }
    if (!(parsed instanceof asn1js.Sequence)) {
        throw invalidDistributionPoints(`${description} must be a SEQUENCE`);
    }
    let points: pkijs.CRLDistributionPoints;
    try {
        points = new pkijs.CRLDistributionPoints({ schema: parsed });
    } catch {
        throw invalidDistributionPoints(`${description} do not parse`);
    }
    if (points.distributionPoints.length === 0) {
        throw invalidDistributionPoints(
            `${description} must carry at least one distribution point`
        );
    }
    if (points.distributionPoints.length > MAX_CDP_DISTRIBUTION_POINTS) {
        throw invalidDistributionPoints(
            `${description} carry ${points.distributionPoints.length.toString()} points, above ` +
                `the supported limit of ${MAX_CDP_DISTRIBUTION_POINTS.toString()}`
        );
    }
    const raws = parsed.valueBlock.value;
    return points.distributionPoints.map((point, index) =>
        inspectDistributionPoint(point, raws[index], description)
    );
}

/**
 * Validates the raw [1] IMPLICIT ReasonFlags content and returns it.
 * pkijs stores the implicit content (unused-bits count octet first,
 * data octets after) as the BitString value with a zero unused-bits
 * marker, so the count is read from the first content octet, not the
 * parsed marker. The content needs the count octet plus at least one
 * data octet, a count in 0-7, and zero padding bits. No octet-trim
 * minimality is required: non-minimal-but-well-formed flag sets stay
 * verdict-neutral against a full CRL. Throws INVALID_RESPONSE when
 * malformed; callers fail closed.
 */
function checkReasonFlagsContent(reasons: asn1js.BitString, description: string): Uint8Array {
    const raw = new Uint8Array(reasons.valueBlock.valueHexView);
    const malformed = `${description} carry a distribution point with malformed reasons`;
    if (raw.length < 2) {
        throw invalidDistributionPoints(malformed);
    }
    const unusedBits = raw[0];
    const data = raw.subarray(1);
    const last = data[data.length - 1];
    if (unusedBits === undefined || unusedBits > 7 || last === undefined) {
        throw invalidDistributionPoints(malformed);
    }
    if ((last & ((1 << unusedBits) - 1)) !== 0) {
        throw invalidDistributionPoints(malformed);
    }
    return raw;
}

/**
 * Raw DistributionPoint member grammar (T07 fix round 3). pkijs keeps
 * the first DistributionPointName choice while dropping wrapper
 * trailers, keeps the first of duplicated [2] fields, and accepts
 * unordered fields (dropping the [0] outright) -- so the raw framing
 * gates the decoded point before it is trusted. Members are context
 * [0]/[1]/[2], each at most once, in DER order; [0] carries exactly
 * one choice matching the decoded shape; every explicit GeneralName
 * wrapper inside fullName/[2] proves complete. Throws
 * INVALID_RESPONSE; callers fail closed.
 */
function checkRawDistributionPointMembers(
    point: pkijs.DistributionPoint,
    raw: asn1js.BaseBlock | undefined,
    description: string
): void {
    const malformedPoint = `${description} carry a malformed distribution point`;
    if (!(raw instanceof asn1js.Sequence)) {
        throw invalidDistributionPoints(malformedPoint);
    }
    let nameRaw: asn1js.BaseBlock | undefined;
    let issuerRaw: asn1js.BaseBlock | undefined;
    let seen = -1;
    for (const member of raw.valueBlock.value) {
        if (member.idBlock.tagClass !== 3) throw invalidDistributionPoints(malformedPoint);
        const tag = member.idBlock.tagNumber;
        if (tag !== 0 && tag !== 1 && tag !== 2) throw invalidDistributionPoints(malformedPoint);
        if (tag <= seen) throw invalidDistributionPoints(malformedPoint);
        seen = tag;
        if (tag === 0) nameRaw = member;
        else if (tag === 2) issuerRaw = member;
    }
    const distributionPoint = point.distributionPoint;
    const crlIssuer = point.cRLIssuer;
    if (nameRaw === undefined) {
        if (distributionPoint !== undefined) throw invalidDistributionPoints(malformedPoint);
    } else {
        if (!(nameRaw instanceof asn1js.Constructed))
            throw invalidDistributionPoints(malformedPoint);
        const choices = nameRaw.valueBlock.value;
        if (choices.length !== 1) throw invalidDistributionPoints(malformedPoint);
        const choice = choices[0];
        if (choice?.idBlock.tagClass !== 3) {
            throw invalidDistributionPoints(malformedPoint);
        }
        if (choice.idBlock.tagNumber === 0) {
            if (!Array.isArray(distributionPoint)) throw invalidDistributionPoints(malformedPoint);
            if (!(choice instanceof asn1js.Constructed)) {
                throw invalidDistributionPoints(malformedPoint);
            }
            for (const kid of choice.valueBlock.value) {
                if (hasSplitDirectoryNameWrapper(kid)) {
                    throw invalidDistributionPoints(
                        `${description} carry a distribution point with a malformed directoryName`
                    );
                }
                if (isUndecidableGeneralNameWrapper(kid)) {
                    throw invalidDistributionPoints(
                        `${description} carry a distribution point with a general name ` +
                            "outside the direct-issuance profile"
                    );
                }
            }
        } else if (choice.idBlock.tagNumber === 1) {
            if (!(distributionPoint instanceof pkijs.RelativeDistinguishedNames)) {
                throw invalidDistributionPoints(malformedPoint);
            }
        } else {
            throw invalidDistributionPoints(malformedPoint);
        }
    }
    if (issuerRaw === undefined) {
        if (crlIssuer !== undefined) throw invalidDistributionPoints(malformedPoint);
    } else {
        if (crlIssuer === undefined) throw invalidDistributionPoints(malformedPoint);
        if (!(issuerRaw instanceof asn1js.Constructed)) {
            throw invalidDistributionPoints(malformedPoint);
        }
        for (const kid of issuerRaw.valueBlock.value) {
            if (hasSplitDirectoryNameWrapper(kid)) {
                throw invalidDistributionPoints(
                    `${description} carry a distribution point with a malformed cRLIssuer directoryName`
                );
            }
        }
    }
}

function inspectDistributionPoint(
    point: pkijs.DistributionPoint,
    raw: asn1js.BaseBlock | undefined,
    description: string
): DistributionPointMetadata {
    const metadata: DistributionPointMetadata = {
        urls: [],
        hasRelativeName: false,
        reasons: null,
        crlIssuerDirectoryNames: [],
        hasUnbindableCrlIssuer: false,
    };
    checkRawDistributionPointMembers(point, raw, description);
    const distributionPoint = point.distributionPoint;
    const crlIssuer = point.cRLIssuer;
    // RFC 5280 4.2.1.13: a DistributionPoint MUST NOT consist of only
    // the reasons field; either distributionPoint or cRLIssuer MUST be
    // present. An empty point must never supply a default scope.
    if (distributionPoint === undefined && crlIssuer === undefined) {
        throw invalidDistributionPoints(
            `${description} carry a distribution point with neither ` +
                "distributionPoint nor cRLIssuer"
        );
    }
    if (distributionPoint === undefined) {
        // Absent beside cRLIssuer is legal (RFC 5280 4.2.1.13);
        // the point contributes no names and stays out of direct
        // scope (T07 fix round 3). The neither-present case threw
        // above, so cRLIssuer is set here.
    } else if (distributionPoint instanceof pkijs.RelativeDistinguishedNames) {
        metadata.hasRelativeName = true;
    } else if (Array.isArray(distributionPoint)) {
        if (distributionPoint.length === 0) {
            throw invalidDistributionPoints(
                `${description} carry a distribution point with an empty fullName`
            );
        }
        if (distributionPoint.length > MAX_CDP_GENERAL_NAMES) {
            throw invalidDistributionPoints(
                `${description} carry too many GeneralNames in one distribution point`
            );
        }
        for (const name of distributionPoint) {
            if (name.type === 4 && name.value instanceof pkijs.RelativeDistinguishedNames) {
                if (!isWellFormedName(name.value)) {
                    throw invalidDistributionPoints(
                        `${description} carry a distribution point with a malformed directoryName`
                    );
                }
            } else if (name.type === 6 && typeof name.value === "string") {
                metadata.urls.push(name.value);
            }
        }
    } else {
        // Unreachable per the pkijs types (a present
        // DistributionPointName is a relative name or a GeneralName
        // array), but fail closed for untyped callers rather than
        // treating it as absent.
        throw invalidDistributionPoints(
            `${description} carry a distribution point with a malformed distributionPoint field`
        );
    }
    if (point.reasons !== undefined) {
        metadata.reasons = checkReasonFlagsContent(point.reasons, description);
    }
    if (crlIssuer !== undefined) {
        if (crlIssuer.length === 0) {
            throw invalidDistributionPoints(
                `${description} carry a distribution point with an empty cRLIssuer`
            );
        }
        if (crlIssuer.length > MAX_CDP_GENERAL_NAMES) {
            throw invalidDistributionPoints(
                `${description} carry too many GeneralNames in one cRLIssuer field`
            );
        }
        // RFC 5280 4.2.1.13: cRLIssuer MUST only contain the DN from the
        // CRL issuer field. Anything else is malformed metadata, not an
        // unbindable-but-skippable hint.
        for (const name of crlIssuer) {
            if (name.type !== 4 || !(name.value instanceof pkijs.RelativeDistinguishedNames)) {
                throw invalidDistributionPoints(
                    `${description} carry a distribution point whose cRLIssuer is not a directoryName`
                );
            }
            if (!isWellFormedName(name.value)) {
                throw invalidDistributionPoints(
                    `${description} carry a distribution point with a malformed cRLIssuer directoryName`
                );
            }
            metadata.crlIssuerDirectoryNames.push(name.value.toString());
        }
    }
    return metadata;
}
