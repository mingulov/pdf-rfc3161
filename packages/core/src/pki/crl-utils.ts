import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { getLogger } from "../utils/logger.js";

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
