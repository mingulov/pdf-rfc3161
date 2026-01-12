import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { getLogger } from "../utils/logger.js";

/**
 * Authority Information Access (AIA) Extension OID
 */
const AIA_OID = "1.3.6.1.5.5.7.1.1";

/**
 * Access Method OID for CA Issuers (id-ad-caIssuers)
 */
const CA_ISSUERS_OID = "1.3.6.1.5.5.7.48.2";

/**
 * Extracts CA Issuers URLs from a certificate's AIA extension.
 * This is used to fetch missing intermediate certificates in the chain.
 *
 * @param cert - The certificate to inspect
 * @returns Array of CA Issuers URLs found
 */
export function getCaIssuers(cert: pkijs.Certificate): string[] {
    const urls: string[] = [];

    if (!cert.extensions) {
        return urls;
    }

    const aiaExt = cert.extensions.find((ext) => ext.extnID === AIA_OID);

    if (!aiaExt?.extnValue) {
        return urls;
    }

    try {
        // Parse the AuthorityInfoAccessSyntax (sequence of AccessDescription)
        let authorityInfoAccess: pkijs.AccessDescription[] = [];

        if (aiaExt.parsedValue) {
            // pkijs might have parsed it already
            const parsed = aiaExt.parsedValue as unknown as {
                accessDescriptions?: pkijs.AccessDescription[];
            };
            if (Array.isArray(parsed.accessDescriptions)) {
                authorityInfoAccess = parsed.accessDescriptions;
            }
        } else {
            // Manual parsing
            const asn1 = asn1js.fromBER(aiaExt.extnValue.valueBlock.valueHexView);
            if (asn1.offset !== -1 && asn1.result.valueBlock instanceof asn1js.Constructed) {
                // It's a SEQUENCE of AccessDescription
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                const valueBlock = asn1.result.valueBlock as unknown as { value: any[] };
                for (const item of valueBlock.value) {
                    const ad = new pkijs.AccessDescription({ schema: item });
                    authorityInfoAccess.push(ad);
                }
            }
        }

        for (const description of authorityInfoAccess) {
            // Check if it is id-ad-caIssuers
            if (description.accessMethod === CA_ISSUERS_OID) {
                const location = description.accessLocation;
                // Type 6 is uniformResourceIdentifier (URI)
                if (location.type === 6 && typeof location.value === "string") {
                    urls.push(location.value);
                }
            }
        }
    } catch (e) {
        getLogger().warn("[Cert-Utils] Failed to parse AIA extension:", e);
    }

    return urls;
}
