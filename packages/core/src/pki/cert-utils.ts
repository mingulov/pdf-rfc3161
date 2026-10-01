import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { getLogger } from "../utils/logger.js";
import { ensureWebCrypto } from "../utils/web-crypto.js";
import { bytesToHex } from "../utils.js";

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

/**
 * Exact byte identity for certificates: true only when both retained
 * signed encodings are byte-identical (or both references are the same
 * object). Serial-only comparison collides across issuers, so
 * identity-sensitive lookups must use this. Never throws:
 * unserializable inputs compare unequal unless they are the same
 * object. Retained TBS bytes (not field re-encoding) keep
 * noncanonical explicit defaults distinct and in-memory certificates
 * comparable to their parses. The representation is selected per
 * input: each side keeps its retained signed TBS bytes when present,
 * and only a side without signed bytes is field re-encoded
 * (encodeTBS), so one empty tbsView never discards the other side's
 * retained bytes.
 */
function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
    if (left.length !== right.length) return false;
    for (let index = 0; index < left.length; index++) {
        if (left[index] !== right[index]) return false;
    }
    return true;
}

export function certificatesByteEqual(a: pkijs.Certificate, b: pkijs.Certificate): boolean {
    if (a === b) return true;
    try {
        const aTbs = a.tbsView.length > 0 ? a.tbsView : new Uint8Array(a.encodeTBS().toBER(false));
        const bTbs = b.tbsView.length > 0 ? b.tbsView : new Uint8Array(b.encodeTBS().toBER(false));
        if (!bytesEqual(aTbs, bTbs)) return false;
        const aSigAlg = new Uint8Array(a.signatureAlgorithm.toSchema().toBER(false));
        const bSigAlg = new Uint8Array(b.signatureAlgorithm.toSchema().toBER(false));
        if (!bytesEqual(aSigAlg, bSigAlg)) return false;
        const aSig = new Uint8Array(a.signatureValue.toBER(false));
        const bSig = new Uint8Array(b.signatureValue.toBER(false));
        return bytesEqual(aSig, bSig);
    } catch {
        return false;
    }
}

/**
 * Returns true when `issuer` actually issued `cert`: the issuer/subject
 * names match and the target signature verifies with the issuer public
 * key. Never throws; any failure means issuance is not established.
 * Establishes issuance only, never trust.
 */
export async function verifyIssuance(
    cert: pkijs.Certificate,
    issuer: pkijs.Certificate
): Promise<boolean> {
    try {
        if (issuer.subject.toString() !== cert.issuer.toString()) return false;
        await ensureWebCrypto();
        return await cert.verify(issuer);
    } catch {
        return false;
    }
}

/**
 * Authority Key Identifier extension OID.
 */
const AKI_OID = "2.5.29.35";

/**
 * Subject Key Identifier extension OID.
 */
const SKI_OID = "2.5.29.14";

/**
 * Hex of the leaf Authority Key Identifier, or undefined when the
 * certificate carries no readable AKI. Ordering hint only; the target
 * signature always decides issuance.
 */
function authorityKeyIdentifier(cert: pkijs.Certificate): string | undefined {
    try {
        const raw = cert.extensions?.find((ext) => ext.extnID === AKI_OID)?.extnValue.valueBlock
            .valueHexView;
        if (!raw) return undefined;
        const asn1 = asn1js.fromBER(raw);
        if (asn1.offset === -1 || !(asn1.result instanceof asn1js.Sequence)) return undefined;
        const aki = new pkijs.AuthorityKeyIdentifier({ schema: asn1.result });
        const keyId = aki.keyIdentifier?.valueBlock.valueHexView;
        return keyId ? bytesToHex(keyId) : undefined;
    } catch {
        return undefined;
    }
}

/**
 * Hex of the candidate Subject Key Identifier, or undefined when the
 * certificate carries no readable SKI. Ordering hint only.
 */
function subjectKeyIdentifier(cert: pkijs.Certificate): string | undefined {
    try {
        const raw = cert.extensions?.find((ext) => ext.extnID === SKI_OID)?.extnValue.valueBlock
            .valueHexView;
        if (!raw) return undefined;
        const asn1 = asn1js.fromBER(raw);
        const view =
            asn1.offset !== -1 && asn1.result instanceof asn1js.OctetString
                ? asn1.result.valueBlock.valueHexView
                : raw;
        return bytesToHex(view);
    } catch {
        return undefined;
    }
}

/**
 * Resolves the issuing certificate from candidates. Names narrow the
 * field, AKI/SKI order same-subject keys, and the target signature
 * decides: the first candidate whose key verifies the target is
 * returned. The target itself (by exact bytes) is never a candidate.
 * Returns undefined when no candidate verifies. Establishes issuance
 * only, never trust.
 *
 * @param cert - The certificate to find the issuer for
 * @param candidates - List of potential issuer certificates
 * @returns The verified issuer certificate if found, otherwise undefined
 */
export async function resolveVerifiedIssuer(
    cert: pkijs.Certificate,
    candidates: pkijs.Certificate[]
): Promise<pkijs.Certificate | undefined> {
    const named = candidates.filter(
        (candidate) =>
            !certificatesByteEqual(candidate, cert) &&
            candidate.subject.toString() === cert.issuer.toString()
    );
    if (named.length === 0) return undefined;
    const aki = authorityKeyIdentifier(cert);
    const preferred: pkijs.Certificate[] = [];
    const rest: pkijs.Certificate[] = [];
    for (const candidate of named) {
        if (aki !== undefined && subjectKeyIdentifier(candidate) === aki) {
            preferred.push(candidate);
        } else {
            rest.push(candidate);
        }
    }
    for (const candidate of [...preferred, ...rest]) {
        if (await verifyIssuance(cert, candidate)) return candidate;
    }
    return undefined;
}

/**
 * Finds the issuer certificate for a given certificate from a list of candidates.
 * Uses Authority Key Identifier (AKI) and Subject Key Identifier (SKI) if available,
 * causing a more robust match than just Subject Name.
 *
 * Structural narrowing only: names, then AKI/SKI preference with a
 * first-name-match fallback. It does not verify issuance and may return
 * the target itself for self-issued names, so callers that build
 * revocation requests or feed trust inputs must use
 * `resolveVerifiedIssuer` instead.
 *
 * @param cert - The certificate to find the issuer for
 * @param candidates - List of potential issuer certificates
 * @returns The issuer certificate if found, otherwise undefined
 */
export function findIssuer(
    cert: pkijs.Certificate,
    candidates: pkijs.Certificate[]
): pkijs.Certificate | undefined {
    // 1. Filter by Issuer Name (Subject)
    const nameMatches = candidates.filter((c) => c.subject.toString() === cert.issuer.toString());

    if (nameMatches.length === 0) {
        return undefined;
    }

    // If only one name match, return it (most common case)
    if (nameMatches.length === 1) {
        return nameMatches[0];
    }

    // 2. If multiple name matches, filter by Key Identifier (AKI == SKI)
    try {
        const akiExt = cert.extensions?.find((ext) => ext.extnID === AKI_OID);
        if (akiExt?.extnValue) {
            try {
                const akiAsn1 = asn1js.fromBER(akiExt.extnValue.valueBlock.valueHexView);

                if (akiAsn1.result instanceof asn1js.Sequence) {
                    // Try pkijs parsing first
                    const aki = new pkijs.AuthorityKeyIdentifier({ schema: akiAsn1.result });
                    let keyIdHex: string | undefined;

                    if (aki.keyIdentifier) {
                        keyIdHex = bytesToHex(aki.keyIdentifier.valueBlock.valueHexView);
                    } else {
                        // Fallback: Manual search in sequence
                        if (
                            "value" in akiAsn1.result.valueBlock &&
                            Array.isArray(akiAsn1.result.valueBlock.value)
                        ) {
                            const sequenceValue = akiAsn1.result.valueBlock.value;
                            const ki = sequenceValue.find(
                                (item) =>
                                    "tagNumber" in item.idBlock && item.idBlock.tagNumber === 0
                            );
                            if (ki && "valueHexView" in ki.valueBlock) {
                                keyIdHex = bytesToHex(ki.valueBlock.valueHexView as ArrayBuffer);
                            }
                        }
                    }

                    if (keyIdHex) {
                        const keyMatch = nameMatches.find((candidate) => {
                            const skiExt = candidate.extensions?.find(
                                (ext) => ext.extnID === SKI_OID
                            );
                            if (!skiExt?.extnValue) return false;

                            // Try to parse SKI as nested OctetString, fallback to raw
                            const skiAsn1 = asn1js.fromBER(
                                skiExt.extnValue.valueBlock.valueHexView
                            );
                            let skiHex: string;
                            if (
                                skiAsn1.offset !== -1 &&
                                skiAsn1.result instanceof asn1js.OctetString
                            ) {
                                skiHex = bytesToHex(skiAsn1.result.valueBlock.valueHexView);
                            } else {
                                skiHex = bytesToHex(skiExt.extnValue.valueBlock.valueHexView);
                            }

                            return skiHex === keyIdHex;
                        });

                        if (keyMatch) {
                            return keyMatch;
                        }
                    }
                }
            } catch (e) {
                getLogger().debug(
                    `[Cert-Utils] AKI parsing failed: ${e instanceof Error ? e.message : String(e)}`
                );
            }
        }
    } catch (e) {
        getLogger().warn("[Cert-Utils] Error matching AKI/SKI:", e);
    }

    // 3. Fallback: Return the first name match
    // Ideally we might check validity dates or other factors, but first match is standard fallback
    return nameMatches[0];
}
