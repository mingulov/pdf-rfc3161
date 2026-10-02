import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { toArrayBuffer } from "../utils.js";

/**
 * Strict distinguished-name grammar shared by the CRL-side validators
 * (T07 fix round 2): the CRL evidence validator walks the CRL issuer
 * name and entry certificateIssuer directoryNames, and the
 * distribution-point metadata reader walks fullName/cRLIssuer
 * directoryNames. One module serves both so the grammar cannot drift
 * between the two paths; the OCSP validator keeps its own frozen copy
 * (T06 complete -- the T07 brief forbids touching it).
 *
 * Tree-shaking: only strict (advanced-entry) paths import this module,
 * so it stays out of the main bundle.
 */

/**
 * True when a raw GeneralName node is a context-constructed [0]
 * (otherName), [3] (x400Address), or [5] (ediPartyName) wrapper.
 * pkijs matches only the leading children of these wrappers against
 * its (RFC-nonconformant, flattened) schemas while silently dropping
 * trailers -- nested ORAddress trailers for [3] (CountryName
 * payloads, second country strings, administration/private-domain,
 * domain-defined, and extension-attribute trailers), trailing choice
 * members for [0]/[5] -- so no framing rule can separate a complete
 * value from one with ignored members: the strict profile rejects
 * the wrapper outright instead of trusting the decoded choice. x400
 * distribution points are vanishingly rare, and fail-closed unknown
 * is the safe direction, so [3] is deferred rather than given a full
 * ORAddress grammar. The implicit choices are primitives pkijs
 * matches strictly.
 */
export function isUndecidableGeneralNameWrapper(node: asn1js.BaseBlock): boolean {
    if (!(node instanceof asn1js.Constructed) || node.idBlock.tagClass !== 3) return false;
    const tag = node.idBlock.tagNumber;
    return tag === 0 || tag === 3 || tag === 5;
}

/**
 * True when a raw directoryName [4] wrapper is split: anything but
 * exactly one Name child. pkijs decodes the first Name and drops the
 * rest, so the wrapper must prove complete before the decoded name
 * is bound. Non-[4] nodes are not judged here.
 */
export function hasSplitDirectoryNameWrapper(node: asn1js.BaseBlock): boolean {
    if (!(node instanceof asn1js.Constructed) || node.idBlock.tagClass !== 3) return false;
    if (node.idBlock.tagNumber !== 4) return false;
    return node.valueBlock.value.length !== 1;
}

/** Maximum RDNs walked in one strict Name grammar check. */
export const MAX_CRL_NAME_RDNS = 64;

/** Maximum attribute type-and-value entries walked in one strict Name grammar check. */
export const MAX_CRL_NAME_ATTRIBUTES = 256;

/**
 * Raw content octets of a parsed OBJECT IDENTIFIER. asn1js keeps only
 * the normalized dotted string in `valueBlock` (`valueHexView` is
 * empty for OIDs), so the exact content octets come from the retained
 * TLV (`valueBeforeDecodeView`) minus the tag+length header, whose
 * span is the retained length less `lenBlock.length`. Returns null
 * when the retained bytes are inconsistent; callers fail closed.
 */
export function oidContentOctets(oid: asn1js.ObjectIdentifier): Uint8Array | null {
    const encoded = oid.valueBeforeDecodeView;
    const contentLength = oid.lenBlock.length;
    if (!Number.isInteger(contentLength) || contentLength < 0 || contentLength > encoded.length) {
        return null;
    }
    return encoded.subarray(encoded.length - contentLength);
}

/**
 * True when OBJECT IDENTIFIER content octets are canonical DER
 * (X.690 8.19). The content must be nonempty, every subidentifier must
 * terminate (an MSB-set octet with no successor means truncation),
 * and every subidentifier must use minimal base-128: a multi-octet
 * subidentifier whose first octet is 0x80 carries zero high bits and
 * could drop that octet (X.690 8.19.2 fewest-octets rule). There is
 * deliberately no first-octet range check: every first-subidentifier
 * value maps to a valid first arc (values at or above 80 are arc 2).
 */
export function isCanonicalDerOidContent(content: Uint8Array): boolean {
    if (content.length === 0) return false;
    let index = 0;
    while (index < content.length) {
        const first = content[index];
        if (first === undefined) return false;
        if ((first & 0x80) === 0) {
            index += 1;
            continue;
        }
        if (first === 0x80) return false;
        index += 1;
        let terminated = false;
        while (index < content.length) {
            const octet = content[index];
            if (octet === undefined) return false;
            index += 1;
            if ((octet & 0x80) === 0) {
                terminated = true;
                break;
            }
        }
        if (!terminated) return false;
    }
    return true;
}

/**
 * Strict Name grammar over the retained RDN subtree (RFC 5280 4.1.2.4).
 * pkijs retains parsed names verbatim (`valueBeforeDecode`) and re-emits
 * them on `toSchema()`, so the forced TBS round-trip cannot see extra or
 * duplicated name members. This walk runs over the original name bytes:
 * Name is a SEQUENCE of SETs (RDNs), each holding attribute
 * type-and-value SEQUENCEs of exactly { type OID, value }. Completeness
 * only: multi-valued RDNs, unusual-but-legal value types, long names,
 * and an entirely empty Name sequence all pass; an empty RDN SET
 * violates its minimum cardinality (RFC 5280 4.1.2.4) and fails, as do
 * extra members, missing members, non-OID types, type OIDs whose
 * content is not canonical DER (empty, unterminated, or non-minimal
 * base-128), and non-SET/non-SEQUENCE framing. Never throws; any
 * failure means malformed. Budget note: this walk re-parses retained
 * bytes outside the shared DER budget (see the aggregate comment at
 * the budget site); the input is bounded by the outer preflight plus
 * the RDN/attribute caps above.
 */
export function isWellFormedName(name: pkijs.RelativeDistinguishedNames): boolean {
    try {
        const retained = name.valueBeforeDecode;
        const bytes =
            retained.byteLength > 0
                ? new Uint8Array(retained)
                : new Uint8Array(name.toSchema().toBER(false));
        const parsed = asn1js.fromBER(toArrayBuffer(bytes));
        if (parsed.offset === -1 || parsed.offset !== bytes.length) return false;
        if (!(parsed.result instanceof asn1js.Sequence)) return false;
        const rdns = parsed.result.valueBlock.value;
        if (rdns.length > MAX_CRL_NAME_RDNS) return false;
        let attributes = 0;
        for (const rdn of rdns) {
            if (!(rdn instanceof asn1js.Set)) return false;
            if (rdn.valueBlock.value.length === 0) return false;
            for (const member of rdn.valueBlock.value) {
                attributes += 1;
                if (attributes > MAX_CRL_NAME_ATTRIBUTES) return false;
                if (!(member instanceof asn1js.Sequence)) return false;
                const parts = member.valueBlock.value;
                if (parts.length !== 2) return false;
                if (!(parts[0] instanceof asn1js.ObjectIdentifier)) return false;
                const typeContent = oidContentOctets(parts[0]);
                if (typeContent === null || !isCanonicalDerOidContent(typeContent)) return false;
            }
        }
        return true;
    } catch {
        return false;
    }
}
