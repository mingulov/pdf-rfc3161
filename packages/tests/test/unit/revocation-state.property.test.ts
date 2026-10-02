/* eslint-disable @typescript-eslint/no-deprecated -- compatibility coverage */
import { describe, expect, it, beforeAll } from "vitest";
import * as fc from "fast-check";
import { createPublicKey, verify as nodeVerify, type KeyObject } from "node:crypto";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { ValidationSession } from "../../../core/src/pki/validation-session.js";
import { InMemoryValidationCache } from "../../../core/src/pki/fetchers/memory-cache.js";
import type {
    RevocationDataFetcher,
    RevocationStatus,
} from "../../../core/src/pki/validation-types.js";
import { toArrayBuffer } from "../../../core/src/utils.js";
import {
    createSignedCRL,
    createSignedOCSPResponse,
    createTestCA,
    createTestLeaf,
    corruptCRLSignature,
    corruptResponseSignature,
    inspectOCSPRequest,
    type TestCertificateAuthority,
    type TestKeyPair,
    type TestLeaf,
} from "../fixtures/signed-revocation-material.js";
import {
    OPENSSL_INTEROP_CA_BASE64,
    OPENSSL_INTEROP_EMPTY_CRL_BASE64,
    OPENSSL_INTEROP_LEAF_BASE64,
    OPENSSL_INTEROP_REVOKED_CRL_BASE64,
    decodeInteropDer,
} from "../fixtures/openssl-crl-interop.js";

// T14: deterministic revocation-state properties.
//
// Cache separation (OCSP vs CRL keys, responder/issuer scoping), issuer
// identity binding, and the complete revocation fallback state model --
// all with real serialized OCSP/CRL evidence. Independent oracles: a
// reference-model cache, hand-rolled DER walks to the OCSP/CRL TBS and
// status bytes, node:crypto TBS signature verification, and real
// openssl-generated golden CRLs. RSA/TSA keys are generated ONCE per
// file (beforeAll), never per generated case.

const SEED_RS_CACHE = 14021;
const SEED_RS_ISSUER = 14022;
const SEED_RS_FALLBACK = 14023;
const CACHE_RUNS = 100;
const ISSUER_RUNS = 40;
const FALLBACK_RUNS = 150;

const OCSP_URL = "http://ocsp.example.com/";
const CRL_URL = "http://crl.example.com/ca.crl";
const LEAF_SERIAL = 2001;

const CHECK_DATE = new Date("2026-05-01T12:00:00Z");
const PRODUCED_AT = new Date("2026-05-01T11:00:00Z");
const THIS_UPDATE = new Date("2026-05-01T11:00:00Z");
const NEXT_UPDATE = new Date("2026-05-02T11:00:00Z");
// Literal freshness bounds (the documented session defaults); evidence
// dates sit far from every boundary so boundary semantics cannot matter.
const SKEW_MS = 5 * 60 * 1000;
const MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

const RSA_SHA256_OID = "1.2.840.113549.1.1.11";
const DELTA_CRL_OID = "2.5.29.27";

// ---------------------------------------------------------------------------
// Hand-rolled DER reader (independent oracle: raw TLV walk, no asn1js/pkijs).
// ---------------------------------------------------------------------------

interface DerNode {
    tagClass: number;
    constructed: boolean;
    tagNumber: number;
    length: number;
    valueOffset: number;
    totalLength: number;
}

interface DerChild {
    node: DerNode;
    offset: number;
}

function readDerNode(bytes: Uint8Array, offset: number): DerNode {
    const tagByte = bytes[offset];
    if (tagByte === undefined) throw new Error("hand DER: truncated tag");
    const tagClass = (tagByte & 0xc0) >> 6;
    const constructed = (tagByte & 0x20) !== 0;
    let tagNumber = tagByte & 0x1f;
    let cursor = offset + 1;
    if (tagNumber === 0x1f) {
        tagNumber = 0;
        for (let index = 0; index < 4; index++) {
            const next = bytes[cursor];
            if (next === undefined) throw new Error("hand DER: truncated high tag");
            cursor++;
            tagNumber = tagNumber * 128 + (next & 0x7f);
            if ((next & 0x80) === 0) break;
            if (index === 3) throw new Error("hand DER: tag number too large");
        }
    }
    const lengthByte = bytes[cursor];
    if (lengthByte === undefined) throw new Error("hand DER: truncated length");
    cursor++;
    let length = 0;
    if (lengthByte < 0x80) {
        length = lengthByte;
    } else {
        if (lengthByte === 0x80) throw new Error("hand DER: indefinite length rejected");
        const octets = lengthByte & 0x7f;
        if (octets < 1 || octets > 4) throw new Error("hand DER: bad length octets");
        for (let index = 0; index < octets; index++) {
            const octet = bytes[cursor];
            if (octet === undefined) throw new Error("hand DER: truncated long length");
            cursor++;
            length = length * 256 + octet;
        }
    }
    if (cursor + length > bytes.length) throw new Error("hand DER: value overruns input");
    return {
        tagClass,
        constructed,
        tagNumber,
        length,
        valueOffset: cursor,
        totalLength: cursor + length - offset,
    };
}

function derChildren(bytes: Uint8Array, node: DerNode): DerChild[] {
    if (!node.constructed) throw new Error("hand DER: primitive has no children");
    const out: DerChild[] = [];
    let cursor = node.valueOffset;
    const end = node.valueOffset + node.length;
    while (cursor < end) {
        const child = readDerNode(bytes, cursor);
        out.push({ node: child, offset: cursor });
        cursor += child.totalLength;
    }
    if (cursor !== end) throw new Error("hand DER: child overrun");
    return out;
}

function nodeBytes(bytes: Uint8Array, node: DerNode): Uint8Array {
    return bytes.slice(node.valueOffset, node.valueOffset + node.length);
}

function oidBytesToString(bytes: Uint8Array): string {
    const first = bytes[0];
    if (first === undefined) throw new Error("hand DER: empty OID");
    const head = Math.min(2, Math.floor(first / 40));
    const parts: number[] = [head, first - head * 40];
    let value = 0;
    let pending = false;
    for (let index = 1; index < bytes.length; index++) {
        const octet = bytes[index];
        if (octet === undefined) throw new Error("hand DER: OID overrun");
        value = value * 128 + (octet & 0x7f);
        pending = true;
        if ((octet & 0x80) === 0) {
            parts.push(value);
            value = 0;
            pending = false;
        }
    }
    if (pending) throw new Error("hand DER: truncated OID subidentifier");
    return parts.map((part) => part.toString(10)).join(".");
}

/** Parses a Zulu UTCTime/GeneralizedTime value to epoch milliseconds. */
function handParseTime(bytes: Uint8Array, node: DerNode): number {
    if (node.tagClass !== 0 || (node.tagNumber !== 23 && node.tagNumber !== 24)) {
        throw new Error("hand DER: not a Time value");
    }
    const text = new TextDecoder("ascii").decode(nodeBytes(bytes, node));
    if (!text.endsWith("Z")) throw new Error("hand DER: non-Zulu Time");
    const digits = text.slice(0, -1);
    for (const char of digits) {
        if (char < "0" || char > "9") throw new Error("hand DER: non-digit Time");
    }
    let year: number;
    let rest: string;
    if (node.tagNumber === 23) {
        if (digits.length !== 12) throw new Error("hand DER: bad UTCTime length");
        const shortYear = Number(digits.slice(0, 2));
        year = shortYear < 50 ? 2000 + shortYear : 1900 + shortYear;
        rest = digits.slice(2);
    } else {
        if (digits.length !== 14) throw new Error("hand DER: bad GeneralizedTime length");
        year = Number(digits.slice(0, 4));
        rest = digits.slice(4);
    }
    const month = Number(rest.slice(0, 2));
    const day = Number(rest.slice(2, 4));
    const hour = Number(rest.slice(4, 6));
    const minute = Number(rest.slice(6, 8));
    const second = Number(rest.slice(8, 10));
    return Date.UTC(year, month - 1, day, hour, minute, second);
}

interface SignedEnvelope {
    /** Exact DER bytes covered by the signature (tag + length + value). */
    tbs: Uint8Array;
    signatureAlgorithmOid: string;
    signature: Uint8Array;
}

function handBitStringSignature(bytes: Uint8Array, node: DerNode): Uint8Array {
    if (node.tagClass !== 0 || node.tagNumber !== 3 || node.constructed) {
        throw new Error("hand DER: not a primitive BIT STRING");
    }
    const value = nodeBytes(bytes, node);
    const unused = value[0];
    if (unused === undefined || unused !== 0 || value.length < 2) {
        throw new Error("hand DER: bad signature BIT STRING");
    }
    return value.slice(1);
}

/** Extracts the BasicOCSPResponse TBS + signature from an OCSPResponse. */
function handOcspEnvelope(responseBytes: Uint8Array): SignedEnvelope & { basicBytes: Uint8Array } {
    const outer = readDerNode(responseBytes, 0);
    const outerKids = derChildren(responseBytes, outer);
    const statusNode = outerKids[0]?.node;
    const responseBytesNode = outerKids[1]?.node;
    if (statusNode === undefined || responseBytesNode === undefined) {
        throw new Error("hand DER: OCSPResponse shape");
    }
    if (statusNode.tagClass !== 0 || statusNode.tagNumber !== 10) {
        throw new Error("hand DER: OCSPResponse status shape");
    }
    const statusValue = nodeBytes(responseBytes, statusNode);
    if (statusValue.length !== 1 || statusValue[0] !== 0) {
        throw new Error("hand DER: OCSPResponse not successful");
    }
    if (responseBytesNode.tagClass !== 2 || responseBytesNode.tagNumber !== 0) {
        throw new Error("hand DER: OCSPResponse responseBytes shape");
    }
    const inner = derChildren(responseBytes, responseBytesNode)[0]?.node;
    if (inner === undefined) throw new Error("hand DER: empty OCSP responseBytes");
    const innerKids = derChildren(responseBytes, inner);
    const octetNode = innerKids[1]?.node;
    if (octetNode?.tagClass !== 0 || octetNode.tagNumber !== 4 || octetNode.constructed) {
        throw new Error("hand DER: OCSP BasicOCSPResponse shape");
    }
    const basicBytes = nodeBytes(responseBytes, octetNode);
    const basic = readDerNode(basicBytes, 0);
    const basicKids = derChildren(basicBytes, basic);
    const tbsChild = basicKids[0];
    const algChild = basicKids[1]?.node;
    const sigChild = basicKids[2]?.node;
    if (tbsChild === undefined || algChild === undefined || sigChild === undefined) {
        throw new Error("hand DER: BasicOCSPResponse shape");
    }
    const algKids = derChildren(basicBytes, algChild);
    const oidNode = algKids[0]?.node;
    if (oidNode?.tagClass !== 0 || oidNode.tagNumber !== 6) {
        throw new Error("hand DER: OCSP signature algorithm shape");
    }
    return {
        tbs: basicBytes.slice(tbsChild.offset, tbsChild.offset + tbsChild.node.totalLength),
        signatureAlgorithmOid: oidBytesToString(nodeBytes(basicBytes, oidNode)),
        signature: handBitStringSignature(basicBytes, sigChild),
        basicBytes,
    };
}

interface HandSingleResponse {
    certStatus: "good" | "revoked" | "unknown";
    producedAt: number;
    thisUpdate: number;
    nextUpdate: number | undefined;
}

/** Extracts the first SingleResponse status + times from BasicOCSPResponse bytes. */
function handFirstSingleResponse(basicBytes: Uint8Array): HandSingleResponse {
    const basic = readDerNode(basicBytes, 0);
    const tbsNode = derChildren(basicBytes, basic)[0]?.node;
    if (tbsNode === undefined) throw new Error("hand DER: missing ResponseData");
    const tbsKids = derChildren(basicBytes, tbsNode);
    const producedAtNode = tbsKids.find(
        (child) =>
            child.node.tagClass === 0 &&
            (child.node.tagNumber === 23 || child.node.tagNumber === 24)
    )?.node;
    const responsesNode = tbsKids.find(
        (child) =>
            child.node.tagClass === 0 && child.node.tagNumber === 16 && child.node.constructed
    )?.node;
    if (producedAtNode === undefined || responsesNode === undefined) {
        throw new Error("hand DER: ResponseData shape");
    }
    const single = derChildren(basicBytes, responsesNode)[0]?.node;
    if (single === undefined) throw new Error("hand DER: empty OCSP responses");
    const singleKids = derChildren(basicBytes, single);
    const statusNode = singleKids[1]?.node;
    const thisUpdateNode = singleKids[2]?.node;
    if (statusNode === undefined || thisUpdateNode === undefined) {
        throw new Error("hand DER: SingleResponse shape");
    }
    if (statusNode.tagClass !== 2) throw new Error("hand DER: SingleResponse certStatus shape");
    let certStatus: HandSingleResponse["certStatus"];
    if (statusNode.tagNumber === 0 && !statusNode.constructed) {
        certStatus = "good";
    } else if (statusNode.tagNumber === 1 && statusNode.constructed) {
        certStatus = "revoked";
    } else if (statusNode.tagNumber === 2 && !statusNode.constructed) {
        certStatus = "unknown";
    } else {
        throw new Error("hand DER: SingleResponse certStatus value");
    }
    const nextUpdateHolder = singleKids[3]?.node;
    let nextUpdate: number | undefined;
    if (nextUpdateHolder?.tagClass === 2) {
        if (nextUpdateHolder.tagNumber !== 0 || !nextUpdateHolder.constructed) {
            throw new Error("hand DER: SingleResponse nextUpdate shape");
        }
        const inner = derChildren(basicBytes, nextUpdateHolder)[0]?.node;
        if (inner === undefined) throw new Error("hand DER: empty nextUpdate");
        nextUpdate = handParseTime(basicBytes, inner);
    }
    return {
        certStatus,
        producedAt: handParseTime(basicBytes, producedAtNode),
        thisUpdate: handParseTime(basicBytes, thisUpdateNode),
        nextUpdate,
    };
}

/** Extracts the TBSCertList TBS + signature from a CRL. */
function handCrlEnvelope(crlBytes: Uint8Array): SignedEnvelope {
    const outer = readDerNode(crlBytes, 0);
    const kids = derChildren(crlBytes, outer);
    const tbsChild = kids[0];
    const algChild = kids[1]?.node;
    const sigChild = kids[2]?.node;
    if (tbsChild === undefined || algChild === undefined || sigChild === undefined) {
        throw new Error("hand DER: CRL shape");
    }
    const algKids = derChildren(crlBytes, algChild);
    const oidNode = algKids[0]?.node;
    if (oidNode?.tagClass !== 0 || oidNode.tagNumber !== 6) {
        throw new Error("hand DER: CRL signature algorithm shape");
    }
    return {
        tbs: crlBytes.slice(tbsChild.offset, tbsChild.offset + tbsChild.node.totalLength),
        signatureAlgorithmOid: oidBytesToString(nodeBytes(crlBytes, oidNode)),
        signature: handBitStringSignature(crlBytes, sigChild),
    };
}

interface HandCrlInfo {
    listsSerial: boolean;
    isDelta: boolean;
    thisUpdate: number;
    nextUpdate: number | undefined;
}

/** Scans a CRL for a serial listing, delta marker, and freshness times. */
function handCrlInfo(crlBytes: Uint8Array, serialBytes: Uint8Array): HandCrlInfo {
    const outer = readDerNode(crlBytes, 0);
    const tbsNode = derChildren(crlBytes, outer)[0]?.node;
    if (tbsNode === undefined) throw new Error("hand DER: missing TBSCertList");
    const tbsKids = derChildren(crlBytes, tbsNode);
    let listsSerial = false;
    let isDelta = false;
    const times: number[] = [];
    for (const { node } of tbsKids) {
        if (node.tagClass === 0 && (node.tagNumber === 23 || node.tagNumber === 24)) {
            times.push(handParseTime(crlBytes, node));
        }
        if (node.tagClass === 0 && node.tagNumber === 16 && node.constructed) {
            for (const entry of derChildren(crlBytes, node)) {
                if (
                    entry.node.tagClass !== 0 ||
                    entry.node.tagNumber !== 16 ||
                    !entry.node.constructed
                ) {
                    continue;
                }
                const serialNode = derChildren(crlBytes, entry.node)[0]?.node;
                if (
                    serialNode?.tagClass !== 0 ||
                    serialNode.tagNumber !== 2 ||
                    serialNode.constructed
                ) {
                    continue;
                }
                const candidate = nodeBytes(crlBytes, serialNode);
                if (
                    candidate.length === serialBytes.length &&
                    candidate.every((byte, index) => byte === serialBytes[index])
                ) {
                    listsSerial = true;
                }
            }
        }
        if (node.tagClass === 2 && node.tagNumber === 0 && node.constructed) {
            const extensions = derChildren(crlBytes, node)[0]?.node;
            if (extensions === undefined) throw new Error("hand DER: CRL extensions shape");
            for (const extension of derChildren(crlBytes, extensions)) {
                const oidNode = derChildren(crlBytes, extension.node)[0]?.node;
                if (oidNode === undefined) throw new Error("hand DER: CRL extension shape");
                if (oidBytesToString(nodeBytes(crlBytes, oidNode)) === DELTA_CRL_OID) {
                    isDelta = true;
                }
            }
        }
    }
    const thisUpdate = times[0];
    if (thisUpdate === undefined) throw new Error("hand DER: CRL has no thisUpdate");
    return { listsSerial, isDelta, thisUpdate, nextUpdate: times[1] };
}

function nodeTbsVerifies(envelope: SignedEnvelope, issuerKey: KeyObject): boolean {
    if (envelope.signatureAlgorithmOid !== RSA_SHA256_OID) return false;
    try {
        return nodeVerify("RSA-SHA256", envelope.tbs, issuerKey, envelope.signature);
    } catch {
        return false;
    }
}

function windowFresh(thisUpdate: number, nextUpdate: number | undefined, checkMs: number): boolean {
    if (thisUpdate > checkMs + SKEW_MS) return false;
    if (nextUpdate !== undefined) return nextUpdate >= checkMs - SKEW_MS;
    return checkMs - thisUpdate <= MAX_AGE_MS;
}

/**
 * Independent per-source OCSP status: hand-rolled parse, node:crypto TBS
 * verification, literal freshness bounds. Any failure yields "unknown";
 * only an authenticated fresh good/revoked is decisive.
 */
function independentOcspStatus(
    responseBytes: Uint8Array | null,
    issuerKey: KeyObject,
    checkMs: number
): RevocationStatus {
    if (responseBytes === null) return "unknown";
    try {
        const envelope = handOcspEnvelope(responseBytes);
        if (!nodeTbsVerifies(envelope, issuerKey)) return "unknown";
        const single = handFirstSingleResponse(envelope.basicBytes);
        if (single.producedAt > checkMs + SKEW_MS) return "unknown";
        if (!windowFresh(single.thisUpdate, single.nextUpdate, checkMs)) return "unknown";
        return single.certStatus;
    } catch {
        return "unknown";
    }
}

/** Independent per-source CRL status, same oracle discipline as OCSP. */
function independentCrlStatus(
    crlBytes: Uint8Array | null,
    issuerKey: KeyObject,
    serialBytes: Uint8Array,
    checkMs: number
): RevocationStatus {
    if (crlBytes === null) return "unknown";
    try {
        const envelope = handCrlEnvelope(crlBytes);
        if (!nodeTbsVerifies(envelope, issuerKey)) return "unknown";
        const info = handCrlInfo(crlBytes, serialBytes);
        if (info.isDelta) return "unknown";
        if (!windowFresh(info.thisUpdate, info.nextUpdate, checkMs)) return "unknown";
        return info.listsSerial ? "revoked" : "good";
    } catch {
        return "unknown";
    }
}

// ---------------------------------------------------------------------------
// Cached PKI + evidence (generated ONCE per file in beforeAll).
// ---------------------------------------------------------------------------

interface PropertyPki {
    ca1: TestCertificateAuthority;
    ca2SameName: TestCertificateAuthority;
    ca3Other: TestCertificateAuthority;
    leaf: TestLeaf;
    ca1Key: KeyObject;
    ca2Key: KeyObject;
    leafSerialBytes: Uint8Array;
    crlClean: Uint8Array;
    crlRevoked: Uint8Array;
    crlCorrupt: Uint8Array;
    goldenOcspGood: Uint8Array;
}

let PKI: PropertyPki | undefined;

function pki(): PropertyPki {
    if (PKI === undefined) throw new Error("property PKI is not built");
    return PKI;
}

function spkiKeyOf(cert: pkijs.Certificate): KeyObject {
    const spki = Buffer.from(cert.subjectPublicKeyInfo.toSchema().toBER(false));
    return createPublicKey({ key: spki, format: "der", type: "spki" });
}

function certificateDer(cert: pkijs.Certificate): Uint8Array {
    return new Uint8Array(cert.toSchema(true).toBER(false));
}

// ---------------------------------------------------------------------------
// Property A: cache separation against a reference model.
// ---------------------------------------------------------------------------

const cacheUrlArb = fc.constantFrom(
    "http://ocsp.example.com/",
    "http://ocsp.example.com/2",
    "http://crl.example.com/ca.crl",
    "http://crl.example.com/ca.crl/",
    "http://x.example.com/a",
    "http://x.example.com/a/b"
);
const cacheReqArb = fc.uint8Array({ minLength: 1, maxLength: 24 });
const cacheRespArb = fc.uint8Array({ minLength: 0, maxLength: 64 });

const cacheOpArb = fc.oneof(
    fc.record({
        op: fc.constant("setOCSP"),
        url: cacheUrlArb,
        req: cacheReqArb,
        resp: cacheRespArb,
    }),
    fc.record({ op: fc.constant("getOCSP"), url: cacheUrlArb, req: cacheReqArb }),
    fc.record({ op: fc.constant("setCRL"), url: cacheUrlArb, resp: cacheRespArb }),
    fc.record({ op: fc.constant("getCRL"), url: cacheUrlArb }),
    fc.record({ op: fc.constant("clear") })
);

function modelKey(kind: string, url: string, reqHex: string): string {
    return `${kind}|${url.length.toString(10)}|${url}|${reqHex}`;
}

function bytesToHex(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("hex");
}

// ---------------------------------------------------------------------------
// Properties B + C: issuer identity and the fallback state model.
// ---------------------------------------------------------------------------

const issuerModeArb = fc.constantFrom(
    "explicit-correct",
    "explicit-wrong-samename",
    "explicit-wrong-other",
    "none"
) as fc.Arbitrary<"explicit-correct" | "explicit-wrong-samename" | "explicit-wrong-other" | "none">;
const identityEvidenceArb = fc.constantFrom(
    "ocsp-ca1",
    "crl-ca1",
    "ocsp-wrongkey",
    "none"
) as fc.Arbitrary<"ocsp-ca1" | "crl-ca1" | "ocsp-wrongkey" | "none">;

const identityArb = fc.record({ issuerMode: issuerModeArb, evidence: identityEvidenceArb });

const fallbackOcspArb = fc.constantFrom("good", "revoked", "corrupt", "missing") as fc.Arbitrary<
    "good" | "revoked" | "corrupt" | "missing"
>;
const fallbackCrlArb = fc.constantFrom("clean", "revoked", "corrupt", "missing") as fc.Arbitrary<
    "clean" | "revoked" | "corrupt" | "missing"
>;

const fallbackArb = fc.record({
    preferOCSP: fc.boolean(),
    ocsp: fallbackOcspArb,
    crl: fallbackCrlArb,
});

interface CaseFetcher extends RevocationDataFetcher {
    ocspCalls: number;
    crlCalls: number;
    servedOcsp: Uint8Array | null;
    servedCrl: Uint8Array | null;
}

type OcspPlan =
    | { mode: "echo"; status: "good" | "revoked"; signerKeys: TestKeyPair; corrupt: boolean }
    | { mode: "missing" };
type CrlPlan = { mode: "bytes"; bytes: Uint8Array } | { mode: "missing" };

function planFetcher(ocspPlan: OcspPlan, crlPlan: CrlPlan): CaseFetcher {
    const state = pki();
    const fetcher: CaseFetcher = {
        ocspCalls: 0,
        crlCalls: 0,
        servedOcsp: null,
        servedCrl: null,
        fetchOCSP: async (_url: string, request: Uint8Array): Promise<Uint8Array> => {
            fetcher.ocspCalls += 1;
            if (ocspPlan.mode === "missing") throw new Error("no OCSP response");
            const inspected = inspectOCSPRequest(request);
            const requestNonce = inspected.nonces[0] ?? undefined;
            let built = await createSignedOCSPResponse(state.ca1.cert, {
                signerKeys: ocspPlan.signerKeys,
                producedAt: PRODUCED_AT,
                responses: [
                    {
                        cert: state.leaf.cert,
                        issuer: state.ca1.cert,
                        status: ocspPlan.status,
                        thisUpdate: THIS_UPDATE,
                        nextUpdate: NEXT_UPDATE,
                    },
                ],
                ...(requestNonce === undefined ? {} : { nonceEcho: requestNonce }),
                certs: [],
            });
            if (ocspPlan.corrupt) {
                const corrupted = corruptResponseSignature(built);
                built = corrupted;
            }
            fetcher.servedOcsp = built;
            return built;
        },
        fetchCRL: async (): Promise<Uint8Array> => {
            fetcher.crlCalls += 1;
            if (crlPlan.mode === "missing") throw new Error("no CRL response");
            fetcher.servedCrl = crlPlan.bytes;
            return crlPlan.bytes;
        },
    };
    return fetcher;
}

describe("revocation state properties (T14)", () => {
    beforeAll(async () => {
        const ca1 = await createTestCA("Property CA 1");
        const ca2SameName = await createTestCA("Property CA 1");
        const ca3Other = await createTestCA("Property CA 3");
        const leaf = await createTestLeaf(ca1, {
            commonName: "Property Leaf",
            serial: LEAF_SERIAL,
            ocspUrl: OCSP_URL,
            crlUrls: [CRL_URL],
        });
        const crlClean = await createSignedCRL(ca1, {
            thisUpdate: THIS_UPDATE,
            nextUpdate: NEXT_UPDATE,
        });
        const crlRevoked = await createSignedCRL(ca1, {
            thisUpdate: THIS_UPDATE,
            nextUpdate: NEXT_UPDATE,
            entries: [{ serial: LEAF_SERIAL }],
        });
        const crlCorrupt = corruptCRLSignature(crlClean);
        const goldenOcspGood = await createSignedOCSPResponse(ca1.cert, {
            signerKeys: ca1.keys,
            producedAt: PRODUCED_AT,
            responses: [
                {
                    cert: leaf.cert,
                    issuer: ca1.cert,
                    status: "good",
                    thisUpdate: THIS_UPDATE,
                    nextUpdate: NEXT_UPDATE,
                },
            ],
            certs: [],
        });
        const serialView = leaf.cert.serialNumber.valueBlock.valueHexView;
        PKI = {
            ca1,
            ca2SameName,
            ca3Other,
            leaf,
            ca1Key: spkiKeyOf(ca1.cert),
            ca2Key: spkiKeyOf(ca2SameName.cert),
            leafSerialBytes: new Uint8Array(serialView),
            crlClean,
            crlRevoked,
            crlCorrupt,
            goldenOcspGood,
        };
    }, 120000);

    it("separates cache entries exactly like the reference model", () => {
        let hits = 0;
        let misses = 0;
        let clears = 0;
        let sets = 0;

        fc.assert(
            fc.property(fc.array(cacheOpArb, { minLength: 1, maxLength: 25 }), (ops) => {
                const cache = new InMemoryValidationCache();
                const model = new Map<string, Uint8Array>();
                for (const op of ops) {
                    if (op.op === "clear") {
                        clears += 1;
                        cache.clear();
                        model.clear();
                    } else if (op.op === "setOCSP") {
                        sets += 1;
                        cache.setOCSP(op.url, op.req, op.resp);
                        model.set(
                            modelKey("ocsp", op.url, bytesToHex(op.req)),
                            new Uint8Array(op.resp)
                        );
                        // Poison the inputs: the cache must have copied.
                        op.req.fill(0xaa);
                        op.resp.fill(0xaa);
                    } else if (op.op === "setCRL") {
                        sets += 1;
                        cache.setCRL(op.url, op.resp);
                        model.set(modelKey("crl", op.url, ""), new Uint8Array(op.resp));
                        op.resp.fill(0xaa);
                    } else if (op.op === "getOCSP") {
                        const key = modelKey("ocsp", op.url, bytesToHex(op.req));
                        const expected = model.get(key) ?? null;
                        const actual = cache.getOCSP(op.url, op.req);
                        if (expected === null) {
                            misses += 1;
                            expect(actual).toBeNull();
                        } else {
                            hits += 1;
                            expect(actual).not.toBeNull();
                            expect(actual).toEqual(expected);
                        }
                        // Poison the request and any returned bytes: later
                        // gets must be unaffected (copy on retrieval).
                        op.req.fill(0xbb);
                        actual?.fill(0xbb);
                    } else {
                        const key = modelKey("crl", op.url, "");
                        const expected = model.get(key) ?? null;
                        const actual = cache.getCRL(op.url);
                        if (expected === null) {
                            misses += 1;
                            expect(actual).toBeNull();
                        } else {
                            hits += 1;
                            expect(actual).not.toBeNull();
                            expect(actual).toEqual(expected);
                        }
                        actual?.fill(0xbb);
                    }
                }
            }),
            { seed: SEED_RS_CACHE, numRuns: CACHE_RUNS }
        );

        // No vacuous replay: hits, misses, clears, and stores must occur.
        expect(sets).toBeGreaterThan(0);
        expect(hits).toBeGreaterThan(0);
        expect(misses).toBeGreaterThan(0);
        expect(clears).toBeGreaterThan(0);
    });

    it("binds revocation verdicts to the verified issuing key", async () => {
        const state = pki();
        const seenCombos = new Set<string>();
        const checkMs = CHECK_DATE.getTime();

        await fc.assert(
            fc.asyncProperty(identityArb, async (input) => {
                seenCombos.add(`${input.issuerMode}|${input.evidence}`);
                const issuer =
                    input.issuerMode === "explicit-correct"
                        ? state.ca1.cert
                        : input.issuerMode === "explicit-wrong-samename"
                          ? state.ca2SameName.cert
                          : input.issuerMode === "explicit-wrong-other"
                            ? state.ca3Other.cert
                            : undefined;
                const ocspPlan: OcspPlan =
                    input.evidence === "ocsp-ca1"
                        ? {
                              mode: "echo",
                              status: "good",
                              signerKeys: state.ca1.keys,
                              corrupt: false,
                          }
                        : input.evidence === "ocsp-wrongkey"
                          ? {
                                mode: "echo",
                                status: "good",
                                signerKeys: state.ca2SameName.keys,
                                corrupt: false,
                            }
                          : { mode: "missing" };
                const crlPlan: CrlPlan =
                    input.evidence === "crl-ca1"
                        ? { mode: "bytes", bytes: state.crlClean }
                        : { mode: "missing" };
                const fetcher = planFetcher(ocspPlan, crlPlan);
                const session = new ValidationSession({
                    fetcher,
                    checkDate: CHECK_DATE,
                    clockSkewMs: SKEW_MS,
                    maxAgeWithoutNextUpdateMs: MAX_AGE_MS,
                });
                session.queueCertificate(state.leaf.cert, issuer === undefined ? {} : { issuer });
                const [result] = await session.validateAll();
                if (result === undefined) throw new Error("session returned no result");

                // Independent ground truth: evidence authentic under the
                // true issuing key AND issuer byte-identical to the CA.
                // With a rejected issuer the evidence is never even
                // fetched, so authenticity is grounded on served bytes.
                let evidenceAuthentic = false;
                if (input.evidence === "ocsp-ca1" || input.evidence === "ocsp-wrongkey") {
                    const served = fetcher.servedOcsp;
                    if (served !== null) {
                        evidenceAuthentic =
                            independentOcspStatus(served, state.ca1Key, checkMs) === "good";
                    }
                    if (input.issuerMode === "explicit-correct") {
                        expect(served).not.toBeNull();
                    } else {
                        expect(served).toBeNull();
                        expect(fetcher.ocspCalls).toBe(0);
                    }
                    if (input.evidence === "ocsp-wrongkey" && served !== null) {
                        // Well-formed but wrong-key: verifies under CA2, so
                        // the unknown verdict is key binding, not breakage.
                        expect(evidenceAuthentic).toBe(false);
                        expect(independentOcspStatus(served, state.ca2Key, checkMs)).toBe("good");
                    }
                    if (input.evidence === "ocsp-ca1" && served !== null) {
                        expect(evidenceAuthentic).toBe(true);
                    }
                } else if (input.evidence === "crl-ca1") {
                    evidenceAuthentic =
                        independentCrlStatus(
                            state.crlClean,
                            state.ca1Key,
                            state.leafSerialBytes,
                            checkMs
                        ) === "good";
                    expect(evidenceAuthentic).toBe(true);
                }
                const issuerIsCa1 =
                    issuer !== undefined &&
                    Buffer.from(certificateDer(issuer)).equals(
                        Buffer.from(certificateDer(state.ca1.cert))
                    );
                const expected: RevocationStatus =
                    evidenceAuthentic && issuerIsCa1 ? "good" : "unknown";

                expect(result.revocationStatus).toBe(expected);
                expect(result.revocationStatus).not.toBe("revoked");
                expect(result.isValid).toBe(expected === "good");

                // Attempt-order spot checks for the decisive-stop rule.
                if (input.issuerMode === "explicit-correct" && input.evidence === "ocsp-ca1") {
                    expect(fetcher.ocspCalls).toBe(1);
                    expect(fetcher.crlCalls).toBe(0);
                }
                if (input.issuerMode === "explicit-correct" && input.evidence === "crl-ca1") {
                    expect(fetcher.ocspCalls).toBe(1);
                    expect(fetcher.crlCalls).toBe(1);
                }
                if (input.issuerMode !== "explicit-correct") {
                    // OCSP needs the issuer to build its request, so a
                    // rejected issuer means no OCSP attempt; CRL bytes are
                    // still collected (T05 preservation) but never decisive.
                    expect(fetcher.ocspCalls).toBe(0);
                    expect(fetcher.crlCalls).toBe(1);
                }
            }),
            { seed: SEED_RS_ISSUER, numRuns: ISSUER_RUNS }
        );

        // All 16 issuer/evidence combinations must execute.
        expect(seenCombos.size).toBe(16);
    }, 120000);

    it("walks the complete OCSP/CRL fallback state model", async () => {
        const state = pki();
        const seenCombos = new Set<string>();
        const servedLabels = new Set<string>();
        const attemptedMissing = new Set<string>();
        const checkMs = CHECK_DATE.getTime();

        await fc.assert(
            fc.asyncProperty(fallbackArb, async (input) => {
                seenCombos.add(
                    `${input.preferOCSP ? "ocsp-first" : "crl-first"}|${input.ocsp}|${input.crl}`
                );
                const ocspPlan: OcspPlan =
                    input.ocsp === "missing"
                        ? { mode: "missing" }
                        : {
                              mode: "echo",
                              status: input.ocsp === "revoked" ? "revoked" : "good",
                              signerKeys: state.ca1.keys,
                              corrupt: input.ocsp === "corrupt",
                          };
                const crlPlan: CrlPlan =
                    input.crl === "missing"
                        ? { mode: "missing" }
                        : {
                              mode: "bytes",
                              bytes:
                                  input.crl === "clean"
                                      ? state.crlClean
                                      : input.crl === "revoked"
                                        ? state.crlRevoked
                                        : state.crlCorrupt,
                          };
                const fetcher = planFetcher(ocspPlan, crlPlan);
                const session = new ValidationSession({
                    fetcher,
                    preferOCSP: input.preferOCSP,
                    checkDate: CHECK_DATE,
                    clockSkewMs: SKEW_MS,
                    maxAgeWithoutNextUpdateMs: MAX_AGE_MS,
                });
                session.queueCertificate(state.leaf.cert, { issuer: state.ca1.cert });
                const [result] = await session.validateAll();
                if (result === undefined) throw new Error("session returned no result");

                // Independent per-source statuses from the SERVED bytes
                // (hand parse + node:crypto TBS verification), never from
                // the combo labels.
                const ocspStatus = independentOcspStatus(fetcher.servedOcsp, state.ca1Key, checkMs);
                const crlStatus = independentCrlStatus(
                    fetcher.servedCrl,
                    state.ca1Key,
                    state.leafSerialBytes,
                    checkMs
                );
                // Served bytes must encode what the labels claim, or
                // the matrix below compares against fiction. A source the
                // walk never reached serves nothing and reads unknown.
                if (fetcher.servedOcsp !== null) {
                    servedLabels.add(`ocsp:${input.ocsp}`);
                    expect(ocspStatus).toBe(
                        input.ocsp === "good"
                            ? "good"
                            : input.ocsp === "revoked"
                              ? "revoked"
                              : "unknown"
                    );
                } else {
                    expect(ocspStatus).toBe("unknown");
                    if (input.ocsp === "missing" && fetcher.ocspCalls > 0) {
                        attemptedMissing.add("ocsp:missing");
                    }
                }
                if (fetcher.servedCrl !== null) {
                    servedLabels.add(`crl:${input.crl}`);
                    expect(crlStatus).toBe(
                        input.crl === "clean"
                            ? "good"
                            : input.crl === "revoked"
                              ? "revoked"
                              : "unknown"
                    );
                } else {
                    expect(crlStatus).toBe("unknown");
                    if (input.crl === "missing" && fetcher.crlCalls > 0) {
                        attemptedMissing.add("crl:missing");
                    }
                }

                const order: ("OCSP" | "CRL")[] = input.preferOCSP
                    ? ["OCSP", "CRL"]
                    : ["CRL", "OCSP"];
                const firstStatus = input.preferOCSP ? ocspStatus : crlStatus;
                const secondStatus = input.preferOCSP ? crlStatus : ocspStatus;
                const firstDecisive = firstStatus === "good" || firstStatus === "revoked";
                const expected: RevocationStatus = firstDecisive ? firstStatus : secondStatus;

                expect(result.revocationStatus).toBe(expected);
                expect(result.isValid).toBe(expected === "good");

                // Attempt order: the first source is always tried; the
                // second only when the first is non-decisive.
                const firstCalls = input.preferOCSP ? fetcher.ocspCalls : fetcher.crlCalls;
                const secondCalls = input.preferOCSP ? fetcher.crlCalls : fetcher.ocspCalls;
                expect(firstCalls).toBe(1);
                expect(secondCalls).toBe(firstDecisive ? 0 : 1);

                // Sources record collected bytes in attempt order: served
                // bytes (even corrupt) appear, outages do not.
                const expectedSources = order.filter((source) =>
                    source === "OCSP" ? fetcher.servedOcsp !== null : fetcher.servedCrl !== null
                );
                expect(result.sources).toEqual(expectedSources);
            }),
            { seed: SEED_RS_FALLBACK, numRuns: FALLBACK_RUNS }
        );

        // The complete model: 2 orders x 4 OCSP states x 4 CRL states.
        // Every byte-label is served as real bytes at least once, and
        // both outage labels are attempted-and-rejected at least once.
        expect(seenCombos.size).toBe(32);
        expect([...servedLabels].sort()).toEqual([
            "crl:clean",
            "crl:corrupt",
            "crl:revoked",
            "ocsp:corrupt",
            "ocsp:good",
            "ocsp:revoked",
        ]);
        expect([...attemptedMissing].sort()).toEqual(["crl:missing", "ocsp:missing"]);
    }, 180000);

    it("reads real openssl CRL bytes with the independent oracle", async () => {
        const parseInterop = (base64: string): pkijs.Certificate => {
            const der = decodeInteropDer(base64);
            const parsed = asn1js.fromBER(toArrayBuffer(der.slice()));
            if (parsed.offset === -1) throw new Error("interop bytes are not DER");
            return new pkijs.Certificate({ schema: parsed.result });
        };
        const ca = parseInterop(OPENSSL_INTEROP_CA_BASE64);
        const leaf = parseInterop(OPENSSL_INTEROP_LEAF_BASE64);
        const caKey = spkiKeyOf(ca);
        const serialBytes = new Uint8Array(leaf.serialNumber.valueBlock.valueHexView);
        // Fixed inside the interop CRL validity window (deterministic
        // until 2126); matches the deterministic interop suite's date.
        const checkMs = new Date("2026-10-03T00:00:00Z").getTime();

        // The hand oracle agrees with the deterministic suite's
        // validateCRLEvidence verdicts on real openssl 3.5.5 bytes.
        expect(
            independentCrlStatus(
                decodeInteropDer(OPENSSL_INTEROP_REVOKED_CRL_BASE64),
                caKey,
                serialBytes,
                checkMs
            )
        ).toBe("revoked");
        expect(
            independentCrlStatus(
                decodeInteropDer(OPENSSL_INTEROP_EMPTY_CRL_BASE64),
                caKey,
                serialBytes,
                checkMs
            )
        ).toBe("good");
    });

    it("pins the oracle's own rejection legs (stale, corrupt)", () => {
        const state = pki();
        const checkMs = CHECK_DATE.getTime();
        const staleMs = checkMs + 60 * 24 * 60 * 60 * 1000;

        // Fresh evidence reads decisive.
        expect(independentOcspStatus(state.goldenOcspGood, state.ca1Key, checkMs)).toBe("good");
        expect(
            independentCrlStatus(state.crlClean, state.ca1Key, state.leafSerialBytes, checkMs)
        ).toBe("good");
        expect(
            independentCrlStatus(state.crlRevoked, state.ca1Key, state.leafSerialBytes, checkMs)
        ).toBe("revoked");

        // Stale evidence is non-decisive (freshness leg is not dead code).
        expect(independentOcspStatus(state.goldenOcspGood, state.ca1Key, staleMs)).toBe("unknown");
        expect(
            independentCrlStatus(state.crlClean, state.ca1Key, state.leafSerialBytes, staleMs)
        ).toBe("unknown");

        // Corrupt evidence is non-decisive (authenticity leg is real).
        expect(
            independentCrlStatus(state.crlCorrupt, state.ca1Key, state.leafSerialBytes, checkMs)
        ).toBe("unknown");
        // Wrong-key evidence fails the true key and passes its own.
        expect(
            independentCrlStatus(state.crlClean, state.ca2Key, state.leafSerialBytes, checkMs)
        ).toBe("unknown");
    });
});
