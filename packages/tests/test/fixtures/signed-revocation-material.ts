import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { toArrayBuffer } from "../../../core/src/utils.js";
import { generateRSAKeyPair, importKeyForCertificate } from "../utils/crypto.js";

// T06: independently signed revocation fixtures. Every certificate and OCSP
// response here carries real keys and real signatures, serialized through
// DER. Nothing in this file mocks a verdict parser: the responses are
// verifiable without the library's own validators (see the T06 report for
// the openssl / raw-WebCrypto receipts).
//
// The intentionally bogus structural fixtures in revocation-material.ts are
// kept for collector tests; the builders below are for authentication.

// ---------------------------------------------------------------------------
// Keys and certificates
// ---------------------------------------------------------------------------

export interface TestKeyPair {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
}

export async function generateECKeyPair(): Promise<TestKeyPair> {
    const pair = await globalThis.crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
    );
    return { publicKey: pair.publicKey, privateKey: pair.privateKey };
}

export function distinguishedName(commonName: string): pkijs.RelativeDistinguishedNames {
    const name = new pkijs.RelativeDistinguishedNames();
    name.typesAndValues.push(
        new pkijs.AttributeTypeAndValue({
            type: "2.5.4.3",
            value: new asn1js.PrintableString({ value: commonName }),
        })
    );
    return name;
}

export function roundTripCertificate(cert: pkijs.Certificate): pkijs.Certificate {
    const der = new Uint8Array(cert.toSchema(true).toBER(false));
    const asn1 = asn1js.fromBER(toArrayBuffer(der));
    if (asn1.offset === -1) throw new Error("test certificate is not DER");
    return new pkijs.Certificate({ schema: asn1.result });
}

function skiExtension(keyId: Uint8Array): pkijs.Extension {
    return new pkijs.Extension({
        extnID: "2.5.29.14",
        critical: false,
        extnValue: new asn1js.OctetString({ valueHex: toArrayBuffer(keyId) }).toBER(false),
    });
}

function akiExtension(keyId: Uint8Array): pkijs.Extension {
    const aki = new pkijs.AuthorityKeyIdentifier({
        keyIdentifier: new asn1js.OctetString({ valueHex: toArrayBuffer(keyId) }),
    });
    return new pkijs.Extension({
        extnID: "2.5.29.35",
        critical: false,
        extnValue: aki.toSchema().toBER(false),
    });
}

/** Key usage extension from raw content bytes (bit 0 of byte 0 is digitalSignature). */
export function keyUsageExtension(content: Uint8Array, critical = true): pkijs.Extension {
    return new pkijs.Extension({
        extnID: "2.5.29.15",
        critical,
        extnValue: new asn1js.BitString({ valueHex: toArrayBuffer(content) }).toBER(false),
    });
}

export function extendedKeyUsageExtension(oids: string[], critical = false): pkijs.Extension {
    const sequence = new asn1js.Sequence({
        value: oids.map((oid) => new asn1js.ObjectIdentifier({ value: oid })),
    });
    return new pkijs.Extension({
        extnID: "2.5.29.37",
        critical,
        extnValue: sequence.toBER(false),
    });
}

/** id-pkix-ocsp-nocheck (RFC 6960 4.2.2.2.1): the responder needs no revocation check. */
export function ocspNoCheckExtension(): pkijs.Extension {
    return new pkijs.Extension({
        extnID: "1.3.6.1.5.5.7.48.1.5",
        critical: false,
        extnValue: new asn1js.Null().toBER(false),
    });
}

/** id-pkix-ocsp-nocheck with an attacker-chosen extnValue (must be NULL to pass). */
export function rawNoCheckExtension(extnValueDer: ArrayBuffer, critical = false): pkijs.Extension {
    return new pkijs.Extension({
        extnID: "1.3.6.1.5.5.7.48.1.5",
        critical,
        extnValue: extnValueDer,
    });
}

/** Key usage with an attacker-chosen extnValue (must be a canonical BIT STRING). */
export function rawKeyUsageExtension(extnValueDer: ArrayBuffer, critical = true): pkijs.Extension {
    return new pkijs.Extension({
        extnID: "2.5.29.15",
        critical,
        extnValue: extnValueDer,
    });
}

/** Extended key usage with an attacker-chosen extnValue (must be a clean OID sequence). */
export function rawEkuExtension(extnValueDer: ArrayBuffer, critical = false): pkijs.Extension {
    return new pkijs.Extension({
        extnID: "2.5.29.37",
        critical,
        extnValue: extnValueDer,
    });
}

/** An extension OID the OCSP profile does not recognize (criticality is the test knob). */
export function unknownExtension(oid: string, critical: boolean): pkijs.Extension {
    return new pkijs.Extension({
        extnID: oid,
        critical,
        extnValue: new asn1js.OctetString({ valueHex: new Uint8Array([0x01]).buffer }).toBER(false),
    });
}

function crlDistributionPointsExtension(crlUrls: string[]): pkijs.Extension {
    const cdp = new pkijs.CRLDistributionPoints({
        distributionPoints: crlUrls.map(
            (crlUrl) =>
                new pkijs.DistributionPoint({
                    distributionPoint: [new pkijs.GeneralName({ type: 6, value: crlUrl })],
                })
        ),
    });
    return new pkijs.Extension({
        extnID: "2.5.29.31",
        critical: false,
        extnValue: cdp.toSchema().toBER(false),
    });
}

function ocspAiaExtension(ocspUrl: string): pkijs.Extension {
    const aia = new pkijs.InfoAccess({
        accessDescriptions: [
            new pkijs.AccessDescription({
                accessMethod: "1.3.6.1.5.5.7.48.1",
                accessLocation: new pkijs.GeneralName({ type: 6, value: ocspUrl }),
            }),
        ],
    });
    return new pkijs.Extension({
        extnID: "1.3.6.1.5.5.7.1.1",
        critical: false,
        extnValue: aia.toSchema().toBER(false),
    });
}

export interface TestCertificateAuthority {
    cert: pkijs.Certificate;
    keys: TestKeyPair;
}

export async function createTestCA(
    commonName: string,
    options: {
        serial?: number;
        keys?: TestKeyPair;
        notBefore?: Date;
        notAfter?: Date;
        ski?: Uint8Array;
    } = {}
): Promise<TestCertificateAuthority> {
    const keys = options.keys ?? (await generateRSAKeyPair());
    const cert = new pkijs.Certificate();
    cert.version = 2;
    cert.serialNumber = new asn1js.Integer({ value: options.serial ?? 1001 });
    cert.subject = distinguishedName(commonName);
    cert.issuer = distinguishedName(commonName);
    cert.notBefore = new pkijs.Time({
        value: options.notBefore ?? new Date("2020-01-01T00:00:00Z"),
    });
    cert.notAfter = new pkijs.Time({ value: options.notAfter ?? new Date("2030-01-01T00:00:00Z") });
    cert.subjectPublicKeyInfo = await importKeyForCertificate(keys.publicKey);
    const extensions: pkijs.Extension[] = [
        new pkijs.Extension({
            extnID: "2.5.29.19",
            critical: true,
            extnValue: new pkijs.BasicConstraints({ cA: true }).toSchema().toBER(false),
        }),
    ];
    if (options.ski) extensions.push(skiExtension(options.ski));
    cert.extensions = extensions;
    await cert.sign(keys.privateKey, "SHA-256");
    return { cert: roundTripCertificate(cert), keys };
}

export interface TestLeaf {
    cert: pkijs.Certificate;
    keys: TestKeyPair;
}

export async function createTestLeaf(
    issuer: TestCertificateAuthority,
    options: {
        commonName?: string;
        serial?: number;
        keys?: TestKeyPair;
        ocspUrl?: string;
        crlUrls?: string[];
        aki?: Uint8Array;
        notBefore?: Date;
        notAfter?: Date;
    } = {}
): Promise<TestLeaf> {
    const keys = options.keys ?? (await generateRSAKeyPair());
    const cert = new pkijs.Certificate();
    cert.version = 2;
    cert.serialNumber = new asn1js.Integer({ value: options.serial ?? 2001 });
    cert.subject = distinguishedName(options.commonName ?? "T06 Leaf");
    cert.issuer = issuer.cert.subject;
    cert.notBefore = new pkijs.Time({
        value: options.notBefore ?? new Date("2020-01-01T00:00:00Z"),
    });
    cert.notAfter = new pkijs.Time({ value: options.notAfter ?? new Date("2030-01-01T00:00:00Z") });
    cert.subjectPublicKeyInfo = await importKeyForCertificate(keys.publicKey);
    const extensions: pkijs.Extension[] = [];
    if (options.aki) extensions.push(akiExtension(options.aki));
    if (options.ocspUrl) extensions.push(ocspAiaExtension(options.ocspUrl));
    if (options.crlUrls && options.crlUrls.length > 0) {
        extensions.push(crlDistributionPointsExtension(options.crlUrls));
    }
    if (extensions.length > 0) cert.extensions = extensions;
    await cert.sign(issuer.keys.privateKey, "SHA-256");
    return { cert: roundTripCertificate(cert), keys };
}

export interface TestResponder {
    cert: pkijs.Certificate;
    keys: TestKeyPair;
}

/**
 * Builds a delegated OCSP responder certificate issued by the CA. Defaults
 * describe a fully authorized delegate (digitalSignature KU, OCSPSigning
 * EKU, nocheck); each knob can be turned to build a negative fixture.
 */
export async function createDelegateResponder(
    issuer: TestCertificateAuthority,
    options: {
        commonName?: string;
        serial?: number;
        keys?: TestKeyPair;
        keyUsage?: Uint8Array | null;
        eku?: string[] | null;
        notBefore?: Date;
        notAfter?: Date;
        nocheck?: boolean;
        extraExtensions?: pkijs.Extension[];
    } = {}
): Promise<TestResponder> {
    const keys = options.keys ?? (await generateECKeyPair());
    const cert = new pkijs.Certificate();
    cert.version = 2;
    cert.serialNumber = new asn1js.Integer({ value: options.serial ?? 3001 });
    cert.subject = distinguishedName(options.commonName ?? "T06 OCSP Responder");
    cert.issuer = issuer.cert.subject;
    cert.notBefore = new pkijs.Time({
        value: options.notBefore ?? new Date("2020-01-01T00:00:00Z"),
    });
    cert.notAfter = new pkijs.Time({ value: options.notAfter ?? new Date("2030-01-01T00:00:00Z") });
    cert.subjectPublicKeyInfo = await importKeyForCertificate(keys.publicKey);
    const extensions: pkijs.Extension[] = [];
    const keyUsage = options.keyUsage === undefined ? new Uint8Array([0x80]) : options.keyUsage;
    if (keyUsage !== null) extensions.push(keyUsageExtension(keyUsage));
    const eku = options.eku === undefined ? ["1.3.6.1.5.5.7.3.9"] : options.eku;
    if (eku !== null) extensions.push(extendedKeyUsageExtension(eku));
    if (options.nocheck !== false) extensions.push(ocspNoCheckExtension());
    for (const extra of options.extraExtensions ?? []) extensions.push(extra);
    cert.extensions = extensions;
    await cert.sign(issuer.keys.privateKey, "SHA-256");
    return { cert: roundTripCertificate(cert), keys };
}

// ---------------------------------------------------------------------------
// Signed OCSP responses
// ---------------------------------------------------------------------------

export type OcspFixtureStatus = "good" | "revoked" | "unknown";

export interface OcspSingleResponseSpec {
    cert: pkijs.Certificate;
    issuer: pkijs.Certificate;
    status: OcspFixtureStatus;
    thisUpdate: Date;
    nextUpdate?: Date;
    revocationTime?: Date;
    /** CRLReason value for a valid revoked status; omitted when undefined. */
    revocationReason?: number;
    /**
     * Raw certStatus block for malformed-grammar probes; overrides
     * status/revocationTime/revocationReason. pkijs re-emits the block
     * verbatim, so the response is genuinely signed over these bytes.
     */
    certStatusOverride?: asn1js.BaseBlock;
    singleExtensions?: pkijs.Extension[];
}

export interface OcspResponderIdSpec {
    /** "byName" matches the responder certificate subject, "byKey" its SHA-1 key hash. */
    form: "byName" | "byKey";
    /** Defaults to the signing certificate; override to build a wrong-ResponderID fixture. */
    name?: pkijs.RelativeDistinguishedNames;
    keyHash?: Uint8Array;
}

/** RFC 6960 KeyHash: SHA-1 over the subjectPublicKey BIT STRING contents. */
export async function responderKeyHash(cert: pkijs.Certificate): Promise<Uint8Array> {
    const contents = cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView;
    const digest = await globalThis.crypto.subtle.digest("SHA-1", contents.slice(0));
    return new Uint8Array(digest);
}

function certificateStatusBlock(
    status: OcspFixtureStatus,
    revocationTime: Date,
    revocationReason?: number
): asn1js.BaseBlock {
    if (status === "good") {
        return new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 } });
    }
    if (status === "unknown") {
        return new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 2 } });
    }
    const children: asn1js.BaseBlock[] = [
        new asn1js.GeneralizedTime({ valueDate: revocationTime }),
    ];
    if (revocationReason !== undefined) {
        children.push(
            new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 0 },
                value: [new asn1js.Enumerated({ value: revocationReason })],
            })
        );
    }
    return new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 1 },
        value: children,
    });
}

export function nonceExtension(nonce: Uint8Array): pkijs.Extension {
    return new pkijs.Extension({
        extnID: "1.3.6.1.5.5.7.48.1.2",
        critical: false,
        extnValue: new asn1js.OctetString({ valueHex: toArrayBuffer(nonce) }).toBER(false),
    });
}

export interface SignedOCSPResponseOptions {
    /** Key that signs the response (usually the CA or delegate key pair). */
    signerKeys?: TestKeyPair;
    /** Certificate the ResponderID is derived from; defaults to the issuer. */
    responderCert?: pkijs.Certificate;
    responderId?: OcspResponderIdSpec;
    producedAt: Date;
    responses: OcspSingleResponseSpec[];
    /** Exact nonce bytes to echo in responseExtensions; omitted when undefined. */
    nonceEcho?: Uint8Array;
    extraResponseExtensions?: pkijs.Extension[];
    /**
     * Embedded certificates. `undefined` embeds the responder certificate
     * when it differs from the issuer and nothing otherwise (the
     * issuer-direct no-embedded-cert profile); pass an explicit array
     * (possibly empty) to override.
     */
    certs?: pkijs.Certificate[];
    certIdHash?: string;
    /** ResponseData version; omitted (v1) unless a test sets it explicitly. */
    responseVersion?: number;
}

export async function createSignedOCSPResponse(
    issuer: pkijs.Certificate,
    options: SignedOCSPResponseOptions
): Promise<Uint8Array> {
    const responderCert = options.responderCert ?? issuer;
    const idSpec = options.responderId ?? { form: "byName" as const };
    let responderID: pkijs.RelativeDistinguishedNames | asn1js.OctetString;
    if (idSpec.form === "byName") {
        responderID = idSpec.name ?? responderCert.subject;
    } else {
        responderID = new asn1js.OctetString({
            valueHex: toArrayBuffer(idSpec.keyHash ?? (await responderKeyHash(responderCert))),
        });
    }

    const singles: pkijs.SingleResponse[] = [];
    for (const spec of options.responses) {
        const certID = new pkijs.CertID();
        await certID.createForCertificate(spec.cert, {
            hashAlgorithm: options.certIdHash ?? "SHA-1",
            issuerCertificate: spec.issuer,
        });
        singles.push(
            new pkijs.SingleResponse({
                certID,
                certStatus:
                    spec.certStatusOverride ??
                    certificateStatusBlock(
                        spec.status,
                        spec.revocationTime ?? new Date("2024-06-01T00:00:00Z"),
                        spec.revocationReason
                    ),
                thisUpdate: spec.thisUpdate,
                ...(spec.nextUpdate === undefined ? {} : { nextUpdate: spec.nextUpdate }),
                ...(spec.singleExtensions === undefined
                    ? {}
                    : { singleExtensions: spec.singleExtensions }),
            })
        );
    }

    const responseExtensions: pkijs.Extension[] = [...(options.extraResponseExtensions ?? [])];
    if (options.nonceEcho !== undefined) {
        responseExtensions.push(nonceExtension(options.nonceEcho));
    }

    const tbs = new pkijs.ResponseData({
        responderID,
        producedAt: options.producedAt,
        responses: singles,
        ...(responseExtensions.length === 0 ? {} : { responseExtensions }),
        ...(options.responseVersion === undefined ? {} : { version: options.responseVersion }),
    });
    const certs = options.certs ?? (responderCert === issuer ? [] : [responderCert]);
    const basic = new pkijs.BasicOCSPResponse({
        tbsResponseData: tbs,
        ...(certs.length === 0 ? {} : { certs }),
    });
    if (options.signerKeys === undefined) {
        throw new Error(
            "createSignedOCSPResponse needs signerKeys (private keys are not in the DER)"
        );
    }
    await basic.sign(options.signerKeys.privateKey, "SHA-256");

    const response = new pkijs.OCSPResponse({
        responseStatus: new asn1js.Enumerated({ value: 0 }),
        responseBytes: new pkijs.ResponseBytes({
            responseType: "1.3.6.1.5.5.7.48.1.1",
            response: new asn1js.OctetString({
                valueHex: basic.toSchema().toBER(false),
            }),
        }),
    });
    const bytes = new Uint8Array(response.toSchema().toBER(false));
    // Round-trip through DER so construction errors surface here, not in the test.
    const reparsed = asn1js.fromBER(toArrayBuffer(bytes.slice()));
    if (reparsed.offset === -1) throw new Error("built OCSP response is not DER");
    return bytes;
}

/**
 * Corrupts the BasicOCSPResponse signature BIT STRING in place (structure
 * stays valid, the signature stops verifying). The corruption flips the
 * last signature byte; the re-encoded response keeps byte-identical TBS.
 */
export function corruptResponseSignature(responseBytes: Uint8Array): Uint8Array {
    const outer = asn1js.fromBER(toArrayBuffer(responseBytes.slice()));
    if (outer.offset === -1) throw new Error("response is not DER");
    const response = new pkijs.OCSPResponse({ schema: outer.result });
    const inner = response.responseBytes?.response.valueBlock.valueHexView;
    if (!inner) throw new Error("response has no responseBytes");
    const basicAsn1 = asn1js.fromBER(toArrayBuffer(new Uint8Array(inner).slice()));
    if (basicAsn1.offset === -1) throw new Error("BasicOCSPResponse is not DER");
    const basic = new pkijs.BasicOCSPResponse({ schema: basicAsn1.result });
    const signature = new Uint8Array(basic.signature.valueBlock.valueHexView);
    if (signature.length === 0) throw new Error("response has an empty signature");
    signature[signature.length - 1] = (signature[signature.length - 1] ?? 0) ^ 0x01;
    basic.signature = new asn1js.BitString({ valueHex: toArrayBuffer(signature) });
    response.responseBytes = new pkijs.ResponseBytes({
        responseType: "1.3.6.1.5.5.7.48.1.1",
        response: new asn1js.OctetString({ valueHex: basic.toSchema().toBER(false) }),
    });
    return new Uint8Array(response.toSchema().toBER(false));
}

// ---------------------------------------------------------------------------
// Request inspection (test-side only; the library never imports this file)
// ---------------------------------------------------------------------------

export interface InspectedOCSPRequest {
    requestCount: number;
    certId: pkijs.CertID | null;
    nonces: Uint8Array[];
}

function decodeNonceValue(extension: pkijs.Extension): Uint8Array | null {
    try {
        const raw = extension.extnValue.valueBlock.valueHexView;
        const parsed = asn1js.fromBER(raw.slice(0));
        if (parsed.offset === -1 || !(parsed.result instanceof asn1js.OctetString)) return null;
        if (parsed.offset !== raw.length) return null;
        return new Uint8Array(parsed.result.valueBlock.valueHexView);
    } catch {
        return null;
    }
}

/** Parses request bytes with pkijs directly (no library validator involved). */
export function inspectOCSPRequest(requestBytes: Uint8Array): InspectedOCSPRequest {
    const asn1 = asn1js.fromBER(toArrayBuffer(requestBytes.slice()));
    if (asn1.offset === -1) throw new Error("request is not DER");
    const request = new pkijs.OCSPRequest({ schema: asn1.result });
    const first = request.tbsRequest.requestList[0];
    const nonces: Uint8Array[] = [];
    for (const extension of request.tbsRequest.requestExtensions ?? []) {
        if (extension.extnID !== "1.3.6.1.5.5.7.48.1.2") continue;
        const decoded = decodeNonceValue(extension);
        nonces.push(decoded ?? new Uint8Array(0));
    }
    return {
        requestCount: request.tbsRequest.requestList.length,
        certId: first?.reqCert ?? null,
        nonces,
    };
}

/** Re-encodes request bytes with an extra nonce extension (duplicate-nonce fixture). */
export function requestWithDuplicateNonce(requestBytes: Uint8Array, nonce: Uint8Array): Uint8Array {
    const asn1 = asn1js.fromBER(toArrayBuffer(requestBytes.slice()));
    if (asn1.offset === -1) throw new Error("request is not DER");
    const request = new pkijs.OCSPRequest({ schema: asn1.result });
    const extensions = [...(request.tbsRequest.requestExtensions ?? [])];
    extensions.push(nonceExtension(nonce));
    extensions.push(nonceExtension(nonce));
    request.tbsRequest.requestExtensions = extensions;
    request.tbsRequest.tbsView = new Uint8Array(0);
    return new Uint8Array(request.toSchema(true).toBER(false));
}

/** Re-encodes request bytes with the single request duplicated (multi-request fixture). */
export function requestWithDuplicateEntries(requestBytes: Uint8Array): Uint8Array {
    const asn1 = asn1js.fromBER(toArrayBuffer(requestBytes.slice()));
    if (asn1.offset === -1) throw new Error("request is not DER");
    const request = new pkijs.OCSPRequest({ schema: asn1.result });
    const first = request.tbsRequest.requestList[0];
    if (!first) throw new Error("request has no entries to duplicate");
    request.tbsRequest.requestList = [first, first];
    request.tbsRequest.tbsView = new Uint8Array(0);
    return new Uint8Array(request.toSchema(true).toBER(false));
}
