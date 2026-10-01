import { beforeAll, describe, expect, it } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { PDFDocument } from "pdf-lib-incremental-save";
import { SimpleTrustStore } from "../../../core/src/pki/trust-store.js";
import {
    verifyPdfTimestamps,
    verifyTimestamp,
    type ExtractedTimestamp,
} from "../../../core/src/pdf/extract.js";
import { TimestampSession } from "../../../core/src/session.js";
import { parseTimestampToken } from "../../../core/src/tsa/token-validation.js";
import type { TimestampInfo } from "../../../core/src/types.js";
import {
    createRFC3161TokenFixture,
    createRFC3161TokenFixtureFromRequest,
} from "../fixtures/rfc3161-token.js";
import { cryptoEngine, generateRSAKeyPair, importKeyForCertificate } from "../utils/crypto.js";

const ID_SIGNED_DATA = "1.2.840.113549.1.7.2";

interface TrustTargetHierarchy {
    root: pkijs.Certificate;
    intermediate: pkijs.Certificate;
    genuineLeaf: pkijs.Certificate;
    untrustedSigner: pkijs.Certificate;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    const copy = new Uint8Array(bytes);
    return copy.buffer as ArrayBuffer;
}

function derOf(certificate: pkijs.Certificate): Uint8Array {
    return new Uint8Array(certificate.toSchema().toBER(false));
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
    if (left.length !== right.length) return false;
    for (let index = 0; index < left.length; index++) {
        if (left[index] !== right[index]) return false;
    }
    return true;
}

async function generateECKeyPair(): Promise<CryptoKeyPair> {
    return (await import("crypto")).webcrypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
    ) as unknown as CryptoKeyPair;
}

/**
 * Re-signs a certificate's TBS with fresh ECDSA randomness, producing a
 * second valid signature over exactly the same TBS bytes (a TBS alias).
 */
async function resignSameTbs(
    certificate: pkijs.Certificate,
    issuerPrivateKey: CryptoKey
): Promise<pkijs.Certificate> {
    const parsed = asn1js.fromBER(toArrayBuffer(derOf(certificate)));
    if (parsed.offset === -1) throw new Error("Certificate is not DER");
    const alias = new pkijs.Certificate({ schema: parsed.result });
    await alias.sign(issuerPrivateKey, "SHA-256", cryptoEngine);
    return alias;
}

async function createHierarchyCertificate(options: {
    commonName: string;
    keys: CryptoKeyPair;
    serial: number;
    ca: boolean;
    issuer?: pkijs.Certificate;
    issuerKeys?: CryptoKeyPair;
}): Promise<pkijs.Certificate> {
    const certificate = new pkijs.Certificate();
    certificate.version = 2;
    certificate.serialNumber = new asn1js.Integer({ value: options.serial });
    certificate.subject.typesAndValues.push(
        new pkijs.AttributeTypeAndValue({
            type: "2.5.4.3",
            value: new asn1js.PrintableString({ value: options.commonName }),
        })
    );
    certificate.issuer = options.issuer?.subject ?? certificate.subject;
    certificate.notBefore.value = new Date(Date.now() - 86400000);
    certificate.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    certificate.subjectPublicKeyInfo = await importKeyForCertificate(options.keys.publicKey);
    if (options.ca) {
        certificate.extensions = [
            new pkijs.Extension({
                extnID: "2.5.29.19",
                critical: true,
                extnValue: new pkijs.BasicConstraints({ cA: true }).toSchema().toBER(),
            }),
        ];
    }
    await certificate.sign(
        (options.issuerKeys ?? options.keys).privateKey,
        "SHA-256",
        cryptoEngine
    );
    return certificate;
}

async function buildHierarchy(): Promise<TrustTargetHierarchy> {
    const rootKeys = await generateRSAKeyPair();
    const intermediateKeys = await generateRSAKeyPair();
    const leafKeys = await generateRSAKeyPair();
    const signerKeys = await generateRSAKeyPair();
    const root = await createHierarchyCertificate({
        commonName: "Trust Target Root",
        keys: rootKeys,
        serial: 1001,
        ca: true,
    });
    const intermediate = await createHierarchyCertificate({
        commonName: "Trust Target Intermediate",
        keys: intermediateKeys,
        serial: 1002,
        ca: true,
        issuer: root,
        issuerKeys: rootKeys,
    });
    const genuineLeaf = await createHierarchyCertificate({
        commonName: "Trust Target Leaf",
        keys: leafKeys,
        serial: 1003,
        ca: false,
        issuer: intermediate,
        issuerKeys: intermediateKeys,
    });
    const untrustedSigner = await createHierarchyCertificate({
        commonName: "Untrusted Signer",
        keys: signerKeys,
        serial: 1004,
        ca: false,
    });
    return { root, intermediate, genuineLeaf, untrustedSigner };
}

function extracted(token: Uint8Array): ExtractedTimestamp {
    return {
        token,
        contentsValueBytes: token.slice(),
        info: {} as TimestampInfo,
        fieldName: "Timestamp",
        coversWholeDocument: true,
        verified: false,
        byteRange: [0, 0, 0, 0],
    };
}

/** Appends extra certificates to a token's unsigned CMS certificate bag. */
function poisonTokenBag(rawToken: Uint8Array, extra: readonly pkijs.Certificate[]): Uint8Array {
    const parsed = parseTimestampToken(rawToken);
    if (parsed.signedData.certificates === undefined) {
        throw new Error("Fixture token has no certificate bag to poison");
    }
    parsed.signedData.certificates.push(...extra);
    return new Uint8Array(
        new pkijs.ContentInfo({
            contentType: ID_SIGNED_DATA,
            content: parsed.signedData.toSchema(),
        })
            .toSchema()
            .toBER(false)
    );
}

/** Rewraps a poisoned token into its TimeStampResp for the embed flow. */
function rewrapResponse(response: Uint8Array, poisonedToken: Uint8Array): Uint8Array {
    const responseSchema = asn1js.fromBER(toArrayBuffer(response));
    if (responseSchema.offset === -1) throw new Error("Fixture response is not DER");
    const timeStampResp = new pkijs.TimeStampResp({ schema: responseSchema.result });
    const tokenSchema = asn1js.fromBER(toArrayBuffer(poisonedToken));
    if (tokenSchema.offset === -1) throw new Error("Poisoned token is not DER");
    timeStampResp.timeStampToken = new pkijs.ContentInfo({ schema: tokenSchema.result });
    return new Uint8Array(timeStampResp.toSchema().toBER(false));
}

async function createOnePagePdf(): Promise<Uint8Array> {
    const pdf = await PDFDocument.create();
    pdf.addPage([100, 100]);
    return pdf.save();
}

describe("trust-target binding (R28)", () => {
    let hierarchy: TrustTargetHierarchy;

    beforeAll(async () => {
        hierarchy = await buildHierarchy();
    });

    function pinnedRootStore(): SimpleTrustStore {
        const store = new SimpleTrustStore();
        store.addCertificate(hierarchy.root);
        return store;
    }

    it("rejects_untrusted_signer_with_unrelated_trusted_intermediate", async () => {
        const fixture = await createRFC3161TokenFixture();
        const store = pinnedRootStore();

        const baseline = await verifyTimestamp(extracted(fixture.rawToken), {
            trustStore: store,
            strictESSValidation: true,
        });
        expect(baseline.verified).toBe(false);

        const poisoned = poisonTokenBag(fixture.rawToken, [hierarchy.intermediate]);
        const result = await verifyTimestamp(extracted(poisoned), {
            trustStore: store,
            strictESSValidation: true,
        });
        expect(result.certificates).toHaveLength(2);
        expect(result.verified).toBe(false);
        expect(result.verificationError).toMatch(/not trusted/);
    });

    it("rejects_untrusted_signer_with_unrelated_trusted_intermediate_in_signed_pdf", async () => {
        const input = await createOnePagePdf();
        const session = new TimestampSession(input, { enableLTV: false });
        try {
            const request = await session.createTimestampRequest();
            const fixture = await createRFC3161TokenFixtureFromRequest(request, {
                form: "response",
            });
            const poisonedToken = poisonTokenBag(fixture.rawToken, [hierarchy.intermediate]);
            const signedPdf = await session.embedTimestampToken(
                rewrapResponse(fixture.response, poisonedToken)
            );
            expect(signedPdf.length).toBeGreaterThan(input.length);

            const results = await verifyPdfTimestamps(signedPdf, {
                trustStore: pinnedRootStore(),
                strictESSValidation: true,
            });
            expect(results).toHaveLength(1);
            expect(results[0]?.certificates).toHaveLength(2);
            expect(results[0]?.verified).toBe(false);
            expect(results[0]?.verificationError).toMatch(/not trusted/);
        } finally {
            session.dispose();
        }
    });

    it("proves the poisoned token is otherwise valid without a trust policy", async () => {
        const fixture = await createRFC3161TokenFixture();
        const poisoned = poisonTokenBag(fixture.rawToken, [hierarchy.intermediate]);
        const tokenResult = await verifyTimestamp(extracted(poisoned), {
            strictESSValidation: true,
        });
        expect(tokenResult.certificates).toHaveLength(2);
        expect(tokenResult.verified).toBe(true);

        const input = await createOnePagePdf();
        const session = new TimestampSession(input, { enableLTV: false });
        try {
            const request = await session.createTimestampRequest();
            const pdfFixture = await createRFC3161TokenFixtureFromRequest(request, {
                form: "response",
            });
            const signedPdf = await session.embedTimestampToken(
                rewrapResponse(
                    pdfFixture.response,
                    poisonTokenBag(pdfFixture.rawToken, [hierarchy.intermediate])
                )
            );
            const results = await verifyPdfTimestamps(signedPdf, {
                strictESSValidation: true,
            });
            expect(results).toHaveLength(1);
            expect(results[0]?.verified).toBe(true);
        } finally {
            session.dispose();
        }
    });

    it("keeps an untrusted target untrusted under candidate permutations", async () => {
        const store = pinnedRootStore();
        const { genuineLeaf, intermediate, root, untrustedSigner } = hierarchy;
        await expect(store.verifyChain([untrustedSigner, intermediate])).resolves.toBe(false);
        await expect(store.verifyChain([untrustedSigner, intermediate, root])).resolves.toBe(false);
        await expect(store.verifyChain([untrustedSigner, genuineLeaf, intermediate])).resolves.toBe(
            false
        );
        await expect(store.verifyChain([untrustedSigner, intermediate, genuineLeaf])).resolves.toBe(
            false
        );
    });

    it("keeps an untrusted target untrusted under duplicate candidates", async () => {
        const store = pinnedRootStore();
        const { intermediate, untrustedSigner } = hierarchy;
        await expect(
            store.verifyChain([untrustedSigner, intermediate, intermediate])
        ).resolves.toBe(false);
        await expect(
            store.verifyChain([untrustedSigner, untrustedSigner, intermediate])
        ).resolves.toBe(false);
    });

    it("verifies a genuine signer chain and ignores unrelated extra candidates", async () => {
        const store = pinnedRootStore();
        const { genuineLeaf, intermediate, untrustedSigner } = hierarchy;
        await expect(store.verifyChain([genuineLeaf, intermediate])).resolves.toBe(true);
        await expect(store.verifyChain([genuineLeaf, intermediate, untrustedSigner])).resolves.toBe(
            true
        );
    });

    it("trusts an explicitly pinned target regardless of unrelated candidates", async () => {
        const store = pinnedRootStore();
        const { intermediate, root, untrustedSigner } = hierarchy;
        await expect(store.verifyChain([root, untrustedSigner])).resolves.toBe(true);
        await expect(store.verifyChain([root, intermediate, untrustedSigner])).resolves.toBe(true);

        const secondRoot = await createHierarchyCertificate({
            commonName: "Trust Target Second Root",
            keys: await generateRSAKeyPair(),
            serial: 1005,
            ca: true,
        });
        const multiAnchor = pinnedRootStore();
        multiAnchor.addCertificate(secondRoot);
        await expect(multiAnchor.verifyChain([root, untrustedSigner])).resolves.toBe(true);
        await expect(multiAnchor.verifyChain([secondRoot, untrustedSigner])).resolves.toBe(true);
        await expect(multiAnchor.verifyChain([untrustedSigner, intermediate])).resolves.toBe(false);
    });

    it("keeps a pinned intermediate chained to its issuer anchor", async () => {
        const { intermediate, root } = hierarchy;
        await expect(pinnedRootStore().verifyChain([intermediate])).resolves.toBe(true);

        const pinnedFirst = new SimpleTrustStore();
        pinnedFirst.addCertificate(intermediate);
        pinnedFirst.addCertificate(root);
        await expect(pinnedFirst.verifyChain([intermediate])).resolves.toBe(true);

        const rootFirst = new SimpleTrustStore();
        rootFirst.addCertificate(root);
        rootFirst.addCertificate(intermediate);
        await expect(rootFirst.verifyChain([intermediate])).resolves.toBe(true);

        const pinnedOnly = new SimpleTrustStore();
        pinnedOnly.addCertificate(intermediate);
        await expect(pinnedOnly.verifyChain([intermediate])).resolves.toBe(false);
    });

    it("keeps a genuine target when a TBS alias shares the candidate bag", async () => {
        const rootKeys = await generateECKeyPair();
        const intermediateKeys = await generateECKeyPair();
        const leafKeys = await generateECKeyPair();
        const root = await createHierarchyCertificate({
            commonName: "EC Alias Root",
            keys: rootKeys,
            serial: 2001,
            ca: true,
        });
        const intermediate = await createHierarchyCertificate({
            commonName: "EC Alias Intermediate",
            keys: intermediateKeys,
            serial: 2002,
            ca: true,
            issuer: root,
            issuerKeys: rootKeys,
        });
        const leaf = await createHierarchyCertificate({
            commonName: "EC Alias Leaf",
            keys: leafKeys,
            serial: 2003,
            ca: false,
            issuer: intermediate,
            issuerKeys: intermediateKeys,
        });
        const alias = await resignSameTbs(leaf, intermediateKeys.privateKey);

        expect(bytesEqual(new Uint8Array(alias.tbsView), new Uint8Array(leaf.tbsView))).toBe(
            true
        );
        expect(bytesEqual(derOf(alias), derOf(leaf))).toBe(false);
        await expect(leaf.verify(intermediate, cryptoEngine)).resolves.toBe(true);
        await expect(alias.verify(intermediate, cryptoEngine)).resolves.toBe(true);

        const store = new SimpleTrustStore();
        store.addCertificate(root);
        await expect(store.verifyChain([leaf, intermediate])).resolves.toBe(true);
        await expect(store.verifyChain([leaf, intermediate, alias])).resolves.toBe(true);
        await expect(store.verifyChain([leaf, alias, intermediate])).resolves.toBe(true);
    });

    it("still rejects an untrusted target when a TBS alias shares the bag", async () => {
        const strangerKeys = await generateECKeyPair();
        const stranger = await createHierarchyCertificate({
            commonName: "EC Stranger",
            keys: strangerKeys,
            serial: 2004,
            ca: false,
        });
        const strangerAlias = await resignSameTbs(stranger, strangerKeys.privateKey);

        expect(
            bytesEqual(new Uint8Array(strangerAlias.tbsView), new Uint8Array(stranger.tbsView))
        ).toBe(true);
        expect(bytesEqual(derOf(strangerAlias), derOf(stranger))).toBe(false);

        const store = pinnedRootStore();
        const { intermediate } = hierarchy;
        await expect(store.verifyChain([stranger, intermediate])).resolves.toBe(false);
        await expect(store.verifyChain([stranger, strangerAlias, intermediate])).resolves.toBe(
            false
        );
        await expect(store.verifyChain([stranger, intermediate, strangerAlias])).resolves.toBe(
            false
        );
    });

    it("rejects every chain when anchors are empty", async () => {
        const store = new SimpleTrustStore();
        const { genuineLeaf, intermediate, root } = hierarchy;
        await expect(store.verifyChain([genuineLeaf, intermediate])).resolves.toBe(false);
        await expect(store.verifyChain([root])).resolves.toBe(false);
    });

    it("applies target semantics to mixed DER and object inputs", async () => {
        const store = pinnedRootStore();
        const { genuineLeaf, intermediate, untrustedSigner } = hierarchy;
        await expect(store.verifyChain([derOf(untrustedSigner), intermediate])).resolves.toBe(
            false
        );
        await expect(store.verifyChain([derOf(genuineLeaf), intermediate])).resolves.toBe(true);

        const derAnchors = new SimpleTrustStore();
        derAnchors.addCertificate(derOf(hierarchy.root));
        await expect(
            derAnchors.verifyChain([derOf(genuineLeaf), derOf(intermediate)])
        ).resolves.toBe(true);
        await expect(
            derAnchors.verifyChain([derOf(untrustedSigner), derOf(intermediate)])
        ).resolves.toBe(false);
    });
});
