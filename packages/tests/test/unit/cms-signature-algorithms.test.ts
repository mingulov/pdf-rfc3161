import { describe, expect, it } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { createRFC3161TokenFixture } from "../fixtures/rfc3161-token.js";
import {
    parseTimestampToken,
    validateTimestampToken,
    verifyTimestampCmsSignature,
} from "../../../core/src/tsa/token-validation.js";

const RSA_SHA256 = "1.2.840.113549.1.1.11";
const ECDSA_SHA256 = "1.2.840.10045.4.3.2";

async function mutateAlgorithm(algorithmId: string, algorithmParams?: asn1js.BaseBlock) {
    const fixture = await createRFC3161TokenFixture();
    const parsed = parseTimestampToken(fixture.rawToken);
    parsed.signerInfo.signatureAlgorithm = new pkijs.AlgorithmIdentifier({
        algorithmId,
        ...(algorithmParams === undefined ? {} : { algorithmParams }),
    });
    parsed.contentInfo.content = parsed.signedData.toSchema();
    return {
        fixture,
        token: new Uint8Array(parsed.contentInfo.toSchema().toBER(false)),
    };
}

async function signedCms(
    algorithm: "RSA-PSS" | "ECDSA" | "RSASSA-PKCS1-v1_5",
    hash: "SHA-256" | "SHA-384" | "SHA-512"
) {
    const fixture = await createRFC3161TokenFixture();
    const parsed = parseTimestampToken(fixture.rawToken);
    const signer = parsed.signedData.certificates?.[0];
    const attrs = parsed.signerInfo.signedAttrs;
    const content = parsed.signedData.encapContentInfo.eContent;
    if (!(signer instanceof pkijs.Certificate) || !attrs || !content) {
        throw new Error("Incomplete fixture");
    }
    const keys =
        algorithm === "ECDSA"
            ? await crypto.subtle.generateKey({ name: algorithm, namedCurve: "P-256" }, true, [
                  "sign",
                  "verify",
              ])
            : await crypto.subtle.generateKey(
                  {
                      name: algorithm,
                      modulusLength: 2048,
                      publicExponent: new Uint8Array([1, 0, 1]),
                      hash,
                  },
                  true,
                  ["sign", "verify"]
              );
    await signer.subjectPublicKeyInfo.importKey(keys.publicKey);
    const digest = attrs.attributes.find((attr) => attr.type === "1.2.840.113549.1.9.4");
    if (!digest) throw new Error("Missing content digest");
    digest.values = [
        new asn1js.OctetString({ valueHex: await crypto.subtle.digest(hash, content.getValue()) }),
    ];
    attrs.encodedValue = attrs.toSchema().toBER(false);
    new Uint8Array(attrs.encodedValue)[0] = 0x31;
    await parsed.signedData.sign(keys.privateKey, 0, hash);
    return { parsed, signer };
}

describe("CMS signature algorithm binding", () => {
    it("rejects an authentic RSA signature relabeled as ECDSA", async () => {
        const { fixture, token } = await mutateAlgorithm(ECDSA_SHA256);
        await expect(validateTimestampToken(token, fixture.context)).rejects.toMatchObject({
            code: "VERIFICATION_FAILED",
        });
    });

    it("rejects non-NULL parameters on an RSA PKCS#1 signature", async () => {
        const { fixture, token } = await mutateAlgorithm(
            RSA_SHA256,
            new asn1js.OctetString({ valueHex: new Uint8Array([0]).buffer })
        );
        await expect(validateTimestampToken(token, fixture.context)).rejects.toMatchObject({
            code: "VERIFICATION_FAILED",
        });
    });

    it.each([undefined, new asn1js.Null()])(
        "accepts RSA absent/NULL parameters: %s",
        async (params) => {
            const { fixture, token } = await mutateAlgorithm(RSA_SHA256, params);
            await expect(validateTimestampToken(token, fixture.context)).resolves.toHaveProperty(
                "token"
            );
        }
    );

    it("accepts the CMS rsaEncryption signature identifier", async () => {
        const { fixture, token } = await mutateAlgorithm("1.2.840.113549.1.1.1", new asn1js.Null());
        await expect(validateTimestampToken(token, fixture.context)).resolves.toHaveProperty(
            "token"
        );
    });

    it("rejects unknown signature algorithm identifiers", async () => {
        const { fixture, token } = await mutateAlgorithm("1.2.3.4");
        await expect(validateTimestampToken(token, fixture.context)).rejects.toMatchObject({
            code: "VERIFICATION_FAILED",
        });
    });

    it("preserves genuine ECDSA signatures and rejects RSA relabeling/parameters", async () => {
        const fixture = await createRFC3161TokenFixture();
        const parsed = parseTimestampToken(fixture.rawToken);
        const signer = parsed.signedData.certificates?.[0];
        if (!(signer instanceof pkijs.Certificate)) throw new Error("Missing fixture signer");
        const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
            "sign",
            "verify",
        ]);
        await signer.subjectPublicKeyInfo.importKey(keys.publicKey);
        await parsed.signedData.sign(keys.privateKey, 0, "SHA-256");
        await expect(
            verifyTimestampCmsSignature(parsed.signedData, parsed.signerInfo, signer)
        ).resolves.toBeUndefined();
        parsed.signerInfo.signatureAlgorithm = new pkijs.AlgorithmIdentifier({
            algorithmId: RSA_SHA256,
        });
        await expect(
            verifyTimestampCmsSignature(parsed.signedData, parsed.signerInfo, signer)
        ).rejects.toMatchObject({ code: "VERIFICATION_FAILED" });
        parsed.signerInfo.signatureAlgorithm = new pkijs.AlgorithmIdentifier({
            algorithmId: ECDSA_SHA256,
            algorithmParams: new asn1js.Null(),
        });
        await expect(
            verifyTimestampCmsSignature(parsed.signedData, parsed.signerInfo, signer)
        ).rejects.toMatchObject({ code: "VERIFICATION_FAILED" });
    });
    it("preserves genuine RSA-PSS but rejects parameters WebCrypto cannot execute", async () => {
        const fixture = await createRFC3161TokenFixture();
        const parsed = parseTimestampToken(fixture.rawToken);
        const signer = parsed.signedData.certificates?.[0];
        if (!(signer instanceof pkijs.Certificate)) throw new Error("Missing fixture signer");
        const keys = await crypto.subtle.generateKey(
            {
                name: "RSA-PSS",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["sign", "verify"]
        );
        await signer.subjectPublicKeyInfo.importKey(keys.publicKey);
        await parsed.signedData.sign(keys.privateKey, 0, "SHA-256");
        await expect(
            verifyTimestampCmsSignature(parsed.signedData, parsed.signerInfo, signer)
        ).resolves.toBeUndefined();
        const original = parsed.signerInfo.signatureAlgorithm.algorithmParams as asn1js.Sequence;
        for (const change of ["mgf", "mgfHash", "trailer"] as const) {
            const params = new pkijs.RSASSAPSSParams({ schema: original });
            if (change === "mgf") params.maskGenAlgorithm.algorithmId = "1.2.3.4";
            if (change === "mgfHash")
                params.maskGenAlgorithm.algorithmParams = new pkijs.AlgorithmIdentifier({
                    algorithmId: "1.3.14.3.2.26",
                }).toSchema();
            if (change === "trailer") params.trailerField = 2;
            parsed.signerInfo.signatureAlgorithm.algorithmParams = params.toSchema();
            await expect(
                verifyTimestampCmsSignature(parsed.signedData, parsed.signerInfo, signer)
            ).rejects.toMatchObject({ code: "VERIFICATION_FAILED" });
        }
    });
    it("rejects differing content and signature digest declarations", async () => {
        const fixture = await createRFC3161TokenFixture();
        const parsed = parseTimestampToken(fixture.rawToken);
        const signer = parsed.signedData.certificates?.[0];
        if (!(signer instanceof pkijs.Certificate)) throw new Error("Missing fixture signer");
        const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
            "sign",
            "verify",
        ]);
        await signer.subjectPublicKeyInfo.importKey(keys.publicKey);
        // Existing signed attributes contain a SHA-256 content digest, while
        // this produces a genuine ECDSA-SHA512 signature over those attributes.
        await parsed.signedData.sign(keys.privateKey, 0, "SHA-512");
        parsed.signerInfo.digestAlgorithm = new pkijs.AlgorithmIdentifier({
            algorithmId: "2.16.840.1.101.3.4.2.1",
        });
        await expect(
            verifyTimestampCmsSignature(parsed.signedData, parsed.signerInfo, signer)
        ).rejects.toMatchObject({ code: "VERIFICATION_FAILED" });
    });
    it.each(["RSA-PSS", "ECDSA", "RSASSA-PKCS1-v1_5"] as const)(
        "preserves genuine %s signatures with SHA-384 and SHA-512",
        async (algorithm) => {
            for (const hash of ["SHA-384", "SHA-512"] as const) {
                const { parsed, signer } = await signedCms(algorithm, hash);
                await expect(
                    verifyTimestampCmsSignature(parsed.signedData, parsed.signerInfo, signer)
                ).resolves.toBeUndefined();
            }
        }
    );

    it("rejects malformed, duplicate, unsupported and out-of-range PSS parameters", async () => {
        const { parsed, signer } = await signedCms("RSA-PSS", "SHA-256");
        const original = parsed.signerInfo.signatureAlgorithm.algorithmParams as asn1js.Sequence;
        const invalid: (asn1js.BaseBlock | undefined)[] = [undefined, new asn1js.Null()];
        for (const change of [
            "negativeSalt",
            "hugeSalt",
            "unknownHash",
            "hashParameters",
            "missingMaskParameters",
            "maskParameters",
        ] as const) {
            const params = new pkijs.RSASSAPSSParams({ schema: original });
            if (change === "negativeSalt") params.saltLength = -1;
            if (change === "hugeSalt") params.saltLength = Number.MAX_SAFE_INTEGER;
            if (change === "unknownHash") params.hashAlgorithm.algorithmId = "1.2.3.4";
            if (change === "hashParameters")
                params.hashAlgorithm.algorithmParams = new asn1js.OctetString();
            if (change === "missingMaskParameters")
                params.maskGenAlgorithm.algorithmParams = new asn1js.Null();
            if (change === "maskParameters")
                params.maskGenAlgorithm.algorithmParams = new pkijs.AlgorithmIdentifier({
                    algorithmId: "2.16.840.1.101.3.4.2.1",
                    algorithmParams: new asn1js.OctetString(),
                }).toSchema();
            invalid.push(params.toSchema());
        }
        invalid.push(
            new asn1js.Sequence({
                value: [...original.valueBlock.value, original.valueBlock.value[0]!],
            })
        );
        for (const params of invalid) {
            parsed.signerInfo.signatureAlgorithm.algorithmParams = params;
            await expect(
                verifyTimestampCmsSignature(parsed.signedData, parsed.signerInfo, signer)
            ).rejects.toMatchObject({ code: "VERIFICATION_FAILED" });
        }
    });

    it("rejects unsupported or malformed CMS digest identifiers", async () => {
        const fixture = await createRFC3161TokenFixture();
        for (const digest of [
            new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.3.4" }),
            new pkijs.AlgorithmIdentifier({
                algorithmId: "2.16.840.1.101.3.4.2.1",
                algorithmParams: new asn1js.OctetString(),
            }),
        ]) {
            const parsed = parseTimestampToken(fixture.rawToken);
            const signer = parsed.signedData.certificates?.[0];
            if (!(signer instanceof pkijs.Certificate)) throw new Error("Missing signer");
            parsed.signerInfo.digestAlgorithm = digest;
            await expect(
                verifyTimestampCmsSignature(parsed.signedData, parsed.signerInfo, signer)
            ).rejects.toMatchObject({ code: "VERIFICATION_FAILED" });
        }
    });
});
