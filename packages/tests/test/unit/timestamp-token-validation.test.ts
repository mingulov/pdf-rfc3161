import { describe, expect, it } from "vitest";
import { TimestampErrorCode, TSAStatus } from "../../../core/src/types.js";
import {
    createRFC3161TokenFixture,
    encodedTstInfoEContentEncoding,
    type FixtureRequestContext,
    type RFC3161TokenFixture,
    type RFC3161TokenFixtureOptions,
} from "../fixtures/rfc3161-token.js";

interface ValidationResult {
    token: Uint8Array;
    info: { hashAlgorithm: string; policy: string };
    signerCertificate: unknown;
    certificates: unknown[];
    responseStatus?: TSAStatus.GRANTED | TSAStatus.GRANTED_WITH_MODS;
}

interface ValidationOptions {
    signerCertificates?: readonly Uint8Array[];
}

async function validate(
    input: Uint8Array,
    context: FixtureRequestContext,
    options?: ValidationOptions
): Promise<ValidationResult> {
    const module = await import("../../../core/src/tsa/token-validation.js");
    return module.validateTimestampToken(input, context, options);
}

async function fixture(options: RFC3161TokenFixtureOptions = {}): Promise<RFC3161TokenFixture> {
    return createRFC3161TokenFixture(options);
}

describe("mandatory RFC 3161 token validation", () => {
    it("accepts independently encoded primitive eContent in raw and full real-signed tokens", async () => {
        for (const form of ["raw", "response"] as const) {
            const token = await fixture({ form, eContentEncoding: "primitive" });

            // This reads the encoded ASN.1 directly, rather than allowing
            // PKIjs EncapsulatedContentInfo to normalize its representation.
            expect(encodedTstInfoEContentEncoding(token.input)).toBe("primitive");
            await expect(validate(token.input, token.context)).resolves.toMatchObject({
                token: token.rawToken,
            });
        }
    });

    it("rejects empty and nested segments in constructed eContent", async () => {
        for (const eContentEncoding of [
            "constructedEmptySegment",
            "constructedNestedSegment",
        ] as const) {
            const token = await fixture({ eContentEncoding });
            await expect(validate(token.input, token.context)).rejects.toMatchObject({
                code: TimestampErrorCode.MALFORMED_RESPONSE,
            });
        }
    });

    it("accepts real signed raw and full tokens across requested hashes, policies, SID forms, and ESS forms", async () => {
        const vectors: {
            label: string;
            options: RFC3161TokenFixtureOptions;
            status?: TSAStatus.GRANTED | TSAStatus.GRANTED_WITH_MODS;
        }[] = [
            {
                label: "raw SHA-256 issuer/serial with a decoy certificate before the signer and ESS v1",
                options: {
                    form: "raw",
                    hashAlgorithm: "SHA-256",
                    certificates: "decoyFirst",
                    ess: "v1",
                },
            },
            {
                label: "full SHA-384 granted response with requested policy and ESS v2",
                options: {
                    form: "response",
                    hashAlgorithm: "SHA-384",
                    policy: "1.2.3.4.5.6",
                    ess: "v2",
                    status: TSAStatus.GRANTED,
                },
                status: TSAStatus.GRANTED,
            },
            {
                label: "full SHA-512 granted-with-modifications response with both ESS versions",
                options: {
                    form: "response",
                    hashAlgorithm: "SHA-512",
                    ess: "both",
                    status: TSAStatus.GRANTED_WITH_MODS,
                },
                status: TSAStatus.GRANTED_WITH_MODS,
            },
            {
                label: "raw non-default SubjectKeyIdentifier SID",
                options: {
                    form: "raw",
                    signerSid: "ski",
                    ess: "v2",
                },
            },
        ];

        for (const vector of vectors) {
            const token = await fixture(vector.options);
            const result = await validate(token.input, token.context);

            expect(result.token).toEqual(token.rawToken);
            expect(result.info.hashAlgorithm).toBe(token.context.hashAlgorithm);
            expect(result.info.policy).toBe(vector.options.policy ?? "1.2.3.4.5");
            expect(result.responseStatus).toBe(vector.status);
            expect(result.certificates.length).toBeGreaterThan(0);
        }
    });

    it("accepts complete real-signed ESS v1 and v2 certificate sequences and policies", async () => {
        for (const ess of ["v1", "v2"] as const) {
            const token = await fixture({
                ess,
                essAdditional: "valid",
                essPolicies: "valid",
            });
            await expect(validate(token.input, token.context)).resolves.toMatchObject({
                token: token.rawToken,
            });
        }
    });

    it("accepts real-signed present empty ESS policy sequences in raw and full tokens", async () => {
        const vectors: RFC3161TokenFixtureOptions[] = [
            { form: "raw", ess: "v1", essPolicies: "empty" },
            { form: "response", ess: "v1", essPolicies: "empty" },
            { form: "raw", ess: "v2", essPolicies: "empty" },
            { form: "response", ess: "v2", essPolicies: "empty" },
        ];

        for (const options of vectors) {
            const token = await fixture(options);
            await expect(validate(token.input, token.context)).resolves.toMatchObject({
                token: token.rawToken,
            });
        }
    });

    it("rejects invalid first, additional, and policies fields in complete ESS v1/v2 sequences", async () => {
        const vectors: RFC3161TokenFixtureOptions[] = [
            { ess: "v1", essAdditional: "wrongFirst" },
            { ess: "v2", essAdditional: "wrongFirst" },
            { ess: "v1", essAdditional: "malformed" },
            { ess: "v2", essAdditional: "malformed" },
            { ess: "v1", essAdditional: "unsupportedAlgorithm" },
            { ess: "v2", essAdditional: "unsupportedAlgorithm" },
            { ess: "v1", essPolicies: "malformed" },
            { ess: "v2", essPolicies: "malformed" },
        ];

        for (const options of vectors) {
            const token = await fixture(options);
            await expect(validate(token.input, token.context)).rejects.toMatchObject({
                code: TimestampErrorCode.VERIFICATION_FAILED,
            });
        }
    });

    it("accepts certReq=false only with a real external signer certificate and no embedded certificates", async () => {
        const token = await fixture({
            form: "response",
            requestCertificate: false,
            certificates: "none",
            ess: "both",
        });

        const result = await validate(token.input, token.context, {
            signerCertificates: [token.signerCertificate],
        });

        expect(result.info.hashAlgorithm).toBe("SHA-256");
        expect(result.responseStatus).toBe(TSAStatus.GRANTED);
    });

    it("rejects every request-binding mismatch before a token can reach a PDF", async () => {
        const vectors: { label: string; options: RFC3161TokenFixtureOptions }[] = [
            { label: "message imprint", options: { imprint: "mismatch" } },
            { label: "message imprint digest length", options: { imprint: "wrongLength" } },
            { label: "message imprint algorithm", options: { imprint: "wrongAlgorithm" } },
            { label: "nonce", options: { responseNonce: new Uint8Array([9, 8, 7, 6]) } },
            { label: "missing nonce", options: { responseNonce: "missing" } },
            { label: "zero nonce", options: { responseNonce: "zero" } },
            { label: "negative nonce", options: { responseNonce: "negative" } },
            {
                label: "requested policy",
                options: { policy: "1.2.3.4.5", responsePolicy: "1.2.3.4.6" },
            },
        ];

        for (const vector of vectors) {
            const token = await fixture(vector.options);
            await expect(validate(token.input, token.context)).rejects.toMatchObject({
                code: TimestampErrorCode.VERIFICATION_FAILED,
            });
        }
    });

    it("rejects malformed CMS, content types, signer selection failures, and every invalid ESS binding", async () => {
        const vectors: { label: string; options: RFC3161TokenFixtureOptions }[] = [
            { label: "corrupted CMS signature", options: { corruptSignature: true } },
            { label: "wrong outer ContentInfo type", options: { contentType: "data" } },
            { label: "wrong encapsulated content type", options: { eContentType: "data" } },
            { label: "multiple SignerInfos", options: { signerCount: 2 } },
            { label: "zero SID match", options: { signerSid: "zero" } },
            { label: "ambiguous SID match", options: { certificates: "ambiguous" } },
            { label: "missing ESS", options: { ess: "missing" } },
            { label: "malformed ESS", options: { ess: "malformed" } },
            { label: "mismatched ESS", options: { ess: "mismatched" } },
            { label: "duplicate ESS", options: { ess: "duplicate" } },
            { label: "unsupported ESS hash", options: { ess: "unsupported" } },
            { label: "conflicting ESS v1 and v2", options: { ess: "conflicting" } },
        ];

        for (const vector of vectors) {
            const token = await fixture(vector.options);
            await expect(validate(token.input, token.context)).rejects.toBeInstanceOf(Error);
        }
    });

    it("requires one critical exclusive id-kp-timeStamping EKU", async () => {
        const vectors: { label: string; eku: NonNullable<RFC3161TokenFixtureOptions["eku"]> }[] = [
            { label: "noncritical", eku: "noncritical" },
            { label: "extra purpose", eku: "extra" },
            { label: "anyExtendedKeyUsage", eku: "any" },
            { label: "missing", eku: "missing" },
            { label: "duplicate extension", eku: "duplicate" },
            { label: "malformed extension", eku: "malformed" },
        ];

        for (const vector of vectors) {
            const token = await fixture({ eku: vector.eku });
            await expect(validate(token.input, token.context)).rejects.toMatchObject({
                code: TimestampErrorCode.VERIFICATION_FAILED,
            });
        }
    });

    it("rejects every non-granted status and status/token structure violation", async () => {
        const statuses = [
            TSAStatus.REJECTION,
            TSAStatus.WAITING,
            TSAStatus.REVOCATION_WARNING,
            TSAStatus.REVOCATION_NOTIFICATION,
            6,
        ];
        for (const status of statuses) {
            const token = await fixture({ form: "response", status });
            await expect(validate(token.input, token.context)).rejects.toMatchObject({
                code: TimestampErrorCode.TSA_ERROR,
            });
        }

        const grantedWithoutToken = await fixture({
            form: "response",
            status: TSAStatus.GRANTED,
            includeToken: false,
        });
        await expect(
            validate(grantedWithoutToken.input, grantedWithoutToken.context)
        ).rejects.toMatchObject({
            code: TimestampErrorCode.MALFORMED_RESPONSE,
        });

        const rejectedWithToken = await fixture({
            form: "response",
            status: TSAStatus.REJECTION,
            includeToken: true,
        });
        await expect(
            validate(rejectedWithToken.input, rejectedWithToken.context)
        ).rejects.toMatchObject({
            code: TimestampErrorCode.MALFORMED_RESPONSE,
        });
    });

    it("enforces both certReq directions and rejects external certificate parse errors", async () => {
        const requestedButMissing = await fixture({
            requestCertificate: true,
            certificates: "none",
        });
        await expect(
            validate(requestedButMissing.input, requestedButMissing.context)
        ).rejects.toMatchObject({
            code: TimestampErrorCode.VERIFICATION_FAILED,
        });

        const forbiddenEmbedded = await fixture({
            requestCertificate: false,
            certificates: "signer",
        });
        await expect(
            validate(forbiddenEmbedded.input, forbiddenEmbedded.context)
        ).rejects.toMatchObject({
            code: TimestampErrorCode.VERIFICATION_FAILED,
        });

        const externalRequired = await fixture({ requestCertificate: false, certificates: "none" });
        await expect(
            validate(externalRequired.input, externalRequired.context)
        ).rejects.toMatchObject({
            code: TimestampErrorCode.VERIFICATION_FAILED,
        });
        await expect(
            validate(externalRequired.input, externalRequired.context, {
                signerCertificates: [new Uint8Array([0x30, 0x00])],
            })
        ).rejects.toMatchObject({ code: TimestampErrorCode.MALFORMED_RESPONSE });
    });

    it("rejects trailing bytes rather than treating an ambiguous envelope as a raw token", async () => {
        const token = await fixture();
        const trailing = new Uint8Array(token.rawToken.length + 1);
        trailing.set(token.rawToken);
        trailing[trailing.length - 1] = 0;

        await expect(validate(trailing, token.context)).rejects.toMatchObject({
            code: TimestampErrorCode.INVALID_RESPONSE,
        });
    });
});
