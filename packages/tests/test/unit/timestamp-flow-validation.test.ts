import { beforeEach, describe, expect, it, vi } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
import { TimestampError, TSAStatus } from "../../../core/src/types.js";
import {
    createRFC3161TokenFixtureFromRequest,
    type RFC3161TokenFixtureOptions,
} from "../fixtures/rfc3161-token.js";

const embedSpy = vi.hoisted(() =>
    vi.fn((_pdf: Uint8Array, _token: Uint8Array) => new Uint8Array([0x25, 0x50, 0x44, 0x46]))
);

vi.mock("../../../core/src/pdf/embed.js", async (importOriginal: <T = unknown>() => Promise<T>) => {
    const original = await importOriginal<typeof import("../../../core/src/pdf/embed.js")>();
    return {
        ...original,
        embedTimestampToken: embedSpy,
    };
});

const { TimestampSession } = await import("../../../core/src/session.js");

async function createSession(): Promise<InstanceType<typeof TimestampSession>> {
    const pdf = await PDFDocument.create();
    pdf.addPage([100, 100]);
    return new TimestampSession(await pdf.save(), { enableLTV: false });
}

describe("TimestampSession pre-embed validation gate", () => {
    beforeEach(() => {
        embedSpy.mockClear();
    });

    it("embeds fully validated one-argument raw and full tokens exactly once and byte-for-byte", async () => {
        for (const form of ["raw", "response"] as const) {
            const session = await createSession();
            const request = await session.createTimestampRequest({
                hashAlgorithm: "SHA-384",
                policy: "1.2.3.4.5",
                requestCertificate: true,
            });
            const token = await createRFC3161TokenFixtureFromRequest(request, {
                form,
                status: TSAStatus.GRANTED_WITH_MODS,
                certificates: "decoyFirst",
                ess: "both",
            });
            embedSpy.mockClear();

            await expect(session.embedTimestampToken(token.input)).resolves.toEqual(
                new Uint8Array([0x25, 0x50, 0x44, 0x46])
            );
            expect(embedSpy).toHaveBeenCalledTimes(1);
            expect(embedSpy.mock.calls[0]?.[1]).toEqual(token.rawToken);
        }
    });

    it("never invokes the PDF embed primitive for every invalid raw or full vector", async () => {
        const vectors: {
            label: string;
            options: RFC3161TokenFixtureOptions;
            requestCertificate?: boolean;
            externalCertificate?: "invalid" | "decoy";
            trailingDer?: boolean;
        }[] = [
            { label: "raw imprint mismatch", options: { form: "raw", imprint: "mismatch" } },
            { label: "raw digest length", options: { form: "raw", imprint: "wrongLength" } },
            { label: "raw digest algorithm", options: { form: "raw", imprint: "wrongAlgorithm" } },
            { label: "raw missing nonce", options: { form: "raw", responseNonce: "missing" } },
            { label: "full zero nonce", options: { form: "response", responseNonce: "zero" } },
            {
                label: "full negative nonce",
                options: { form: "response", responseNonce: "negative" },
            },
            {
                label: "full nonce mismatch",
                options: { form: "response", responseNonce: new Uint8Array([9]) },
            },
            {
                label: "full policy mismatch",
                options: { form: "response", responsePolicy: "1.2.3.4.999" },
            },
            { label: "raw wrong token type", options: { form: "raw", contentType: "data" } },
            {
                label: "full wrong eContent type",
                options: { form: "response", eContentType: "data" },
            },
            {
                label: "raw eContent with an empty constructed segment",
                options: { form: "raw", eContentEncoding: "constructedEmptySegment" },
            },
            {
                label: "full eContent with a nested constructed segment",
                options: { form: "response", eContentEncoding: "constructedNestedSegment" },
            },
            { label: "raw corrupted CMS", options: { form: "raw", corruptSignature: true } },
            {
                label: "full corrupted CMS",
                options: { form: "response", corruptSignature: true },
            },
            { label: "raw unknown signer SID", options: { form: "raw", signerSid: "zero" } },
            {
                label: "full ambiguous signer SID",
                options: { form: "response", certificates: "ambiguous" },
            },
            { label: "raw multiple SignerInfos", options: { form: "raw", signerCount: 2 } },
            { label: "raw missing ESS", options: { form: "raw", ess: "missing" } },
            { label: "full malformed ESS", options: { form: "response", ess: "malformed" } },
            { label: "raw mismatched ESS", options: { form: "raw", ess: "mismatched" } },
            { label: "full duplicate ESS", options: { form: "response", ess: "duplicate" } },
            { label: "raw unsupported ESS", options: { form: "raw", ess: "unsupported" } },
            { label: "full conflicting ESS", options: { form: "response", ess: "conflicting" } },
            {
                label: "raw ESS wrong first",
                options: { form: "raw", ess: "v1", essAdditional: "wrongFirst" },
            },
            {
                label: "full malformed additional ESS",
                options: { form: "response", ess: "v2", essAdditional: "malformed" },
            },
            {
                label: "raw unsupported additional ESS algorithm",
                options: { form: "raw", ess: "v2", essAdditional: "unsupportedAlgorithm" },
            },
            {
                label: "full malformed ESS policies",
                options: { form: "response", ess: "v1", essPolicies: "malformed" },
            },
            {
                label: "raw ESS v1 first IssuerSerial with forbidden issuer UID",
                options: { form: "raw", ess: "v1", essIssuerSerial: "extraUidFirst" },
            },
            {
                label: "full ESS v1 additional IssuerSerial with forbidden issuer UID",
                options: {
                    form: "response",
                    ess: "v1",
                    essAdditional: "valid",
                    essIssuerSerial: "extraUidAdditional",
                },
            },
            {
                label: "raw ESS v2 first IssuerSerial with forbidden issuer UID",
                options: { form: "raw", ess: "v2", essIssuerSerial: "extraUidFirst" },
            },
            {
                label: "full ESS v2 additional IssuerSerial with forbidden issuer UID",
                options: {
                    form: "response",
                    ess: "v2",
                    essAdditional: "valid",
                    essIssuerSerial: "extraUidAdditional",
                },
            },
            {
                label: "raw ESS policy CPS qualifier with wrong value type",
                options: { form: "raw", ess: "v1", essPolicies: "wrongCpsType" },
            },
            {
                label: "full ESS policy UserNotice qualifier with wrong value type",
                options: { form: "response", ess: "v2", essPolicies: "wrongUserNoticeType" },
            },
            {
                label: "raw ESS policy UserNotice with malformed nested fields",
                options: { form: "raw", ess: "v1", essPolicies: "malformedUserNotice" },
            },
            {
                label: "full ESS policy UserNotice with no notice numbers",
                options: { form: "response", ess: "v2", essPolicies: "emptyUserNoticeNumbers" },
            },
            { label: "raw missing EKU", options: { form: "raw", eku: "missing" } },
            { label: "full duplicate EKU", options: { form: "response", eku: "duplicate" } },
            { label: "raw noncritical EKU", options: { form: "raw", eku: "noncritical" } },
            { label: "full extra EKU", options: { form: "response", eku: "extra" } },
            { label: "raw any EKU", options: { form: "raw", eku: "any" } },
            { label: "full malformed EKU", options: { form: "response", eku: "malformed" } },
            {
                label: "full status rejection",
                options: { form: "response", status: TSAStatus.REJECTION },
            },
            {
                label: "full status waiting",
                options: { form: "response", status: TSAStatus.WAITING },
            },
            {
                label: "full revocation warning",
                options: { form: "response", status: TSAStatus.REVOCATION_WARNING },
            },
            {
                label: "full revocation notification",
                options: { form: "response", status: TSAStatus.REVOCATION_NOTIFICATION },
            },
            { label: "full unknown status", options: { form: "response", status: 6 } },
            {
                label: "full granted response without token",
                options: { form: "response", status: TSAStatus.GRANTED, includeToken: false },
            },
            {
                label: "full rejected response with forbidden token",
                options: { form: "response", status: TSAStatus.REJECTION, includeToken: true },
            },
            {
                label: "raw requested certificate missing",
                options: { form: "raw", certificates: "none" },
            },
            {
                label: "full certReq=false with forbidden embedded certificate",
                requestCertificate: false,
                options: { form: "response", certificates: "signer" },
            },
            {
                label: "raw certReq=false without an external certificate",
                requestCertificate: false,
                options: { form: "raw", certificates: "none" },
            },
            {
                label: "full certReq=false with malformed external certificate",
                requestCertificate: false,
                options: { form: "response", certificates: "none" },
                externalCertificate: "invalid",
            },
            {
                label: "raw certReq=false with an unrelated external certificate",
                requestCertificate: false,
                options: { form: "raw", certificates: "none" },
                externalCertificate: "decoy",
            },
            {
                label: "raw trailing DER",
                options: { form: "raw" },
                trailingDer: true,
            },
            {
                label: "raw ContentInfo indefinite outer length",
                options: { form: "raw", outerTokenFraming: "indefinite" },
            },
            {
                label: "raw ContentInfo non-minimal outer length",
                options: { form: "raw", outerTokenFraming: "nonMinimal" },
            },
            {
                label: "full response nested ContentInfo indefinite outer length",
                options: { form: "response", outerTokenFraming: "indefinite" },
            },
            {
                label: "full response nested ContentInfo non-minimal outer length",
                options: { form: "response", outerTokenFraming: "nonMinimal" },
            },
            {
                label: "full TimeStampResp indefinite outer length",
                options: { form: "response", responseOuterFraming: "indefinite" },
            },
            {
                label: "full TimeStampResp non-minimal outer length",
                options: { form: "response", responseOuterFraming: "nonMinimal" },
            },
            {
                label: "raw ContentInfo high-tag 3f 10",
                options: { form: "raw", outerTokenFraming: "highTagShort" },
            },
            {
                label: "raw ContentInfo high-tag 3f 80 10",
                options: { form: "raw", outerTokenFraming: "highTagLeadingZero" },
            },
            {
                label: "full response nested ContentInfo high-tag 3f 10",
                options: { form: "response", outerTokenFraming: "highTagShort" },
            },
            {
                label: "full response nested ContentInfo high-tag 3f 80 10",
                options: { form: "response", outerTokenFraming: "highTagLeadingZero" },
            },
            {
                label: "full TimeStampResp high-tag 3f 10",
                options: { form: "response", responseOuterFraming: "highTagShort" },
            },
            {
                label: "full TimeStampResp high-tag 3f 80 10",
                options: { form: "response", responseOuterFraming: "highTagLeadingZero" },
            },
        ];

        for (const vector of vectors) {
            const session = await createSession();
            const request = await session.createTimestampRequest({
                policy: "1.2.3.4.5",
                requestCertificate: vector.requestCertificate,
            });
            const token = await createRFC3161TokenFixtureFromRequest(request, vector.options);
            const input = vector.trailingDer ? new Uint8Array([...token.input, 0]) : token.input;
            const validationOptions =
                vector.externalCertificate === "invalid"
                    ? { signerCertificates: [new Uint8Array([0x30, 0x00])] }
                    : vector.externalCertificate === "decoy"
                      ? { signerCertificates: [token.decoyCertificate] }
                      : undefined;
            embedSpy.mockClear();

            await expect(
                session.embedTimestampToken(input, validationOptions)
            ).rejects.toBeInstanceOf(TimestampError);
            expect(embedSpy, vector.label).not.toHaveBeenCalled();
        }
    });

    it("requires an external signer certificate for a certReq=false manual response", async () => {
        const session = await createSession();
        const request = await session.createTimestampRequest({ requestCertificate: false });
        const token = await createRFC3161TokenFixtureFromRequest(request, {
            form: "response",
            certificates: "none",
        });

        await expect(session.embedTimestampToken(token.input)).rejects.toBeInstanceOf(
            TimestampError
        );
        expect(embedSpy).not.toHaveBeenCalled();

        await expect(
            session.embedTimestampToken(token.input, {
                signerCertificates: [token.signerCertificate],
            })
        ).resolves.toEqual(new Uint8Array([0x25, 0x50, 0x44, 0x46]));
        expect(embedSpy).toHaveBeenCalledTimes(1);
    });
});
