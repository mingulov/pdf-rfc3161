import { describe, expect, it } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
    extractTimestamps,
    verifyTimestamp,
    type ExtractedTimestamp,
} from "../../../core/src/pdf/extract.js";
import { TimestampSession } from "../../../core/src/session.js";
import {
    TimestampError,
    TimestampErrorCode,
    TSAStatus,
    type TimestampInfo,
} from "../../../core/src/types.js";
import {
    createRFC3161TokenFixture,
    createRFC3161TokenFixtureFromRequest,
    encodedTstInfoEContentEncoding,
    FIXTURE_GENTIME_ISO,
    type FixtureRequestContext,
    type RFC3161TokenFixture,
    type RFC3161TokenFixtureOptions,
} from "../fixtures/rfc3161-token.js";
import {
    parseTimestampToken as parseStrictToken,
    selectSignerCertificate,
} from "../../../core/src/tsa/token-validation.js";

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

function minimalPdf(): Uint8Array {
    return new TextEncoder().encode(`%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>
endobj
xref
0 4
0000000000 65535 f${" "}
0000000009 00000 n${" "}
0000000058 00000 n${" "}
0000000115 00000 n${" "}
trailer
<< /Size 4 /Root 1 0 R >>
startxref
203
%%EOF`);
}

async function prepareSessionWithToken(
    options: Omit<
        RFC3161TokenFixtureOptions,
        "data" | "hashAlgorithm" | "nonce" | "policy" | "requestCertificate"
    >
): Promise<{
    session: TimestampSession;
    token: Omit<RFC3161TokenFixture, "context">;
}> {
    const session = new TimestampSession(minimalPdf(), {
        enableLTV: false,
        prepareOptions: { signatureSize: 4096 },
    });
    const request = await session.createTimestampRequest({
        hashAlgorithm: "SHA-256",
        requestCertificate: true,
    });
    const token = await createRFC3161TokenFixtureFromRequest(request, {
        form: "raw",
        ...options,
    });
    return { session, token };
}

function makeExtractedTimestamp(token: Uint8Array): ExtractedTimestamp {
    return {
        token,
        contentsValueBytes: token.slice(),
        info: {} as TimestampInfo,
        fieldName: "Test",
        coversWholeDocument: true,
        verified: false,
        byteRange: [0, 0, 0, 0],
    };
}

function indexOfBytes(haystack: Uint8Array, needle: Uint8Array): number {
    if (needle.length === 0 || needle.length > haystack.length) return -1;
    for (let index = 0; index + needle.length <= haystack.length; index++) {
        let found = true;
        for (let offset = 0; offset < needle.length; offset++) {
            if (haystack[index + offset] !== needle[offset]) {
                found = false;
                break;
            }
        }
        if (found) return index;
    }
    return -1;
}

/** Rewrites the fixture validity window in place to an expired range (2020-2021). */
function expireValidityInPlace(bytes: Uint8Array): void {
    const encoder = new TextEncoder();
    const swaps: [string, string][] = [
        ["250101000000Z", "200101000000Z"],
        ["300101000000Z", "210101000000Z"],
    ];
    for (const [from, to] of swaps) {
        const content = encoder.encode(from);
        const needle = new Uint8Array([0x17, content.length, ...content]);
        const at = indexOfBytes(bytes, needle);
        expect(at).toBeGreaterThanOrEqual(0);
        expect(indexOfBytes(bytes.subarray(at + 1), needle)).toBe(-1);
        bytes.set(encoder.encode(to), at + 2);
    }
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

    it("rejects signers that were expired or not yet valid at genTime, across raw, full, and external inputs", async () => {
        const embedded: RFC3161TokenFixtureOptions[] = [
            { certificateValidity: "expired" },
            { certificateValidity: "expired", form: "response" },
            { certificateValidity: "notYetValid" },
            { certificateValidity: "notYetValid", form: "response" },
        ];
        for (const options of embedded) {
            const token = await fixture(options);
            await expect(validate(token.input, token.context)).rejects.toMatchObject({
                code: TimestampErrorCode.VERIFICATION_FAILED,
                message: expect.stringContaining("not valid at genTime"),
            });
        }

        const external: RFC3161TokenFixtureOptions[] = [
            {
                certificateValidity: "expired",
                requestCertificate: false,
                certificates: "none",
            },
            {
                certificateValidity: "notYetValid",
                form: "response",
                requestCertificate: false,
                certificates: "none",
            },
        ];
        for (const options of external) {
            const token = await fixture(options);
            await expect(
                validate(token.input, token.context, {
                    signerCertificates: [token.signerCertificate],
                })
            ).rejects.toMatchObject({
                code: TimestampErrorCode.VERIFICATION_FAILED,
                message: expect.stringContaining("not valid at genTime"),
            });
        }
    });

    it("rejects a signer certificate with unparseable validity dates, embedded or external", async () => {
        for (const form of ["raw", "response"] as const) {
            const token = await fixture({ form, corruptSignerValidity: true });
            await expect(validate(token.input, token.context)).rejects.toMatchObject({
                code: TimestampErrorCode.VERIFICATION_FAILED,
                message: expect.stringContaining("not valid at genTime"),
            });
        }

        const external = await fixture({
            requestCertificate: false,
            certificates: "none",
            corruptSignerValidity: true,
        });
        await expect(
            validate(external.input, external.context, {
                signerCertificates: [external.signerCertificate],
            })
        ).rejects.toMatchObject({
            code: TimestampErrorCode.VERIFICATION_FAILED,
            message: expect.stringContaining("not valid at genTime"),
        });
    });

    it("treats non-finite and non-Date validity bounds as not valid at genTime", async () => {
        const { isCertValidAtTime } = await import("../../../core/src/pki/pki-utils.js");
        const start = new Date("2025-01-01T00:00:00Z");
        const end = new Date("2030-01-01T00:00:00Z");
        const genTime = new Date(FIXTURE_GENTIME_ISO);
        const certWith = (notBefore: unknown, notAfter: unknown): pkijs.Certificate =>
            ({
                notBefore: { value: notBefore },
                notAfter: { value: notAfter },
            }) as unknown as pkijs.Certificate;

        expect(isCertValidAtTime(certWith(start, end), genTime)).toBe(true);
        expect(isCertValidAtTime(certWith(new Date(NaN), end), genTime)).toBe(false);
        expect(isCertValidAtTime(certWith(start, new Date(NaN)), genTime)).toBe(false);
        expect(isCertValidAtTime(certWith(start, end), new Date(NaN))).toBe(false);
        expect(isCertValidAtTime(certWith("2025-01-01T00:00:00Z", end), genTime)).toBe(false);
        expect(
            isCertValidAtTime(certWith(start, end), "2026-08-24T00:00:00Z" as unknown as Date)
        ).toBe(false);
    });

    it("accepts signers whose validity bounds exactly equal the token genTime", async () => {
        const vectors: RFC3161TokenFixtureOptions[] = [
            {
                signerValidityDates: {
                    notBefore: FIXTURE_GENTIME_ISO,
                    notAfter: "2030-01-01T00:00:00Z",
                },
            },
            {
                form: "response",
                signerValidityDates: {
                    notBefore: "2025-01-01T00:00:00Z",
                    notAfter: FIXTURE_GENTIME_ISO,
                },
            },
        ];
        for (const options of vectors) {
            const token = await fixture(options);
            const result = await validate(token.input, token.context);
            expect(result.token).toEqual(token.rawToken);
        }
    });

    it("still embeds a token whose signer has since expired but was valid at genTime, byte-for-byte (C05)", async () => {
        // The signer lapsed after issuance: notAfter falls between the fixed
        // genTime and today, so the certificate is expired at every run date
        // past 2026-09-01 yet covered the moment the token was minted.
        const genTime = new Date(FIXTURE_GENTIME_ISO).getTime();
        const notAfter = new Date("2026-09-01T00:00:00Z").getTime();
        expect(notAfter).toBeGreaterThan(genTime);
        expect(notAfter).toBeLessThan(Date.now());

        const session = new TimestampSession(minimalPdf(), {
            enableLTV: false,
            prepareOptions: { signatureSize: 4096 },
        });
        const request = await session.createTimestampRequest({
            hashAlgorithm: "SHA-256",
            requestCertificate: true,
        });
        const token = await createRFC3161TokenFixtureFromRequest(request, {
            form: "raw",
            signerValidityDates: {
                notBefore: "2025-01-01T00:00:00Z",
                notAfter: "2026-09-01T00:00:00Z",
            },
        });

        const pdf = await session.embedTimestampToken(token.rawToken);
        const extracted = await extractTimestamps(pdf);
        expect(extracted).toHaveLength(1);
        const contents = extracted[0]?.contentsValueBytes;
        expect(extracted[0]?.token).toEqual(token.rawToken);
        expect(contents?.slice(0, token.rawToken.length)).toEqual(token.rawToken);
        const padding = contents?.slice(token.rawToken.length);
        expect(padding?.length).toBeGreaterThan(0);
        expect(padding).toEqual(new Uint8Array(padding?.length ?? 0));

        // Post-embed verification must agree: the signer covered genTime.
        const verified = await verifyTimestamp(extracted[0]!, {
            pdf,
            strictESSValidation: true,
        });
        expect(verified.verified).toBe(true);
    });
});

describe("signer validity encodings (T09a fix round 1)", () => {
    it("rejects notBefore-only corruption with a valid notAfter, in raw and response forms", async () => {
        for (const form of ["raw", "response"] as const) {
            const { session, token } = await prepareSessionWithToken({
                form,
                signerValidityWire: { notBefore: "X".repeat(13) },
            });
            await expect(session.embedTimestampToken(token.input)).rejects.toMatchObject({
                code: TimestampErrorCode.VERIFICATION_FAILED,
                message: expect.stringContaining("not valid at genTime"),
            });
        }
    });

    it("rejects notAfter-only corruption with a valid notBefore, in raw and response forms", async () => {
        // Non-digit content always degrades to 1899, which predates any
        // genTime, so this vector already rejected pre-fix via the window
        // check; post-fix the encoding check rejects it first. The red-able
        // notAfter vector is the day-32 rollover in the matrix below.
        for (const form of ["raw", "response"] as const) {
            const { session, token } = await prepareSessionWithToken({
                form,
                signerValidityWire: { notAfter: "X".repeat(13) },
            });
            await expect(session.embedTimestampToken(token.input)).rejects.toMatchObject({
                code: TimestampErrorCode.VERIFICATION_FAILED,
                message: expect.stringContaining("not valid at genTime"),
            });
        }
    });

    it("rejects UTCTime calendar rollovers that land inside the window", async () => {
        const vectors: { name: string; wire: { notBefore?: string; notAfter?: string } }[] = [
            { name: "month 13", wire: { notBefore: "251301000000Z" } },
            { name: "day 32", wire: { notAfter: "260832000000Z" } },
            { name: "Feb 30 non-leap", wire: { notBefore: "250230000000Z" } },
            { name: "Feb 29 non-leap", wire: { notBefore: "250229000000Z" } },
            // Self-consistent garbage: re-encodes byte-identically, so only
            // the parser-error check rejects it.
            { name: "1899 fixed point", wire: { notBefore: "-11130000000Z" } },
        ];
        for (const vector of vectors) {
            const { session, token } = await prepareSessionWithToken({
                signerValidityWire: vector.wire,
            });
            await expect(
                session.embedTimestampToken(token.rawToken),
                vector.name
            ).rejects.toMatchObject({
                code: TimestampErrorCode.VERIFICATION_FAILED,
                message: expect.stringContaining("not valid at genTime"),
            });
        }
    });

    it("rejects a GeneralizedTime calendar rollover", async () => {
        const { session, token } = await prepareSessionWithToken({
            signerValidityGeneralizedTime: true,
            signerValidityWire: { notBefore: "20251301000000Z" },
        });
        await expect(session.embedTimestampToken(token.rawToken)).rejects.toMatchObject({
            code: TimestampErrorCode.VERIFICATION_FAILED,
            message: expect.stringContaining("not valid at genTime"),
        });
    });

    it("accepts Feb 29 of a leap year as a control", async () => {
        const { session, token } = await prepareSessionWithToken({
            signerValidityWire: { notBefore: "240229000000Z" },
        });
        const pdf = await session.embedTimestampToken(token.rawToken);
        const extracted = await extractTimestamps(pdf);
        expect(extracted).toHaveLength(1);
        expect(extracted[0]?.token).toEqual(token.rawToken);
    });

    it("accepts well-formed GeneralizedTime validity bounds", async () => {
        const { session, token } = await prepareSessionWithToken({
            signerValidityGeneralizedTime: true,
        });
        const pdf = await session.embedTimestampToken(token.rawToken);
        const extracted = await extractTimestamps(pdf);
        expect(extracted).toHaveLength(1);
        expect(extracted[0]?.token).toEqual(token.rawToken);
    });

    it("rejects corrupted GeneralizedTime validity with a coded parse error", async () => {
        // T11 (0x18) intentional delta: GeneralizedTime corruption still
        // rejects during ASN.1 parsing before any validity gate runs, but
        // the plain asn1js Error is now normalized to a coded
        // TimestampError instead of escaping uncoded.
        const { session, token } = await prepareSessionWithToken({
            signerValidityGeneralizedTime: true,
            signerValidityWire: { notBefore: "X".repeat(15) },
        });
        const error = await session.embedTimestampToken(token.rawToken).then(
            () => undefined,
            (cause: unknown) => cause
        );
        expect(error).toBeInstanceOf(TimestampError);
        expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
        expect((error as TimestampError).message).toBe("Timestamp token: ASN.1 parse failed");
    });

    it("rejects externally supplied corrupted validity at the same gate", async () => {
        const token = await fixture({
            requestCertificate: false,
            certificates: "none",
            signerValidityWire: { notBefore: "X".repeat(13) },
        });
        await expect(
            validate(token.input, token.context, {
                signerCertificates: [token.signerCertificate],
            })
        ).rejects.toMatchObject({
            code: TimestampErrorCode.VERIFICATION_FAILED,
            message: expect.stringContaining("not valid at genTime"),
        });
    });

    it("fails post-embed verification for corrupted signer validity", async () => {
        const token = await fixture({ signerValidityWire: { notBefore: "X".repeat(13) } });
        const result = await verifyTimestamp(makeExtractedTimestamp(token.rawToken), {
            strictESSValidation: true,
        });
        expect(result.verified).toBe(false);
        expect(result.verificationError ?? "").toContain("not valid at genTime");
    });

    it("reports original encoding health directly, failing closed without TBS bytes", async () => {
        const module = await import("../../../core/src/pki/pki-utils.js");
        expect(typeof module.validityOk).toBe("function");
        const programmatic = new pkijs.Certificate();
        programmatic.notBefore = new pkijs.Time({
            type: pkijs.TimeType.GeneralizedTime,
            value: new Date("2025-01-01T00:00:00Z"),
        });
        programmatic.notAfter = new pkijs.Time({
            type: pkijs.TimeType.GeneralizedTime,
            value: new Date("2030-01-01T00:00:00Z"),
        });
        expect(module.validityOk(programmatic)).toBe(false);

        const good = await fixture({});
        const goodSchema = asn1js.fromBER(good.signerCertificate);
        expect(goodSchema.offset).toBe(good.signerCertificate.length);
        expect(module.validityOk(new pkijs.Certificate({ schema: goodSchema.result }))).toBe(true);

        const bad = await fixture({ signerValidityWire: { notBefore: "251301000000Z" } });
        const badSchema = asn1js.fromBER(bad.signerCertificate);
        expect(badSchema.offset).toBe(bad.signerCertificate.length);
        expect(module.validityOk(new pkijs.Certificate({ schema: badSchema.result }))).toBe(false);
    });

    it("accepts mixed UTCTime-notBefore and GeneralizedTime-notAfter encodings", async () => {
        // Long-lived shape (e.g. notBefore 2026, notAfter 2060): pins that
        // validityOk accepts mixed tags. Signature validity is irrelevant
        // here because CMS signature verification is a separate gate.
        const module = await import("../../../core/src/pki/pki-utils.js");
        const base = await fixture({});
        const cert = new pkijs.Certificate({
            schema: asn1js.fromBER(base.signerCertificate).result,
        });
        cert.notAfter.type = pkijs.TimeType.GeneralizedTime;
        // encodeFlag=true: re-encode TBS from objects (default reuses cached tbsView).
        const mixed = new Uint8Array(cert.toSchema(true).toBER(false));
        const schema = asn1js.fromBER(mixed.slice().buffer);
        expect(schema.offset).toBe(mixed.length);
        const reparsed = new pkijs.Certificate({ schema: schema.result });
        expect(reparsed.notBefore.type).toBe(0);
        expect(reparsed.notAfter.type).toBe(1);
        expect(module.validityOk(reparsed)).toBe(true);
    });

    it("embeds the validated bytes when the caller mutates the input mid-flight", async () => {
        const { session, token } = await prepareSessionWithToken({});
        const input = new Uint8Array(token.rawToken);
        const pending = session.embedTimestampToken(input);
        expireValidityInPlace(input);
        const mutated = new Uint8Array(input);
        const pdf = await pending;
        const extracted = await extractTimestamps(pdf);
        expect(extracted).toHaveLength(1);
        expect(extracted[0]?.token).toEqual(token.rawToken);
        expect(extracted[0]?.token).not.toEqual(mutated);
    });

    it("embeds the validated bytes when a sliced-view input is mutated mid-flight", async () => {
        const { session, token } = await prepareSessionWithToken({});
        const padded = new Uint8Array(token.rawToken.length + 64);
        padded.set(token.rawToken, 32);
        const input = padded.subarray(32, 32 + token.rawToken.length);
        const pending = session.embedTimestampToken(input);
        expireValidityInPlace(padded);
        const mutated = new Uint8Array(input);
        const pdf = await pending;
        const extracted = await extractTimestamps(pdf);
        expect(extracted).toHaveLength(1);
        expect(extracted[0]?.token).toEqual(token.rawToken);
        expect(extracted[0]?.token).not.toEqual(mutated);
    });

    it("embeds the validated bytes when a Buffer-view input is mutated mid-flight", async () => {
        // Buffer.slice() shares storage (unlike Uint8Array.slice()), so the
        // snapshot must be an unconditional copy to survive a Buffer input.
        const { session, token } = await prepareSessionWithToken({});
        const backing = Buffer.alloc(token.rawToken.length + 64);
        const input = backing.subarray(32, 32 + token.rawToken.length);
        input.set(token.rawToken);
        const pending = session.embedTimestampToken(input);
        expireValidityInPlace(backing);
        const mutated = new Uint8Array(input);
        const pdf = await pending;
        const extracted = await extractTimestamps(pdf);
        expect(extracted).toHaveLength(1);
        expect(extracted[0]?.token).toEqual(token.rawToken);
        expect(extracted[0]?.token).not.toEqual(mutated);
    });
});

// T11 (R19/S19): the strict parser enforces the TSTInfo profile --
// version 1 (RFC 3161 S2.4: servers MUST provide v1, requesters MUST
// recognize v1, and no v2 exists), no unsupported critical extensions
// (RFC 5280 S4.2 criticality; this library supports none), and
// absent-or-NULL digest parameters (RFC 5754 S2: MUST accept NULL,
// MUST generate absent). Surgery below re-encodes the token, which
// breaks the CMS signature by design; the strict parse runs before
// any signature check, so profile rejections surface regardless.
describe("TSTInfo profile (T11/R19/S19)", () => {
    function withModifiedTstInfo(
        token: Uint8Array,
        modify: (tst: asn1js.Sequence) => void
    ): Uint8Array {
        const parsed = asn1js.fromBER(new Uint8Array(token).buffer);
        if (parsed.offset === -1) throw new Error("fixture token is not DER");
        const root = parsed.result as asn1js.Sequence;
        const content = root.valueBlock.value[1] as asn1js.Constructed;
        const signedData = content.valueBlock.value[0] as asn1js.Sequence;
        const encap = signedData.valueBlock.value[2] as asn1js.Sequence;
        const wrapped = encap.valueBlock.value[1] as asn1js.Constructed;
        const eContent = wrapped.valueBlock.value[0] as asn1js.OctetString;
        const segments = eContent.idBlock.isConstructed
            ? (eContent.valueBlock.value as asn1js.OctetString[])
            : [eContent];
        const total = segments.reduce((n, s) => n + s.valueBlock.valueHexView.length, 0);
        const tstBytes = new Uint8Array(total);
        let offset = 0;
        for (const segment of segments) {
            const view = new Uint8Array(segment.valueBlock.valueHexView);
            tstBytes.set(view, offset);
            offset += view.length;
        }
        const tstParsed = asn1js.fromBER(new Uint8Array(tstBytes).buffer);
        if (tstParsed.offset === -1) throw new Error("fixture TSTInfo is not DER");
        const tst = tstParsed.result as asn1js.Sequence;
        modify(tst);
        wrapped.valueBlock.value[0] = new asn1js.OctetString({
            valueHex: new Uint8Array(tst.toBER(false)).buffer,
        });
        return new Uint8Array(root.toBER(false));
    }

    function messageImprintAlgId(tst: asn1js.Sequence): asn1js.Sequence {
        const imprint = tst.valueBlock.value[2] as asn1js.Sequence;
        return imprint.valueBlock.value[0] as asn1js.Sequence;
    }

    function tstExtension(critical: boolean): asn1js.Constructed {
        const extension = new pkijs.Extension({
            extnID: "1.2.3.4.5.6.7",
            critical,
            extnValue: new asn1js.OctetString({
                valueHex: new Uint8Array([1, 2, 3]).buffer,
            }).toBER(false),
        });
        return new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 1 },
            value: [extension.toSchema()],
        });
    }

    function expectMalformedProfile(token: Uint8Array, message: string): void {
        try {
            parseStrictToken(token);
        } catch (error) {
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.MALFORMED_RESPONSE);
            expect((error as TimestampError).message).toBe(message);
            return;
        }
        throw new Error(`expected the strict parser to reject: ${message}`);
    }

    it("accepts the unmodified fixture profile (surgery-harness control)", async () => {
        const token = (await fixture({ form: "raw" })).rawToken;
        const rebuilt = withModifiedTstInfo(token, () => {});
        expect(parseStrictToken(rebuilt).tstInfo.version).toBe(1);
    });

    it("requires TSTInfo version 1", async () => {
        const token = (await fixture({ form: "raw" })).rawToken;
        const mutated = withModifiedTstInfo(token, (tst) => {
            tst.valueBlock.value[0] = new asn1js.Integer({ value: 2 });
        });
        expectMalformedProfile(mutated, "TSTInfo version must be 1");
    });

    it("rejects an unsupported critical TSTInfo extension", async () => {
        const token = (await fixture({ form: "raw" })).rawToken;
        const mutated = withModifiedTstInfo(token, (tst) => {
            tst.valueBlock.value.push(tstExtension(true));
        });
        expectMalformedProfile(mutated, "TSTInfo has an unsupported critical extension");
    });

    it("accepts an unknown non-critical TSTInfo extension", async () => {
        const token = (await fixture({ form: "raw" })).rawToken;
        const mutated = withModifiedTstInfo(token, (tst) => {
            tst.valueBlock.value.push(tstExtension(false));
        });
        expect(parseStrictToken(mutated).tstInfo.extensions?.length).toBe(1);
    });

    it("accepts absent and NULL digest parameters", async () => {
        const token = (await fixture({ form: "raw" })).rawToken;
        expect(parseStrictToken(token).tstInfo.messageImprint.hashAlgorithm.algorithmParams).toBeUndefined();
        const nulled = withModifiedTstInfo(token, (tst) => {
            messageImprintAlgId(tst).valueBlock.value.push(new asn1js.Null());
        });
        const params: unknown = parseStrictToken(nulled).tstInfo.messageImprint.hashAlgorithm
            .algorithmParams;
        expect(params).toBeInstanceOf(asn1js.Null);
    });

    it("rejects non-NULL digest parameters", async () => {
        const token = (await fixture({ form: "raw" })).rawToken;
        const octetParams = withModifiedTstInfo(token, (tst) => {
            messageImprintAlgId(tst).valueBlock.value.push(
                new asn1js.OctetString({ valueHex: new Uint8Array([9, 9]).buffer })
            );
        });
        expectMalformedProfile(octetParams, "TSTInfo digest parameters must be absent or NULL");
        const integerParams = withModifiedTstInfo(token, (tst) => {
            messageImprintAlgId(tst).valueBlock.value.push(new asn1js.Integer({ value: 0 }));
        });
        expectMalformedProfile(integerParams, "TSTInfo digest parameters must be absent or NULL");
    });
});

// T11 (0x18): asn1js throws a plain Error on corrupted GeneralizedTime
// content. The strict token parser normalizes that to a coded
// TimestampError, and SKI selection fails closed (no match) instead of
// letting the decode throw escape.
describe("corrupted GeneralizedTime normalization (T11/0x18)", () => {
    function corruptOnlyGeneralizedTime(token: Uint8Array): Uint8Array {
        const hits: number[] = [];
        for (let at = 0; at + 17 <= token.length; at++) {
            if (token[at] === 0x18 && token[at + 1] === 0x0f) hits.push(at);
        }
        // The fixture token carries exactly one GeneralizedTime (the
        // TSTInfo genTime); anything else means the harness is stale.
        expect(hits).toHaveLength(1);
        const out = new Uint8Array(token);
        out.set(new TextEncoder().encode("2060010100000!Z"), hits[0]! + 2);
        return out;
    }

    it("codes a corrupted TSTInfo genTime as INVALID_RESPONSE", async () => {
        const token = (await fixture({ form: "raw" })).rawToken;
        try {
            parseStrictToken(corruptOnlyGeneralizedTime(token));
        } catch (error) {
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
            expect((error as TimestampError).message).toBe("TSTInfo: ASN.1 parse failed");
            return;
        }
        throw new Error("expected the strict parser to reject a corrupted genTime");
    });

    it("selects no signer (coded) when the SKI extension is undecodable", () => {
        const cert = new pkijs.Certificate();
        const hostile = new Uint8Array([0x18, 0x0f, ...new TextEncoder().encode("2030010100000!Z")]);
        cert.extensions = [
            new pkijs.Extension({
                extnID: "2.5.29.14",
                critical: false,
                extnValue: hostile.buffer,
            }),
        ];
        const signerInfo = new pkijs.SignerInfo();
        (signerInfo as unknown as { sid: unknown }).sid = new asn1js.Primitive({
            idBlock: { tagClass: 3, tagNumber: 0 },
            valueHex: new Uint8Array(20).buffer,
        });
        try {
            selectSignerCertificate(signerInfo, [cert]);
        } catch (error) {
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.VERIFICATION_FAILED);
            expect((error as TimestampError).message).toContain("matched 0 signer certificates");
            return;
        }
        throw new Error("expected SKI selection to fail closed on undecodable bytes");
    });
});
