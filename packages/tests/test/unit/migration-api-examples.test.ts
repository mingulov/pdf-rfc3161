import {
    SimpleTrustStore,
    TimestampSession,
    createTimestampRequest,
    sendTimestampRequest,
    timestampPdfMultiple,
    verifyTimestamp,
    type ExtractedTimestamp,
    type TSAConfig,
    type TimestampRequestOptions,
    type VerificationOptions,
} from "pdf-rfc3161";
import { addVRIForSignature } from "pdf-rfc3161/internals";
import { describe, expect, expectTypeOf, it } from "vitest";

type HasNoStandaloneResponseValidator =
    "validateTimestampResponse" extends keyof typeof import("pdf-rfc3161") ? false : true;
type MultipleTimestampOptions = Parameters<typeof timestampPdfMultiple>[0];
type HasNoMisplacedEkuOption = "requireTimestampingEKU" extends keyof MultipleTimestampOptions
    ? false
    : true;

const hasNoStandaloneResponseValidator: HasNoStandaloneResponseValidator = true;
const hasNoMisplacedEkuOption: HasNoMisplacedEkuOption = true;

async function typecheckMigrationExamples(
    pdf: Uint8Array,
    timestamp: ExtractedTimestamp,
    tsa: TSAConfig,
    rootCertificate: Uint8Array,
    crl: Uint8Array,
    ocspResponse: Uint8Array
): Promise<void> {
    const requestOptions = {
        hashAlgorithm: "SHA-256",
        policy: "1.2.3.4",
    } satisfies TimestampRequestOptions;
    const { request, nonce } = await createTimestampRequest(pdf, requestOptions);
    const responseBytes = await sendTimestampRequest(request, tsa);

    const session = new TimestampSession(pdf, { hashAlgorithm: "SHA-256" });
    const sessionRequest = await session.createTimestampRequest();
    const sessionResponse = await sendTimestampRequest(sessionRequest, tsa);
    const timestampedPdf = await session.embedTimestampToken(sessionResponse);
    expectTypeOf(nonce).toEqualTypeOf<Uint8Array>();
    expectTypeOf(responseBytes).toEqualTypeOf<Uint8Array>();
    expectTypeOf(timestampedPdf).toEqualTypeOf<Uint8Array>();

    const verificationOptions = {
        requireTimestampingEKU: false,
        requireCertValidAtGenTime: false,
    } satisfies VerificationOptions;
    await verifyTimestamp(timestamp, verificationOptions);

    const trustStore = new SimpleTrustStore();
    trustStore.addCertificate(rootCertificate);
    await verifyTimestamp(timestamp, { trustStore });
    await verifyTimestamp(timestamp);

    await timestampPdfMultiple({
        pdf,
        tsaList: [tsa],
        signatureFieldName: "Timestamp",
        enableLTV: false,
    });

    await addVRIForSignature(
        pdf,
        { fieldName: "Timestamp" },
        {
            validationData: {
                certificates: [rootCertificate],
                crls: [crl],
                ocspResponses: [ocspResponse],
            },
        }
    );
}

describe("migration API examples", () => {
    it("keeps the documented public API boundaries type-compatible", () => {
        expect(typecheckMigrationExamples).toBeTypeOf("function");
        expect(hasNoStandaloneResponseValidator).toBe(true);
        expect(hasNoMisplacedEkuOption).toBe(true);
    });
});
