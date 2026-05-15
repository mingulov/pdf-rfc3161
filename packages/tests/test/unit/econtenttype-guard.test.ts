import { describe, it, expect, vi } from "vitest";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { verifyTimestamp, type ExtractedTimestamp } from "../../../core/src/pdf/extract.js";
import { type TimestampInfo } from "../../../core/src/types.js";

// Constants
const OID_ID_DATA = "1.2.840.113549.1.7.1";
const OID_ID_CT_TSTINFO = "1.2.840.113549.1.9.16.1.4";
const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";

// Build a minimal SignedData wrapped in a ContentInfo. Caller picks the
// inner eContentType: legitimate timestamps use id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4);
// passing id-data simulates a crafted CMS where the inner content is arbitrary
// bytes signed under id-data -- what we must reject.
function buildSignedDataToken(eContentType: string): Uint8Array {
    const signedData = new pkijs.SignedData({
        version: 3,
        encapContentInfo: new pkijs.EncapsulatedContentInfo({
            eContentType,
            eContent: new asn1js.OctetString({ valueHex: new Uint8Array([0x01]).buffer }),
        }),
        signerInfos: [
            new pkijs.SignerInfo({
                version: 1,
                sid: new pkijs.IssuerAndSerialNumber({
                    issuer: new pkijs.RelativeDistinguishedNames({
                        typesAndValues: [
                            new pkijs.AttributeTypeAndValue({
                                type: "2.5.4.3",
                                value: new asn1js.PrintableString({ value: "Test" }),
                            }),
                        ],
                    }),
                    serialNumber: new asn1js.Integer({ value: 1 }),
                }),
                digestAlgorithm: new pkijs.AlgorithmIdentifier({
                    algorithmId: "2.16.840.1.101.3.4.2.1",
                }),
            }),
        ],
    });

    const contentInfo = new pkijs.ContentInfo({
        contentType: OID_SIGNED_DATA,
        content: signedData.toSchema(),
    });

    return new Uint8Array(contentInfo.toSchema().toBER(false));
}

function makeExtractedTimestamp(token: Uint8Array): ExtractedTimestamp {
    return {
        token,
        info: {} as TimestampInfo,
        fieldName: "Test",
        coversWholeDocument: true,
        verified: false,
        byteRange: [0, 0, 0, 0],
    };
}

describe("eContentType guard (H2)", () => {
    it("rejects a SignedData whose eContentType is not id-ct-TSTInfo", async () => {
        // Make signature verification pass so the eContentType check is the
        // only thing that can reject the token.
        vi.spyOn(pkijs.SignedData.prototype, "verify").mockResolvedValue({
            signatureVerified: true,
            signerVerified: true,
            message: "OK",
            code: 0,
            date: new Date(),
            certificatePath: [],
        } as unknown as pkijs.SignedDataVerifyResult);

        const craftedToken = buildSignedDataToken(OID_ID_DATA);
        const result = await verifyTimestamp(makeExtractedTimestamp(craftedToken));

        expect(result.verified).toBe(false);
        expect(result.verificationError ?? "").toMatch(/content.?type|TSTInfo/i);
    });

    it("does not reject a SignedData whose eContentType is id-ct-TSTInfo", async () => {
        // The workaround replaces eContentType with id-data before verify so
        // pkijs will validate the attached content hash. We are not testing
        // that path here; we only check that the H2 guard does not fire when
        // the original eContentType is the legitimate timestamp OID.
        vi.spyOn(pkijs.SignedData.prototype, "verify").mockResolvedValue({
            signatureVerified: true,
            signerVerified: true,
            message: "OK",
            code: 0,
            date: new Date(),
            certificatePath: [],
        } as unknown as pkijs.SignedDataVerifyResult);

        const legitToken = buildSignedDataToken(OID_ID_CT_TSTINFO);
        const result = await verifyTimestamp(makeExtractedTimestamp(legitToken));

        // Either verified=true OR a different non-eContentType error
        // (e.g. missing ESS attribute) -- definitely NOT the H2 rejection.
        expect(result.verificationError ?? "").not.toMatch(/content.?type|TSTInfo/i);
    });
});
