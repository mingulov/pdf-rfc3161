import { describe, it, expect } from "vitest";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { verifyTimestamp, ExtractedTimestamp } from "../../src/pdf/extract.js";
import { TimestampInfo } from "../../src/types.js";

// Helper to create a dummy timestamp token
function createDummyTimestamp(withESS: boolean): Uint8Array {
    const signedData = new pkijs.SignedData({
        version: 3,
        encapContentInfo: new pkijs.EncapsulatedContentInfo({
            eContentType: "1.2.840.113549.1.7.1", // id-data
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
                    algorithmId: "2.16.840.1.101.3.4.2.1", // SHA-256
                }),
            }),
        ],
    });

    if (withESS) {
        // Add signing-certificate-v2 attribute
        const attr = new pkijs.Attribute({
            type: "1.2.840.113549.1.9.16.2.47", // id-aa-signingCertificateV2
            values: [
                new asn1js.OctetString({ valueHex: new Uint8Array([0x00]).buffer }), // Dummy value
            ],
        });

        const signerInfo = signedData.signerInfos[0];
        if (signerInfo) {
            signerInfo.signedAttrs = new pkijs.SignedAndUnsignedAttributes({
                type: 0, // signedAttrs
                attributes: [attr],
            });
        }
    }

    const contentInfo = new pkijs.ContentInfo({
        contentType: "1.2.840.113549.1.7.2", // signedData
        content: signedData.toSchema(),
    });

    return new Uint8Array(contentInfo.toSchema().toBER(false));
}

// Mock verifies to always pass cryptographic signature check
// We are only testing the attribute logic here
import { vi } from "vitest";

// We need to verify verifyTimestamp logic.
// verifyTimestamp parses the token using pkijs.
// It calls signedData.verify(). We should mock that if possible or ensure our dummy data is valid enough to pass parse,
// but verify() usually requires real crypto.
// However, the function `verifyTimestamp` calls `signedData.verify` first.
// If that fails, it returns "Signature verification failed".
// We need it to pass signature verification to reach our ESS check.
// This requires mocking `pkijs.SignedData.prototype.verify`.

describe("Strict PAdES Validation", () => {
    it("should fail if strictESSValidation is true and ESS attribute is missing", async () => {
        // Mock verify to return true
        const verifySpy = vi.spyOn(pkijs.SignedData.prototype, "verify").mockResolvedValue({
            signatureVerified: true,
            signerVerified: true,
            message: "OK",
            code: 0,
            date: new Date(),
            certificatePath: [],
        } as unknown as pkijs.SignedDataVerifyResult);

        const token = createDummyTimestamp(false); // No ESS
        const timestamp: ExtractedTimestamp = {
            token,
            info: {} as TimestampInfo,
            fieldName: "Test",
            coversWholeDocument: true,
            verified: false,
        };

        const result = await verifyTimestamp(timestamp, { strictESSValidation: true });

        expect(result.verified).toBe(false);
        expect(result.verificationError).toContain("Strict validation: Missing");

        verifySpy.mockRestore();
    });

    it("should pass if strictESSValidation is true and ESS attribute is present", async () => {
        const verifySpy = vi.spyOn(pkijs.SignedData.prototype, "verify").mockResolvedValue({
            signatureVerified: true,
            signerVerified: true,
            message: "OK",
            code: 0,
            date: new Date(),
            certificatePath: [],
        } as unknown as pkijs.SignedDataVerifyResult);

        const token = createDummyTimestamp(true); // Has ESS
        const timestamp: ExtractedTimestamp = {
            token,
            info: {} as TimestampInfo,
            fieldName: "Test",
            coversWholeDocument: true,
            verified: true,
        };

        const result = await verifyTimestamp(timestamp, { strictESSValidation: true });

        expect(result.verified).toBe(true);
        expect(result.verificationError).toBeUndefined();

        verifySpy.mockRestore();
    });

    it("should ignore ESS attribute if strictESSValidation is false", async () => {
        const verifySpy = vi.spyOn(pkijs.SignedData.prototype, "verify").mockResolvedValue({
            signatureVerified: true,
            signerVerified: true,
            message: "OK",
            code: 0,
            date: new Date(),
            certificatePath: [],
        } as unknown as pkijs.SignedDataVerifyResult);

        const token = createDummyTimestamp(false); // No ESS
        const timestamp: ExtractedTimestamp = {
            token,
            info: {} as TimestampInfo,
            fieldName: "Test",
            coversWholeDocument: true,
            verified: true,
        };

        // Default is false
        const result = await verifyTimestamp(timestamp, {});

        expect(result.verified).toBe(true);

        verifySpy.mockRestore();
    });
});
