import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { verifyTimestamp, type ExtractedTimestamp } from "../../../core/src/pdf/extract.js";
import type { TimestampInfo } from "../../../core/src/types.js";

// Audit L2: positive tests for the 0.2.0 default-true behaviour of
// requireTimestampingEKU (G1) and requireCertValidAtGenTime (G2). The
// existing strict-validation.test.ts only exercises strictESSValidation
// while explicitly passing both flags as `false` to keep that scope
// clean. That makes a future revert of the `?? true` defaults completely
// invisible to CI.
//
// Approach: build a SignedData with NO certificates and bypass the
// cryptographic verify check. The verify path then reaches the G1/G2
// branches, both of which hit the "no signing certificate available to
// check" guard. The error message names which flag tripped, so we can
// assert the routing precisely:
//
//   - Default call: error mentions "requireTimestampingEKU" -> G1 ran (default true).
//   - With `requireTimestampingEKU: false, requireCertValidAtGenTime: true`:
//     error mentions "requireCertValidAtGenTime" -> G1 skipped, G2 ran.
//   - With both false: neither fires -> verified === true.
//
// A future revert of the `?? true` default would change the no-options
// branch to verified === true, breaking these tests immediately.

function createNoCertsToken(): Uint8Array {
    const signedData = new pkijs.SignedData({
        version: 3,
        encapContentInfo: new pkijs.EncapsulatedContentInfo({
            eContentType: "1.2.840.113549.1.9.16.1.4", // id-ct-TSTInfo
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
        contentType: "1.2.840.113549.1.7.2",
        content: signedData.toSchema(),
    });
    return new Uint8Array(contentInfo.toSchema().toBER(false));
}

function makeTimestamp(token: Uint8Array): ExtractedTimestamp {
    const info: TimestampInfo = {
        genTime: new Date("2026-01-01T00:00:00Z"),
        policy: "1.2.3.4",
        serialNumber: "1",
        hashAlgorithm: "SHA-256",
        messageDigest: "deadbeef",
        hasCertificate: false,
        hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
    };
    return {
        token,
        info,
        fieldName: "Test",
        coversWholeDocument: true,
        verified: false,
        byteRange: [0, 0, 0, 0],
    };
}

describe("verifyTimestamp G1/G2 default-true behaviour (audit L2)", () => {
    let verifySpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
        verifySpy = vi
            .spyOn(pkijs.SignedData.prototype, "verify")
            .mockResolvedValue({
                signatureVerified: true,
                signerVerified: true,
                certificatePath: [],
            } as unknown as pkijs.SignedDataVerifyResult);
    });

    afterEach(() => {
        verifySpy.mockRestore();
    });

    it("default options enforce G1 (no opt-out flag) -- error mentions requireTimestampingEKU", async () => {
        const ts = makeTimestamp(createNoCertsToken());

        const result = await verifyTimestamp(ts);

        expect(result.verified).toBe(false);
        expect(result.verificationError).toMatch(/requireTimestampingEKU/);
    });

    it("opt-out from G1 advances to G2 -- error mentions requireCertValidAtGenTime", async () => {
        const ts = makeTimestamp(createNoCertsToken());

        const result = await verifyTimestamp(ts, { requireTimestampingEKU: false });

        expect(result.verified).toBe(false);
        // Now we should hit the G2 default-true guard for the same "no cert" reason.
        expect(result.verificationError).toMatch(/requireCertValidAtGenTime/);
    });

    it("opt-out from both G1 and G2 -- verify succeeds (smoke test for the routing)", async () => {
        const ts = makeTimestamp(createNoCertsToken());

        const result = await verifyTimestamp(ts, {
            requireTimestampingEKU: false,
            requireCertValidAtGenTime: false,
        });

        // With both guards skipped, the remaining strictESSValidation
        // default is false, so verify returns true.
        expect(result.verified).toBe(true);
    });

    it("regression: a future revert of `?? true` in extract.ts would flip the default test to verified=true", async () => {
        // Sentinel: if this test ever passes with verified=true under no
        // options, someone reverted the 0.2.0 G1/G2 default flip. The
        // assertion below is the same as the first test -- duplicated so
        // a failing-test bisect makes the regression obvious.
        const ts = makeTimestamp(createNoCertsToken());

        const result = await verifyTimestamp(ts);

        expect(result.verified).toBe(false);
    });
});
