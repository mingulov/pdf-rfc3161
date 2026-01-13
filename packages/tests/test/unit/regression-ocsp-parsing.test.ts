import { describe, it, expect } from "vitest";
import { parseOCSPResponse } from "pdf-rfc3161";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";

describe("Regression: OCSP Response Parsing", () => {
    // The bug was that pkijs/asn1js parses the status as an Enumerated object,
    // but the code expected a number.
    //
    // OCSPResponse ::= SEQUENCE {
    //    responseStatus         OCSPResponseStatus,
    //    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
    //
    // OCSPResponseStatus ::= ENUMERATED { successful(0), ... }

    it("should correctly parse status 'successful' (0) from DER (fix validation)", () => {
        // DER: SEQUENCE(0x30) len 0x03 -> ENUMERATED(0x0a) len 0x01 val 0x00
        const successfulResponse = new Uint8Array([0x30, 0x03, 0x0a, 0x01, 0x00]);

        // Before fix: Threw "OCSP responder error: Unknown error" because it misread the object as implicit number check fail
        // After fix: correctly sees 0 (SUCCESSFUL), proceeds, then throws "no responseBytes" (expected)

        try {
            parseOCSPResponse(successfulResponse);
        } catch (error: any) {
            expect(error.message).toBe("OCSP response has no responseBytes");
        }
    });

    it("should correctly parse status 'internalError' (2) from DER", () => {
        // DER: SEQUENCE(0x30) len 0x03 -> ENUMERATED(0x0a) len 0x01 val 0x02
        const errorResponse = new Uint8Array([0x30, 0x03, 0x0a, 0x01, 0x02]);

        try {
            parseOCSPResponse(errorResponse);
        } catch (error: any) {
            // Should properly identify the error code
            expect(error.message).toContain("Internal Error");
            expect(error.message).toContain("code: 2");
        }
    });

    it("should correctly parse status 'revoked' (1) from DER", () => {
        // Construct a revoked response using pkijs/asn1js with correct types

        // 1. Mock certStatus: [1] IMPLICIT RevokedInfo
        const revokedInfo = new asn1js.Constructed({
            idBlock: {
                tagClass: 3, // Context-specific
                tagNumber: 1 // [1]
            },
            value: [
                new asn1js.GeneralizedTime({ valueDate: new Date() })
            ]
        });

        // 2. Mock SingleResponse
        const certID = new pkijs.CertID({
            hashAlgorithm: new pkijs.AlgorithmIdentifier({
                algorithmId: "1.3.14.3.2.26", // sha-1
                algorithmParams: new asn1js.Null()
            }),
            issuerNameHash: new asn1js.OctetString({ valueHex: new Uint8Array(20).buffer }),
            issuerKeyHash: new asn1js.OctetString({ valueHex: new Uint8Array(20).buffer }),
            serialNumber: new asn1js.Integer({ value: 1 }),
        });

        const singleResp = new pkijs.SingleResponse({
            certID,
            certStatus: revokedInfo,
            thisUpdate: new Date(),
        });

        // 3. Mock ResponseData (tbsResponseData)
        // responderID CHOICE { byName [1] Name, byKey [2] KeyHash }

        const rdn = new pkijs.RelativeDistinguishedNames({
            typesAndValues: [
                new pkijs.AttributeTypeAndValue({
                    type: "2.5.4.3", // CN
                    value: new asn1js.PrintableString({ value: "Test Responder" })
                })
            ]
        });
        const responderID = new asn1js.Constructed({
            idBlock: { tagClass: 3, tagNumber: 1 }, // [1] EXPLICIT Name
            value: [rdn.toSchema()]
        });

        // ResponseData expects specific fields. 
        // passing 'responderID' as the raw schema object directly might fail if pkijs tries to convert it AGAIN or check instance type.
        // So we might need to bypass BasicOCSPResponse constructor validation by constructing ResponseData manually OR using `any` cast trick properly.

        // Let's try manual ResponseData + BasicOCSPResponse wrapper since we know the components are valid DER.

        const responseDataRaw = new asn1js.Sequence({
            value: [
                new asn1js.Constructed({
                    idBlock: { tagClass: 3, tagNumber: 0 },
                    value: [new asn1js.Integer({ value: 0 })] // Version 0 (v1)
                }),
                responderID,
                new asn1js.GeneralizedTime({ valueDate: new Date() }),
                new asn1js.Sequence({ value: [singleResp.toSchema()] })
            ]
        });

        // BasicOCSPResponse
        const basicOCSPRaw = new asn1js.Sequence({
            value: [
                responseDataRaw,
                new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.840.113549.1.1.11" }).toSchema(),
                new asn1js.BitString({ valueHex: new Uint8Array(128).buffer })
            ]
        });

        // OCSPResponse
        const responseBytes = new pkijs.ResponseBytes({
            responseType: "1.3.6.1.5.5.7.48.1.1", // id-pkix-ocsp-basic
            response: new asn1js.OctetString({ valueHex: basicOCSPRaw.toBER(false) })
        });

        const ocspResponse = new pkijs.OCSPResponse({
            responseStatus: new asn1js.Enumerated({ value: 0 }), // successful
            responseBytes
        });

        const der = new Uint8Array(ocspResponse.toSchema().toBER(false));

        const result = parseOCSPResponse(der);
        expect(result.status).toBe(0);
        expect(result.certStatus).toBe(1); // REVOKED
    });
});
