import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    return bytes.slice().buffer;
}

function certificateStatus(
    status: "good" | "revoked" | "good-constructed" | "good-nonempty"
): asn1js.BaseBlock {
    if (status === "good") {
        return new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 } });
    }
    if (status === "good-constructed") {
        return new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [] });
    }
    if (status === "good-nonempty") {
        return new asn1js.Primitive({
            idBlock: { tagClass: 3, tagNumber: 0 },
            valueHex: Uint8Array.of(0).buffer,
        });
    }
    return new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 1 },
        value: [new asn1js.GeneralizedTime({ valueDate: new Date("2024-01-01T00:00:00Z") })],
    });
}

export function createOcspResponseCandidate(
    status: "good" | "revoked" | "good-constructed" | "good-nonempty",
    transformBasicResponse: (bytes: Uint8Array) => Uint8Array = (bytes) => bytes
): Uint8Array {
    const certID = new pkijs.CertID({
        hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: "1.3.14.3.2.26" }),
        issuerNameHash: new asn1js.OctetString({ valueHex: new Uint8Array(20).buffer }),
        issuerKeyHash: new asn1js.OctetString({ valueHex: new Uint8Array(20).buffer }),
        serialNumber: new asn1js.Integer({ value: 1 }),
    });
    const singleResponse = new pkijs.SingleResponse({
        certID,
        certStatus: certificateStatus(status),
        thisUpdate: new Date("2024-01-01T00:00:00Z"),
    });
    const responder = new pkijs.RelativeDistinguishedNames({
        typesAndValues: [
            new pkijs.AttributeTypeAndValue({
                type: "2.5.4.3",
                value: new asn1js.PrintableString({ value: "Candidate responder" }),
            }),
        ],
    });
    const responseData = new asn1js.Sequence({
        value: [
            new asn1js.Constructed({
                idBlock: { tagClass: 3, tagNumber: 1 },
                value: [responder.toSchema()],
            }),
            new asn1js.GeneralizedTime({ valueDate: new Date("2024-01-01T00:00:00Z") }),
            new asn1js.Sequence({ value: [singleResponse.toSchema()] }),
        ],
    });
    const basicResponse = new asn1js.Sequence({
        value: [
            responseData,
            new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.840.113549.1.1.11" }).toSchema(),
            new asn1js.BitString({ valueHex: Uint8Array.of(1).buffer }),
        ],
    });
    const response = new pkijs.OCSPResponse({
        responseStatus: new asn1js.Enumerated({ value: 0 }),
        responseBytes: new pkijs.ResponseBytes({
            responseType: "1.3.6.1.5.5.7.48.1.1",
            response: new asn1js.OctetString({
                valueHex: toArrayBuffer(
                    transformBasicResponse(new Uint8Array(basicResponse.toBER(false)))
                ),
            }),
        }),
    });
    return new Uint8Array(response.toSchema().toBER(false));
}

export interface TestCrlOptions {
    /** CRL number extension value (2.5.29.20); omitted when undefined */
    crlNumber?: number;
    /** Delta CRL indicator base number (2.5.29.27); presence marks a delta CRL */
    deltaBaseNumber?: number;
    /** Serial numbers to list as revoked entries */
    revokedSerials?: number[];
}

export function createCrlFixture(options: TestCrlOptions = {}): Uint8Array {
    const algorithm = new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.840.113549.1.1.11" });
    const issuer = new pkijs.RelativeDistinguishedNames({
        typesAndValues: [
            new pkijs.AttributeTypeAndValue({
                type: "2.5.4.3",
                value: new asn1js.PrintableString({ value: "Fixture issuer" }),
            }),
        ],
    });
    const extensions: pkijs.Extension[] = [];
    if (options.crlNumber !== undefined) {
        extensions.push(
            new pkijs.Extension({
                extnID: "2.5.29.20",
                critical: false,
                extnValue: new asn1js.Integer({ value: options.crlNumber }).toBER(false),
            })
        );
    }
    if (options.deltaBaseNumber !== undefined) {
        extensions.push(
            new pkijs.Extension({
                extnID: "2.5.29.27",
                critical: false,
                extnValue: new asn1js.Integer({ value: options.deltaBaseNumber }).toBER(false),
            })
        );
    }
    const revokedCertificates = (options.revokedSerials ?? []).map(
        (serial) =>
            new pkijs.RevokedCertificate({
                userCertificate: new asn1js.Integer({ value: serial }),
                revocationDate: new pkijs.Time({
                    value: new Date("2024-01-02T00:00:00Z"),
                }),
            })
    );
    const crl = new pkijs.CertificateRevocationList({
        version: 1,
        signature: algorithm,
        issuer,
        thisUpdate: new pkijs.Time({ value: new Date("2024-01-01T00:00:00Z") }),
        nextUpdate: new pkijs.Time({ value: new Date("2024-02-01T00:00:00Z") }),
        ...(revokedCertificates.length > 0 ? { revokedCertificates } : {}),
        ...(extensions.length > 0 ? { crlExtensions: new pkijs.Extensions({ extensions }) } : {}),
        signatureAlgorithm: algorithm,
        signatureValue: new asn1js.BitString({ valueHex: Uint8Array.of(1).buffer }),
    });
    const crlSchema = crl.toSchema(true) as asn1js.Sequence;
    return new Uint8Array(crlSchema.toBER(false));
}

export function createCrlCandidate(): Uint8Array {
    const algorithm = new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.840.113549.1.1.11" });
    const issuer = new pkijs.RelativeDistinguishedNames({
        typesAndValues: [
            new pkijs.AttributeTypeAndValue({
                type: "2.5.4.3",
                value: new asn1js.PrintableString({ value: "Candidate issuer" }),
            }),
        ],
    });
    const crl = new pkijs.CertificateRevocationList({
        version: 1,
        signature: algorithm,
        issuer,
        thisUpdate: new pkijs.Time({ value: new Date("2024-01-01T00:00:00Z") }),
        signatureAlgorithm: algorithm,
        signatureValue: new asn1js.BitString({ valueHex: Uint8Array.of(1).buffer }),
    });
    const crlSchema = crl.toSchema(true) as asn1js.Sequence;
    return new Uint8Array(crlSchema.toBER(false));
}
