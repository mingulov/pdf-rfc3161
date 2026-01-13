import { describe, it, expect } from "vitest";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { getCaIssuers, findIssuer } from "../../../core/src/pki/cert-utils.js";
import { hexToBytes } from "../../../core/src/utils.js";
// Helper to construct a cert with AIA extension
function createCertWithAIA(urls: string[]): pkijs.Certificate {
    const cert = new pkijs.Certificate();

    if (urls.length > 0) {
        // Create AccessDescriptions
        const accessDescriptions = urls.map(url => {
            return new pkijs.AccessDescription({
                accessMethod: "1.3.6.1.5.5.7.48.2", // id-ad-caIssuers
                accessLocation: new pkijs.GeneralName({
                    type: 6, // URI
                    value: url
                })
            });
        });

        // Create AuthorityInfoAccess syntax manually (asn1js.Sequence of AccessDescriptions)
        const aiaSyntax = new asn1js.Sequence({
            value: accessDescriptions.map(ad => ad.toSchema())
        });

        // Create pkijs.Extension
        const ext = new pkijs.Extension({
            extnID: "1.3.6.1.5.5.7.1.1", // AIA
            extnValue: aiaSyntax.toBER(false)
        });

        cert.extensions = [ext];
    } else {
        cert.extensions = [];
    }

    return cert;
}

// Helper to create a basic certificate with subject, issuer, and optional AKI/SKI
function createTestCert(options: {
    subject: string,
    issuer?: string,
    ski?: string,
    aki?: string,
    serial?: string
}): pkijs.Certificate {
    const cert = new pkijs.Certificate();

    // Set Subject
    const subject = new pkijs.RelativeDistinguishedNames({
        typesAndValues: [
            new pkijs.AttributeTypeAndValue({
                type: "2.5.4.3", // commonName
                value: new asn1js.Utf8String({ value: options.subject })
            })
        ]
    });
    cert.subject = subject;

    // Set Issuer
    const issuer = new pkijs.RelativeDistinguishedNames({
        typesAndValues: [
            new pkijs.AttributeTypeAndValue({
                type: "2.5.4.3", // commonName
                value: new asn1js.Utf8String({ value: options.issuer ?? options.subject })
            })
        ]
    });
    cert.issuer = issuer;

    // Set Serial Number
    if (options.serial) {
        cert.serialNumber = new asn1js.Integer({ value: parseInt(options.serial) });
    }

    cert.extensions = [];

    // Add SKI
    if (options.ski) {
        const skiBytes = hexToBytes(options.ski);
        const skiValue = new asn1js.OctetString({
            valueHex: skiBytes.buffer,
            // Ensure we use a clean buffer if possible, but hexToBytes already creates one
        });
        cert.extensions.push(new pkijs.Extension({
            extnID: "2.5.29.14",
            extnValue: skiValue.toBER(false)
        }));
    }

    // Add AKI
    if (options.aki) {
        const akiBytes = hexToBytes(options.aki);
        const aki = new pkijs.AuthorityKeyIdentifier({
            keyIdentifier: new asn1js.OctetString({
                valueHex: akiBytes.buffer
            })
        });
        cert.extensions.push(new pkijs.Extension({
            extnID: "2.5.29.35",
            extnValue: aki.toSchema().toBER(false)
        }));
    }

    return cert;
}

describe("Cert Utils", () => {
    describe("getCaIssuers", () => {
        it("should return empty array if no extensions", () => {
            const cert = new pkijs.Certificate();
            const urls = getCaIssuers(cert);
            expect(urls).toEqual([]);
        });

        it("should return empty array if no AIA extension", () => {
            const cert = new pkijs.Certificate();
            cert.extensions = [
                new pkijs.Extension({ extnID: "1.2.3.4", extnValue: new Uint8Array([0x05, 0x00]).buffer })
            ];
            const urls = getCaIssuers(cert);
            expect(urls).toEqual([]);
        });

        it("should extract single URL", () => {
            const url = "http://example.com/ca.cer";
            const cert = createCertWithAIA([url]);
            const urls = getCaIssuers(cert);
            expect(urls).toEqual([url]);
        });

        it("should extract multiple URLs", () => {
            const cert = createCertWithAIA(["http://a.com/1.cer", "http://b.com/2.crt"]);
            const urls = getCaIssuers(cert);
            expect(urls).toEqual(["http://a.com/1.cer", "http://b.com/2.crt"]);
        });
    });

    describe("findIssuer", () => {
        it("should find issuer by common name match", () => {
            const issuer = createTestCert({ subject: "Root CA" });
            const child = createTestCert({ subject: "Intermediate CA", issuer: "Root CA" });

            const result = findIssuer(child, [issuer]);
            expect(result).toBe(issuer);
        });

        it("should return undefined if no issuer name matches", () => {
            const notIssuer = createTestCert({ subject: "Wrong CA" });
            const child = createTestCert({ subject: "Intermediate CA", issuer: "Root CA" });

            const result = findIssuer(child, [notIssuer]);
            expect(result).toBeUndefined();
        });

        it("should use AKI/SKI to differentiate when multiple issuers have same name", () => {
            // Two roots with same name but different keys (cross-signing scenario)
            const root1 = createTestCert({ subject: "Root CA", ski: "11111111", serial: "1" });
            const root2 = createTestCert({ subject: "Root CA", ski: "22222222", serial: "2" });

            // Child points to Root CA and specifically key 2222...
            const child = createTestCert({
                subject: "Intermediate CA",
                issuer: "Root CA",
                aki: "22222222"
            });

            const candidates = [root1, root2];
            const result = findIssuer(child, candidates);

            expect(result).toBe(root2);
            expect(result?.serialNumber.valueBlock.valueDec).toBe(2);
        });

        it("should fallback to first match if AKI/SKI missing", () => {
            const root1 = createTestCert({ subject: "Root CA", serial: "1" });
            const root2 = createTestCert({ subject: "Root CA", serial: "2" });

            const child = createTestCert({
                subject: "Intermediate CA",
                issuer: "Root CA"
            });

            const candidates = [root1, root2];
            const result = findIssuer(child, candidates);

            // Should pick the first one from the list
            expect(result).toBe(root1);
        });

        it("should handle error in AKI/SKI matching and fallback", () => {
            // Malformed AKI extension in child
            const root = createTestCert({ subject: "Root CA", ski: "11111111" });
            const child = createTestCert({ subject: "Intermediate CA", issuer: "Root CA" });

            // Sabotage extensions to cause a parse error if possible, or just missing AKI
            child.extensions = [
                new pkijs.Extension({
                    extnID: "2.5.29.35",
                    extnValue: new Uint8Array([0x00]).buffer // invalid ASN.1
                })
            ];

            const result = findIssuer(child, [root]);
            expect(result).toBe(root); // Still finds it via name
        });
    });
});
