
import { describe, it, expect } from "vitest";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { getCaIssuers } from "../../../core/src/pki/cert-utils.js";

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

        // Create AuthorityInfoAccess syntax manually (Sequence of AccessDescriptions)
        const aiaSyntax = new asn1js.Sequence({
            value: accessDescriptions.map(ad => ad.toSchema())
        });

        // Create Extension
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
});
