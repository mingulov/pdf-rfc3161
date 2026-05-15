import { describe, it, expect } from "vitest";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { hasTimestampingEKU } from "../../../core/src/pki/pki-utils.js";

const OID_ID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";
const OID_EKU_EXT = "2.5.29.37";
const OID_KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
const OID_ANY_EKU = "2.5.29.37.0";

function certWithExtensions(extensions: pkijs.Extension[]): pkijs.Certificate {
    const cert = new pkijs.Certificate();
    cert.extensions = extensions;
    return cert;
}

function ekuExtension(ekuOids: string[]): pkijs.Extension {
    const ekuSeq = new asn1js.Sequence({
        value: ekuOids.map((oid) => new asn1js.ObjectIdentifier({ value: oid })),
    });
    return new pkijs.Extension({
        extnID: OID_EKU_EXT,
        critical: false,
        extnValue: ekuSeq.toBER(false),
    });
}

describe("hasTimestampingEKU (G1)", () => {
    it("returns true when cert lists id-kp-timeStamping", () => {
        const cert = certWithExtensions([ekuExtension([OID_ID_KP_TIMESTAMPING])]);
        expect(hasTimestampingEKU(cert)).toBe(true);
    });

    it("returns true when cert lists id-kp-timeStamping among multiple purposes", () => {
        const cert = certWithExtensions([
            ekuExtension([OID_KP_CLIENT_AUTH, OID_ID_KP_TIMESTAMPING]),
        ]);
        expect(hasTimestampingEKU(cert)).toBe(true);
    });

    it("returns false when cert lists EKU purposes other than timestamping", () => {
        const cert = certWithExtensions([ekuExtension([OID_KP_CLIENT_AUTH])]);
        expect(hasTimestampingEKU(cert)).toBe(false);
    });

    it("returns false when cert has no EKU extension at all", () => {
        const cert = certWithExtensions([]);
        expect(hasTimestampingEKU(cert)).toBe(false);
    });

    it("returns true for anyExtendedKeyUsage (2.5.29.37.0) per RFC 5280", () => {
        const cert = certWithExtensions([ekuExtension([OID_ANY_EKU])]);
        expect(hasTimestampingEKU(cert)).toBe(true);
    });

    it("returns false when EKU extension is present but empty", () => {
        const cert = certWithExtensions([ekuExtension([])]);
        expect(hasTimestampingEKU(cert)).toBe(false);
    });
});
