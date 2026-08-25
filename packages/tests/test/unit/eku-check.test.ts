import { describe, expect, it } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
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

function ekuExtension(ekuOids: string[], critical = true): pkijs.Extension {
    const ekuSeq = new asn1js.Sequence({
        value: ekuOids.map((oid) => new asn1js.ObjectIdentifier({ value: oid })),
    });
    return new pkijs.Extension({
        extnID: OID_EKU_EXT,
        critical,
        extnValue: ekuSeq.toBER(false),
    });
}

describe("hasTimestampingEKU", () => {
    it("accepts exactly one critical id-kp-timeStamping EKU", () => {
        expect(
            hasTimestampingEKU(certWithExtensions([ekuExtension([OID_ID_KP_TIMESTAMPING])]))
        ).toBe(true);
    });

    it("rejects a noncritical EKU", () => {
        expect(
            hasTimestampingEKU(certWithExtensions([ekuExtension([OID_ID_KP_TIMESTAMPING], false)]))
        ).toBe(false);
    });

    it("rejects additional EKU purposes", () => {
        expect(
            hasTimestampingEKU(
                certWithExtensions([ekuExtension([OID_ID_KP_TIMESTAMPING, OID_KP_CLIENT_AUTH])])
            )
        ).toBe(false);
    });

    it("rejects anyExtendedKeyUsage", () => {
        expect(hasTimestampingEKU(certWithExtensions([ekuExtension([OID_ANY_EKU])]))).toBe(false);
    });

    it("rejects a missing EKU extension", () => {
        expect(hasTimestampingEKU(certWithExtensions([]))).toBe(false);
    });

    it("rejects duplicate EKU extensions", () => {
        expect(
            hasTimestampingEKU(
                certWithExtensions([
                    ekuExtension([OID_ID_KP_TIMESTAMPING]),
                    ekuExtension([OID_ID_KP_TIMESTAMPING]),
                ])
            )
        ).toBe(false);
    });

    it("rejects empty and malformed EKU extensions", () => {
        expect(hasTimestampingEKU(certWithExtensions([ekuExtension([])]))).toBe(false);
        expect(
            hasTimestampingEKU(
                certWithExtensions([
                    new pkijs.Extension({
                        extnID: OID_EKU_EXT,
                        critical: true,
                        extnValue: new Uint8Array([0x05, 0x00]).buffer,
                    }),
                ])
            )
        ).toBe(false);
    });
});
