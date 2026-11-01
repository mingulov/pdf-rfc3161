import { describe, it, expect } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { isCertValidAtTime, validityOk } from "../../../core/src/pki/pki-utils.js";
import { createRFC3161TokenFixture } from "../fixtures/rfc3161-token.js";

function certWithValidity(notBefore: Date, notAfter: Date): pkijs.Certificate {
    const cert = new pkijs.Certificate();
    cert.notBefore = new pkijs.Time({ type: pkijs.TimeType.GeneralizedTime, value: notBefore });
    cert.notAfter = new pkijs.Time({ type: pkijs.TimeType.GeneralizedTime, value: notAfter });
    return cert;
}

describe("isCertValidAtTime (G2)", () => {
    const start = new Date("2024-01-01T00:00:00Z");
    const end = new Date("2025-01-01T00:00:00Z");
    const cert = certWithValidity(start, end);

    it("returns true when time is inside the validity window", () => {
        expect(isCertValidAtTime(cert, new Date("2024-06-15T12:00:00Z"))).toBe(true);
    });

    it("returns true at the lower bound (notBefore)", () => {
        expect(isCertValidAtTime(cert, start)).toBe(true);
    });

    it("returns true at the upper bound (notAfter)", () => {
        expect(isCertValidAtTime(cert, end)).toBe(true);
    });

    it("returns false one millisecond before notBefore", () => {
        const tooEarly = new Date(start.getTime() - 1);
        expect(isCertValidAtTime(cert, tooEarly)).toBe(false);
    });

    it("returns false one millisecond after notAfter", () => {
        const tooLate = new Date(end.getTime() + 1);
        expect(isCertValidAtTime(cert, tooLate)).toBe(false);
    });

    it("returns false when cert is missing notBefore or notAfter", () => {
        const broken = new pkijs.Certificate();
        // No notBefore/notAfter set -- defensive return
        expect(isCertValidAtTime(broken, new Date("2024-06-15T12:00:00Z"))).toBe(false);
    });

});

describe("validityOk encoding gate", () => {
    it("accepts well-formed GeneralizedTime validity encodings", async () => {
        const fixture = await createRFC3161TokenFixture({ signerValidityGeneralizedTime: true });
        const asn1 = asn1js.fromBER(fixture.signerCertificate.slice().buffer);
        if (asn1.offset === -1) throw new Error("fixture signer is not DER");
        const cert = new pkijs.Certificate({ schema: asn1.result });
        expect(
            cert.notBefore.type === pkijs.TimeType.GeneralizedTime ||
                cert.notAfter.type === pkijs.TimeType.GeneralizedTime
        ).toBe(true);
        expect(validityOk(cert)).toBe(true);
    });
});
