import { describe, it, expect } from "vitest";
import * as pkijs from "pkijs";
import { isCertValidAtTime } from "../../../core/src/pki/pki-utils.js";

function certWithValidity(notBefore: Date, notAfter: Date): pkijs.Certificate {
    const cert = new pkijs.Certificate();
    cert.notBefore = new pkijs.Time({ type: 1, value: notBefore });
    cert.notAfter = new pkijs.Time({ type: 1, value: notAfter });
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
