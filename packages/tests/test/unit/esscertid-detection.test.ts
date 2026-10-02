/**
 * ESSCertID detection outcomes on real timestamp tokens.
 *
 * T13 (S21) rewrite: the previous revision of this file built
 * TimestampInfo object literals and asserted the fields it had just set,
 * which cannot fail. Every test below parses bytes produced by the shared
 * signed-token fixture and asserts the detected outcome.
 *
 * pkijs 3.4.1 exposes no signingCertificate/signingCertificateV2 shape on
 * a parsed SignerInfo, so the lenient pki-utils parse keeps both ESS
 * fields absent on every real token; the strict response path instead
 * scans the signed attributes for the ESS OIDs and reports real
 * detection. Both behaviors are pinned below.
 */

import { describe, expect, it } from "vitest";
import { parseTimestampToken } from "../../../core/src/pki/pki-utils.js";
import { parseTimestampResponse } from "../../../core/src/tsa/response.js";
import { bytesToHex, toArrayBuffer } from "../../../core/src/utils.js";
import { createRFC3161TokenFixture, FIXTURE_GENTIME_ISO } from "../fixtures/rfc3161-token.js";

describe("ESSCertIDv2 Detection", () => {
    it("extracts the full TimestampInfo from a real v2-signed token", async () => {
        const fixture = await createRFC3161TokenFixture({ ess: "v2", form: "raw" });
        const info = parseTimestampToken(fixture.rawToken);

        expect(info.policy).toBe("1.2.3.4.5");
        expect(info.serialNumber).toBe("01e240");
        expect(info.hashAlgorithm).toBe("SHA-256");
        expect(info.hashAlgorithmOID).toBe("2.16.840.1.101.3.4.2.1");
        expect(info.hasCertificate).toBe(true);
        expect(info.genTime.toISOString()).toBe(new Date(FIXTURE_GENTIME_ISO).toISOString());
        expect(info.nonce).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));

        // Digest binding: the reported imprint is the SHA-256 of the
        // timestamped data, not an echo of a caller-supplied string.
        const expectedDigest = new Uint8Array(
            await crypto.subtle.digest("SHA-256", toArrayBuffer(fixture.context.data))
        );
        expect(info.messageDigest).toBe(bytesToHex(expectedDigest));

        // pkijs exposes no signingCertificateV2 on parse, so detection
        // stays absent even for a genuinely v2-signed token.
        expect(info.usesESSCertIDv2).toBeUndefined();
        expect(info.certIdHashAlgorithm).toBeUndefined();
    });

    it("keeps ESS detection absent across v1, missing and combined modes", async () => {
        for (const ess of ["v1", "missing", "both"] as const) {
            const fixture = await createRFC3161TokenFixture({ ess, form: "raw" });
            const info = parseTimestampToken(fixture.rawToken);

            expect(info.usesESSCertIDv2).toBeUndefined();
            expect(info.certIdHashAlgorithm).toBeUndefined();
            expect(info.hasCertificate).toBe(true);
            expect(info.policy).toBe("1.2.3.4.5");
        }
    });

    it("detects the ESS mode on the full response form", async () => {
        const cases = [
            { ess: "v2", usesESSCertIDv2: true, certIdHashAlgorithm: undefined },
            { ess: "v1", usesESSCertIDv2: false, certIdHashAlgorithm: "SHA-1" },
            { ess: "missing", usesESSCertIDv2: undefined, certIdHashAlgorithm: undefined },
            // Both attributes present: the v2 attribute wins.
            { ess: "both", usesESSCertIDv2: true, certIdHashAlgorithm: undefined },
        ] as const;
        for (const { ess, usesESSCertIDv2, certIdHashAlgorithm } of cases) {
            const fixture = await createRFC3161TokenFixture({ ess, form: "response" });
            const parsed = parseTimestampResponse(fixture.response);

            expect(parsed.info.usesESSCertIDv2).toBe(usesESSCertIDv2);
            expect(parsed.info.certIdHashAlgorithm).toBe(certIdHashAlgorithm);
            expect(parsed.info.policy).toBe("1.2.3.4.5");
            expect(parsed.info.hashAlgorithm).toBe("SHA-256");
            expect(parsed.info.hasCertificate).toBe(true);
            expect(parsed.token.length).toBeGreaterThan(0);
        }
    });
});
