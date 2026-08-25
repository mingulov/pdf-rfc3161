import { describe, expect, it } from "vitest";
import {
    parseTimestampResponse,
    validateTimestampResponse,
} from "../../../core/src/tsa/response.js";
import { TimestampErrorCode, TSAStatus } from "../../../core/src/types.js";
import { createRFC3161TokenFixture } from "../fixtures/rfc3161-token.js";

function expectErrorCode(callback: () => unknown, code: TimestampErrorCode): void {
    let caught: unknown;
    try {
        callback();
    } catch (error) {
        caught = error;
    }
    expect(caught).toMatchObject({ code });
}

describe("TSA Response", () => {
    describe("parseTimestampResponse", () => {
        it("accepts only real full granted responses", async () => {
            for (const status of [TSAStatus.GRANTED, TSAStatus.GRANTED_WITH_MODS]) {
                const statusString = `granted status ${status.toString()}`;
                const fixture = await createRFC3161TokenFixture({
                    form: "response",
                    status,
                    statusString,
                });
                const response = parseTimestampResponse(fixture.response);

                expect(response.status).toBe(status);
                expect(response.statusString).toBe(statusString);
                expect(response.token).toEqual(fixture.rawToken);
                expect(response.info.messageDigest).toMatch(/^[0-9a-f]+$/i);
            }
        });

        it("preserves every accepted PKIFreeText status string in historical order", async () => {
            for (const status of [TSAStatus.GRANTED, TSAStatus.GRANTED_WITH_MODS]) {
                const fixture = await createRFC3161TokenFixture({
                    form: "response",
                    status,
                    statusStrings: ["first status text", "second status text"],
                });

                expect(parseTimestampResponse(fixture.response).statusString).toBe(
                    "first status text; second status text"
                );
            }
        });

        it("rejects raw ContentInfo and malformed ASN.1 envelopes", async () => {
            const fixture = await createRFC3161TokenFixture();
            expect(() => parseTimestampResponse(fixture.rawToken)).toThrow(
                /complete TimeStampResp/
            );
            expect(() => parseTimestampResponse(new Uint8Array())).toThrow();
            expect(() => parseTimestampResponse(new Uint8Array([0x30, 0x02]))).toThrow();
        });

        it("treats every non-granted status, including warnings and unknown values, as fatal", async () => {
            for (const status of [2, 3, 4, 5, 6]) {
                const fixture = await createRFC3161TokenFixture({ form: "response", status });
                expectErrorCode(
                    () => parseTimestampResponse(fixture.response),
                    TimestampErrorCode.TSA_ERROR
                );
            }
        });

        it("rejects status/token structure violations", async () => {
            const missing = await createRFC3161TokenFixture({
                form: "response",
                status: TSAStatus.GRANTED,
                includeToken: false,
            });
            const forbidden = await createRFC3161TokenFixture({
                form: "response",
                status: TSAStatus.REJECTION,
                includeToken: true,
            });

            expectErrorCode(
                () => parseTimestampResponse(missing.response),
                TimestampErrorCode.MALFORMED_RESPONSE
            );
            expectErrorCode(
                () => parseTimestampResponse(forbidden.response),
                TimestampErrorCode.MALFORMED_RESPONSE
            );
        });
    });

    describe("validateTimestampResponse", () => {
        const hash = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
        const baseInfo = {
            genTime: new Date(),
            policy: "1.2.3",
            serialNumber: "1234",
            hashAlgorithm: "SHA-256",
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            messageDigest: "deadbeef",
            hasCertificate: true,
        };

        it("checks matching digest, algorithm, positive nonce, and requested policy", () => {
            expect(
                validateTimestampResponse(
                    { ...baseInfo, nonce: new Uint8Array([0, 0x81]) },
                    hash,
                    "SHA-256",
                    new Uint8Array([0, 0x81]),
                    "1.2.3"
                )
            ).toBe(true);
        });

        it("preserves case-insensitive digest comparison and supported digest lengths", () => {
            expect(validateTimestampResponse(baseInfo, hash, "SHA-256")).toBe(true);
            const sha384Hash = new Uint8Array(48).fill(0xab);
            expect(
                validateTimestampResponse(
                    {
                        ...baseInfo,
                        hashAlgorithm: "SHA-384",
                        hashAlgorithmOID: "2.16.840.1.101.3.4.2.2",
                        messageDigest: "AB".repeat(48),
                    },
                    sha384Hash,
                    "SHA-384"
                )
            ).toBe(true);
        });

        it("rejects mismatched digest, algorithm, nonce, and policy", () => {
            expect(
                validateTimestampResponse({ ...baseInfo, messageDigest: "00" }, hash, "SHA-256")
            ).toBe(false);
            expect(
                validateTimestampResponse(
                    { ...baseInfo, hashAlgorithm: "SHA-384" },
                    hash,
                    "SHA-256"
                )
            ).toBe(false);
            expect(
                validateTimestampResponse(
                    { ...baseInfo, nonce: new Uint8Array([1]) },
                    hash,
                    "SHA-256",
                    new Uint8Array([2])
                )
            ).toBe(false);
            expect(validateTimestampResponse(baseInfo, hash, "SHA-256", undefined, "1.2.4")).toBe(
                false
            );
        });

        it("rejects absent, zero, negative, and non-minimal expected nonces", () => {
            expect(validateTimestampResponse(baseInfo, hash, "SHA-256", new Uint8Array([1]))).toBe(
                false
            );
            expect(
                validateTimestampResponse(
                    { ...baseInfo, nonce: new Uint8Array([0]) },
                    hash,
                    "SHA-256",
                    new Uint8Array([1])
                )
            ).toBe(false);
            expect(
                validateTimestampResponse(
                    { ...baseInfo, nonce: new Uint8Array([0x80]) },
                    hash,
                    "SHA-256",
                    new Uint8Array([1])
                )
            ).toBe(false);
            expect(
                validateTimestampResponse(
                    { ...baseInfo, nonce: new Uint8Array([1]) },
                    hash,
                    "SHA-256",
                    new Uint8Array([0, 1])
                )
            ).toBe(false);
        });

        it("keeps the no-expected-nonce compatibility path while checking an explicit policy", () => {
            expect(validateTimestampResponse(baseInfo, hash, "SHA-256")).toBe(true);
            expect(validateTimestampResponse(baseInfo, hash, "SHA-256", undefined, "1.2.3")).toBe(
                true
            );
        });
    });
});
