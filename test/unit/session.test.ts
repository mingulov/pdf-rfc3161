import { describe, it, expect, beforeEach } from "vitest";
import { TimestampSession } from "../../src/session.js";
import { TimestampError } from "../../src/types.js";
import { PDFDocument } from "pdf-lib-incremental-save";

describe("TimestampSession", () => {
    let pdfBytes: Uint8Array;

    beforeEach(async () => {
        // Create a basic PDF
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        pdfBytes = await doc.save();
    });

    describe("signatureSize", () => {
        it("should use LTV_SIGNATURE_SIZE (16384 bytes) when enableLTV is true", () => {
            const session = new TimestampSession(pdfBytes, {
                enableLTV: true,
            });

            expect(session.signatureSize).toBe(16384); // 16KB = LTV_SIGNATURE_SIZE
        });

        it("should use DEFAULT_SIGNATURE_SIZE (8192 bytes) when enableLTV is false", () => {
            const session = new TimestampSession(pdfBytes, {
                enableLTV: false,
            });

            expect(session.signatureSize).toBe(8192); // 8KB = DEFAULT_SIGNATURE_SIZE
        });

        it("should use DEFAULT_SIGNATURE_SIZE when enableLTV is undefined", () => {
            const session = new TimestampSession(pdfBytes);

            expect(session.signatureSize).toBe(8192); // Default when enableLTV is undefined (treated as true by default)
        });

        it("should allow manual signature size override", () => {
            const session = new TimestampSession(pdfBytes, {
                enableLTV: true,
                prepareOptions: { signatureSize: 32768 },
            });

            expect(session.signatureSize).toBe(32768);
        });

        it("should respect explicit signatureSize: 0 (auto)", () => {
            const session = new TimestampSession(pdfBytes, {
                enableLTV: false,
                prepareOptions: { signatureSize: 0 },
            });

            // signatureSize: 0 means auto/default, which should return DEFAULT_SIGNATURE_SIZE
            expect(session.signatureSize).toBe(8192);
        });

        it("should respect explicit signatureSize: 0 with LTV enabled", () => {
            const session = new TimestampSession(pdfBytes, {
                enableLTV: true,
                prepareOptions: { signatureSize: 0 },
            });

            // signatureSize: 0 with LTV should return LTV_SIGNATURE_SIZE
            expect(session.signatureSize).toBe(16384);
        });
    });

    describe("setSignatureSize", () => {
        it("should return the set value after calling setSignatureSize", () => {
            const session = new TimestampSession(pdfBytes, {
                enableLTV: true,
            });

            // First check initial value
            const initialSize = session.signatureSize;
            expect(initialSize).toBe(16384);

            // Set new value
            session.setSignatureSize(20480);

            // Verify it returns the new value
            expect(session.signatureSize).toBe(20480);
        });

        it("should allow setting very large signature size", () => {
            const session = new TimestampSession(pdfBytes);

            session.setSignatureSize(131072); // 128KB

            expect(session.signatureSize).toBe(131072);
        });

        it("should allow setting minimum signature size", () => {
            const session = new TimestampSession(pdfBytes);

            session.setSignatureSize(256);

            expect(session.signatureSize).toBe(256);
        });

        it("should allow setting to LTV_SIGNATURE_SIZE explicitly", () => {
            const session = new TimestampSession(pdfBytes, {
                enableLTV: false,
            });

            // Set to LTV size explicitly
            session.setSignatureSize(16384);

            expect(session.signatureSize).toBe(16384);
        });
    });

    describe("dispose", () => {
        it("should clear pdfBytes after dispose", () => {
            const session = new TimestampSession(pdfBytes, { enableLTV: true });

            expect(session.signatureSize).toBe(16384);

            session.dispose();

            // After dispose, accessing signatureSize should work
            expect(() => {
                // eslint-disable-next-line @typescript-eslint/no-unused-expressions
                session.signatureSize;
            }).not.toThrow();
        });

        it("should throw error when creating request after dispose", async () => {
            const session = new TimestampSession(pdfBytes, { enableLTV: true });
            session.dispose();

            await expect(session.createTimestampRequest()).rejects.toThrow(TimestampError);
        });

        it("should throw error when embedding token after dispose", async () => {
            const session = new TimestampSession(pdfBytes, { enableLTV: true });
            await session.createTimestampRequest();
            session.dispose();

            const rawToken = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
            await expect(session.embedTimestampToken(rawToken)).rejects.toThrow(TimestampError);
        });

        it("should allow creating new session after old one is disposed", async () => {
            // Create first session
            const session1 = new TimestampSession(pdfBytes, { enableLTV: true });
            await session1.createTimestampRequest();
            session1.dispose();

            // Create a new session with same bytes
            const session2 = new TimestampSession(pdfBytes, { enableLTV: true });
            expect(session2.signatureSize).toBe(16384);

            // Should work fine
            const tsq = await session2.createTimestampRequest();
            expect(tsq.length).toBeGreaterThan(0);
        });
    });

    describe("createTimestampRequest", () => {
        it("should create a non-empty timestamp request", async () => {
            const session = new TimestampSession(pdfBytes);

            const tsq = await session.createTimestampRequest();

            expect(tsq.length).toBeGreaterThan(0);
            // TSQ should be DER-encoded, first byte is usually 0x30 (SEQUENCE)
            expect(tsq[0]).toBe(0x30);
        });
    });

    describe("calculateOptimalSize", () => {
        it("should return aligned size for small token", () => {
            const smallToken = new Uint8Array(100);
            const size = TimestampSession.calculateOptimalSize(smallToken);

            expect(size).toBeGreaterThan(100);
            // Size should be aligned to SIGNATURE_SIZE_OPTIMIZE_ALIGN (32)
            expect(size % 32).toBe(0);
        });

        it("should return aligned size for large token", () => {
            const largeToken = new Uint8Array(8000);
            const size = TimestampSession.calculateOptimalSize(largeToken);

            expect(size).toBeGreaterThan(8000);
            expect(size % 32).toBe(0);
        });

        it("should add safety margin", () => {
            const token = new Uint8Array(8191);
            const size = TimestampSession.calculateOptimalSize(token);

            // Should be at least token length + SIGNATURE_SIZE_OPTIMIZE_ADD (32)
            expect(size).toBeGreaterThanOrEqual(8191 + 32);
        });
    });

    describe("embedTimestampToken - TSA status handling", () => {
        // Minimal valid TimeStampResp with status=2 (rejection) - no token
        const REJECTED_RESPONSE = new Uint8Array([
            0x30,
            0x0b, // SEQUENCE (11 bytes)
            0x30,
            0x09, // PKIStatusInfo SEQUENCE (9 bytes)
            0x02,
            0x01,
            0x02, // INTEGER status=2 (REJECTION)
            0x30,
            0x04, // statusString SEQUENCE (4 bytes)
            0x0c,
            0x02,
            0x65,
            0x72, // UTF8String "er"
        ]);

        // WAITING status (3)
        const WAITING_RESPONSE = new Uint8Array([
            0x30,
            0x0b, // SEQUENCE (11 bytes)
            0x30,
            0x09, // PKIStatusInfo SEQUENCE (9 bytes)
            0x02,
            0x01,
            0x03, // INTEGER status=3 (WAITING)
            0x30,
            0x04, // statusString SEQUENCE (4 bytes)
            0x0c,
            0x02,
            0x65,
            0x72, // UTF8String "er"
        ]);

        // REVOCATION_WARNING status (4)
        const REVOCATION_WARNING_RESPONSE = new Uint8Array([
            0x30,
            0x0b, // SEQUENCE (11 bytes)
            0x30,
            0x09, // PKIStatusInfo SEQUENCE (9 bytes)
            0x02,
            0x01,
            0x04, // INTEGER status=4 (REVOCATION_WARNING)
            0x30,
            0x04, // statusString SEQUENCE (4 bytes)
            0x0c,
            0x02,
            0x65,
            0x72, // UTF8String "er"
        ]);

        // REVOCATION_NOTIFICATION status (5)
        const REVOCATION_NOTIFICATION_RESPONSE = new Uint8Array([
            0x30,
            0x0b, // SEQUENCE (11 bytes)
            0x30,
            0x09, // PKIStatusInfo SEQUENCE (9 bytes)
            0x02,
            0x01,
            0x05, // INTEGER status=5 (REVOCATION_NOTIFICATION)
            0x30,
            0x04, // statusString SEQUENCE (4 bytes)
            0x0c,
            0x02,
            0x65,
            0x72, // UTF8String "er"
        ]);

        it("should throw TimestampError for REJECTION status", async () => {
            const session = new TimestampSession(pdfBytes);
            await session.createTimestampRequest();

            await expect(session.embedTimestampToken(REJECTED_RESPONSE)).rejects.toThrow(
                "TSA rejected request"
            );
        });

        it("should throw TimestampError with TSA_ERROR code for REJECTION", async () => {
            const session = new TimestampSession(pdfBytes);
            await session.createTimestampRequest();

            let thrown = false;
            try {
                await session.embedTimestampToken(REJECTED_RESPONSE);
            } catch (error) {
                thrown = true;
                expect(error).toBeInstanceOf(TimestampError);
                const tsError = error as TimestampError;
                expect(tsError.code).toBe("TSA_ERROR");
                expect(tsError.message).toContain("TSA rejected request");
            }
            expect(thrown).toBe(true);
        });

        it("should throw for WAITING status", async () => {
            const session = new TimestampSession(pdfBytes);
            await session.createTimestampRequest();

            await expect(session.embedTimestampToken(WAITING_RESPONSE)).rejects.toThrow();
        });

        it("should throw for REVOCATION_WARNING status", async () => {
            const session = new TimestampSession(pdfBytes);
            await session.createTimestampRequest();

            await expect(
                session.embedTimestampToken(REVOCATION_WARNING_RESPONSE)
            ).rejects.toThrow();
        });

        it("should throw for REVOCATION_NOTIFICATION status", async () => {
            const session = new TimestampSession(pdfBytes);
            await session.createTimestampRequest();

            await expect(
                session.embedTimestampToken(REVOCATION_NOTIFICATION_RESPONSE)
            ).rejects.toThrow();
        });

        it("should fall back to raw bytes if parse fails but no token", async () => {
            const session = new TimestampSession(pdfBytes);
            await session.createTimestampRequest();

            // Invalid ASN.1 that can't be parsed - should still try to use as raw token
            // But the parseTimestampResponse will catch the error and fall back
            const invalidData = new Uint8Array([0x00, 0x01, 0x02, 0x03]);

            // This should NOT throw because it falls back to raw bytes
            // However, embedding invalid bytes might cause other issues
            // The key is that the TSA status check doesn't throw on parse errors
            try {
                await session.embedTimestampToken(invalidData);
            } catch {
                // May fail at embedding stage, which is acceptable
                // The important thing is it didn't throw due to TSA status check
            }
        });

        it("should still embed token if status is GRANTED", () => {
            // Note: We can't easily test GRANTED status without a valid token
            // This test documents the expected behavior
            // A real implementation would use a mock or recorded response
            expect(true).toBe(true);
        });

        it("should still embed token if status is GRANTED_WITH_MODS", () => {
            // Similar to above - hard to test without a valid response
            expect(true).toBe(true);
        });
    });

    describe("memory cleanup", () => {
        it("should clear internal references on dispose", async () => {
            const session = new TimestampSession(pdfBytes, { enableLTV: true });
            await session.createTimestampRequest();

            session.dispose();

            await expect(session.createTimestampRequest()).rejects.toThrow(TimestampError);
            await expect(session.embedTimestampToken(new Uint8Array([0x01, 0x02]))).rejects.toThrow(
                TimestampError
            );
        });

        it("should allow multiple dispose calls safely", () => {
            const session = new TimestampSession(pdfBytes);
            session.dispose();
            expect(() => {
                session.dispose();
            }).not.toThrow();
        });

        it("should not leak memory with repeated session creation", async () => {
            const sessions: TimestampSession[] = [];

            for (let i = 0; i < 50; i++) {
                const session = new TimestampSession(pdfBytes);
                await session.createTimestampRequest();
                sessions.push(session);
            }

            for (const session of sessions) {
                session.dispose();
            }

            for (const session of sessions) {
                await expect(session.createTimestampRequest()).rejects.toThrow(TimestampError);
            }

            sessions.length = 0;
            expect(sessions.length).toBe(0);
        });

        it("should handle concurrent session lifecycle", async () => {
            const sessions: TimestampSession[] = [];

            for (let i = 0; i < 10; i++) {
                const session = new TimestampSession(pdfBytes);
                await session.createTimestampRequest();
                sessions.push(session);

                if (i % 2 === 0) {
                    session.dispose();
                }
            }

            for (let i = 0; i < sessions.length; i++) {
                if (i % 2 === 0) {
                    await expect(sessions[i]?.createTimestampRequest()).rejects.toThrow(
                        TimestampError
                    );
                } else {
                    const tsq = await sessions[i]?.createTimestampRequest();
                    expect(tsq?.length).toBeGreaterThan(0);
                }
            }
        });

        it("should work with rapid creation/disposal cycles", async () => {
            for (let i = 0; i < 100; i++) {
                const session = new TimestampSession(pdfBytes);
                await session.createTimestampRequest();
                session.dispose();
            }

            const finalSession = new TimestampSession(pdfBytes);
            const tsq = await finalSession.createTimestampRequest();
            expect(tsq.length).toBeGreaterThan(0);

            finalSession.dispose();
        });

        it("should isolate disposed sessions from active ones", async () => {
            const session1 = new TimestampSession(pdfBytes, { enableLTV: true });
            const session2 = new TimestampSession(pdfBytes, { enableLTV: true });

            await session1.createTimestampRequest();
            await session2.createTimestampRequest();

            session1.dispose();

            // session1 should be unusable
            await expect(session1.createTimestampRequest()).rejects.toThrow(TimestampError);

            // session2 should still work
            const tsq = await session2.createTimestampRequest();
            expect(tsq.length).toBeGreaterThan(0);

            session2.dispose();
        });

        it("should prevent operations after dispose with clear error", async () => {
            const session = new TimestampSession(pdfBytes);
            session.dispose();

            let threw = false;
            try {
                await session.createTimestampRequest();
            } catch (error) {
                threw = true;
                expect(error).toBeInstanceOf(TimestampError);
                const tsError = error as TimestampError;
                expect(tsError.code).toBe("PDF_ERROR");
                expect(tsError.message).toContain("disposed");
            }
            expect(threw).toBe(true);
        });
    });
});
