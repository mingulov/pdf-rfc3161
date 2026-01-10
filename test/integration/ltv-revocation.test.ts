import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
    timestampPdf,
    DEFAULT_TSA_CONFIG,
    INCOMPATIBLE_TSA_URLS,
    KNOWN_TSA_URLS,
} from "../../src/index.js";
import { PDFDocument } from "pdf-lib-incremental-save";
import * as ocspClient from "../../src/pki/ocsp-client.js";
import * as crlClient from "../../src/pki/crl-client.js";
import * as ocspUtils from "../../src/pki/ocsp-utils.js";
import * as crlUtils from "../../src/pki/crl-utils.js";

// Mock the client modules
// We'll spy on them to control behavior
vi.mock("../../src/pki/ocsp-client.js", async (importOriginal) => {
    return {
        ...(await importOriginal<typeof ocspClient>()),
        fetchOCSPResponse: vi.fn(),
    };
});

vi.mock("../../src/pki/crl-client.js", async (importOriginal) => {
    return {
        ...(await importOriginal<typeof crlClient>()),
        fetchCRL: vi.fn(),
    };
});

// We might need to mock utils if we want to force specific URLs for testing
vi.mock("../../src/pki/ocsp-utils.js", async (importOriginal) => {
    return {
        ...(await importOriginal<typeof ocspUtils>()),
        getOCSPURI: vi.fn(),
    };
});

vi.mock("../../src/pki/crl-utils.js", async (importOriginal) => {
    return {
        ...(await importOriginal<typeof crlUtils>()),
        getCRLDistributionPoints: vi.fn(),
    };
});

/**
 * LTV Revocation Logic Tests
 *
 * These tests verify the library's ability to handle revocation data (OCSP, CRL)
 * when enabling LTV (Long-Term Validation).
 *
 * The tests mock the revocation fetching but still call real TSA servers to get
 * the timestamp token. When LIVE_TSA_TESTS=true, they call actual TSAs.
 *
 * Some TSA servers are known to be incompatible (see INCOMPATIBLE_TSA_URLS).
 * Tests will verify that the library handles these gracefully.
 */
describe("LTV Revocation Logic", () => {
    const hasLiveTsa = process.env.LIVE_TSA_TESTS === "true";
    const itLive = hasLiveTsa ? it : it.skip;

    let pdfBytes: Uint8Array;

    // Helper to get a TSA URL that may be incompatible
    const getTestTsaUrl = (): string => KNOWN_TSA_URLS.DIGICERT;

    beforeEach(async () => {
        // Create a basic PDF
        const doc = await PDFDocument.create();
        doc.addPage();
        pdfBytes = await doc.save();

        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    itLive(
        "should fetch OCSP when OCSP URI is present and fetch succeeds",
        async () => {
            const tsaUrl = getTestTsaUrl();

            // Skip if TSA is incompatible - verify error handling
            if (INCOMPATIBLE_TSA_URLS.has(tsaUrl)) {
                try {
                    await timestampPdf({
                        pdf: pdfBytes,
                        tsa: { ...DEFAULT_TSA_CONFIG, url: tsaUrl },
                        enableLTV: true,
                    });
                } catch (error) {
                    expect((error as Error).name).toBe("TimestampError");
                }
                return;
            }

            // Setup mocks
            // 1. Mock getOCSPURI to return a URL
            vi.mocked(ocspUtils.getOCSPURI).mockReturnValue("http://ocsp.example.com");

            // 2. Mock fetchOCSPResponse to return dummy bytes
            const dummyOCSP = new Uint8Array([0x01, 0x02, 0x03]);
            vi.mocked(ocspClient.fetchOCSPResponse).mockResolvedValue(dummyOCSP);

            // 3. Mock CRL to ensure it's NOT called
            vi.mocked(crlClient.fetchCRL).mockResolvedValue(new Uint8Array([]));

            // Use a real TSA (or mock that too, but real is fine for integration if we mock the revocation part)
            // Since we are mocking the revocation fetching, the actual cert checking loop in completeLTVData
            // will use our mocks.
            // NOTE: integration requires actual TSA response to get a token with certs.
            // If network is an issue, we should mock TSA response too, but let's assume TSA works.
            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: { ...DEFAULT_TSA_CONFIG, url: tsaUrl }, // Trusted TSA
                enableLTV: true,
            });

            // Verify LTV data
            expect(result.ltvData).toBeDefined();
            // Depending on chain length, we might have multiple calls.
            // Check that we have OCSP responses
            expect(result.ltvData?.ocspResponses.length).toBeGreaterThan(0);
            expect(result.ltvData?.crls.length).toBe(0);

            // Verify mocks
            expect(ocspUtils.getOCSPURI).toHaveBeenCalled();
            expect(ocspClient.fetchOCSPResponse).toHaveBeenCalled();
            expect(crlClient.fetchCRL).not.toHaveBeenCalled();
        },
        30000
    );

    itLive(
        "should fallback to CRL when fetchOCSPResponse fails",
        async () => {
            const tsaUrl = getTestTsaUrl();

            if (INCOMPATIBLE_TSA_URLS.has(tsaUrl)) {
                try {
                    await timestampPdf({
                        pdf: pdfBytes,
                        tsa: { ...DEFAULT_TSA_CONFIG, url: tsaUrl },
                        enableLTV: true,
                    });
                } catch (error) {
                    expect((error as Error).name).toBe("TimestampError");
                }
                return;
            }

            // Setup mocks
            // 1. Mock getOCSPURI to return a URL
            vi.mocked(ocspUtils.getOCSPURI).mockReturnValue("http://ocsp.example.com");

            // 2. Mock getCRLDistributionPoints to return a URL
            vi.mocked(crlUtils.getCRLDistributionPoints).mockReturnValue([
                "http://crl.example.com",
            ]);

            // 3. Mock fetchOCSPResponse to FAIL
            vi.mocked(ocspClient.fetchOCSPResponse).mockRejectedValue(new Error("Network Error"));

            // 4. Mock fetchCRL to SUCCEED
            const dummyCRL = new Uint8Array([0x04, 0x05, 0x06]);
            vi.mocked(crlClient.fetchCRL).mockResolvedValue(dummyCRL);

            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: { ...DEFAULT_TSA_CONFIG, url: tsaUrl },
                enableLTV: true,
            });

            // Verify LTV data
            expect(result.ltvData).toBeDefined();
            expect(result.ltvData?.ocspResponses.length).toBe(0); // Failed
            expect(result.ltvData?.crls.length).toBeGreaterThan(0); // Fallback succeeded

            // Verify mocks
            expect(ocspClient.fetchOCSPResponse).toHaveBeenCalled();
            expect(crlClient.fetchCRL).toHaveBeenCalledWith("http://crl.example.com");
        },
        30000
    );

    itLive(
        "should fallback to CRL when OCSP URI is missing",
        async () => {
            const tsaUrl = getTestTsaUrl();

            if (INCOMPATIBLE_TSA_URLS.has(tsaUrl)) {
                try {
                    await timestampPdf({
                        pdf: pdfBytes,
                        tsa: { ...DEFAULT_TSA_CONFIG, url: tsaUrl },
                        enableLTV: true,
                    });
                } catch (error) {
                    expect((error as Error).name).toBe("TimestampError");
                }
                return;
            }

            // Setup mocks
            // 1. Mock getOCSPURI to return null
            vi.mocked(ocspUtils.getOCSPURI).mockReturnValue(null);

            // 2. Mock getCRLDistributionPoints to return a URL
            vi.mocked(crlUtils.getCRLDistributionPoints).mockReturnValue([
                "http://crl.example.com",
            ]);

            // 3. Mock fetchCRL to SUCCEED
            const dummyCRL = new Uint8Array([0x07, 0x08, 0x09]);
            vi.mocked(crlClient.fetchCRL).mockResolvedValue(dummyCRL);

            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: { ...DEFAULT_TSA_CONFIG, url: tsaUrl },
                enableLTV: true,
            });

            // Verify LTV data
            expect(result.ltvData).toBeDefined();
            expect(result.ltvData?.ocspResponses.length).toBe(0);
            expect(result.ltvData?.crls.length).toBeGreaterThan(0);

            // Verify mocks
            expect(ocspClient.fetchOCSPResponse).not.toHaveBeenCalled();
            expect(crlClient.fetchCRL).toHaveBeenCalled();
        },
        30000
    );
});

vi.mock("../../src/pki/crl-client.js", async (importOriginal) => {
    return {
        ...(await importOriginal<typeof crlClient>()),
        fetchCRL: vi.fn(),
    };
});

// We might need to mock utils if we want to force specific URLs for testing
vi.mock("../../src/pki/ocsp-utils.js", async (importOriginal) => {
    return {
        ...(await importOriginal<typeof ocspUtils>()),
        getOCSPURI: vi.fn(),
    };
});

vi.mock("../../src/pki/crl-utils.js", async (importOriginal) => {
    return {
        ...(await importOriginal<typeof crlUtils>()),
        getCRLDistributionPoints: vi.fn(),
    };
});

describe("LTV Revocation Logic", () => {
    const hasLiveTsa = process.env.LIVE_TSA_TESTS === "true";
    const itLive = hasLiveTsa ? it : it.skip;

    let pdfBytes: Uint8Array;

    beforeEach(async () => {
        // Create a basic PDF
        const doc = await PDFDocument.create();
        doc.addPage();
        pdfBytes = await doc.save();

        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    itLive(
        "should fetch OCSP when OCSP URI is present and fetch succeeds",
        async () => {
            // Setup mocks
            // 1. Mock getOCSPURI to return a URL
            vi.mocked(ocspUtils.getOCSPURI).mockReturnValue("http://ocsp.example.com");

            // 2. Mock fetchOCSPResponse to return dummy bytes
            const dummyOCSP = new Uint8Array([0x01, 0x02, 0x03]);
            vi.mocked(ocspClient.fetchOCSPResponse).mockResolvedValue(dummyOCSP);

            // 3. Mock CRL to ensure it's NOT called
            vi.mocked(crlClient.fetchCRL).mockResolvedValue(new Uint8Array([]));

            // Use a real TSA (or mock that too, but real is fine for integration if we mock the revocation part)
            // Since we are mocking the revocation fetching, the actual cert checking loop in completeLTVData
            // will use our mocks.
            // NOTE: integration requires actual TSA response to get a token with certs.
            // If network is an issue, we should mock TSA response too, but let's assume TSA works.
            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: { ...DEFAULT_TSA_CONFIG, url: "http://timestamp.digicert.com" }, // Trusted TSA
                enableLTV: true,
            });

            // Verify LTV data
            expect(result.ltvData).toBeDefined();
            // Depending on chain length, we might have multiple calls.
            // Check that we have OCSP responses
            expect(result.ltvData?.ocspResponses.length).toBeGreaterThan(0);
            expect(result.ltvData?.crls.length).toBe(0);

            // Verify mocks
            expect(ocspUtils.getOCSPURI).toHaveBeenCalled();
            expect(ocspClient.fetchOCSPResponse).toHaveBeenCalled();
            expect(crlClient.fetchCRL).not.toHaveBeenCalled();
        },
        30000
    );

    itLive(
        "should fallback to CRL when fetchOCSPResponse fails",
        async () => {
            // Setup mocks
            // 1. Mock getOCSPURI to return a URL
            vi.mocked(ocspUtils.getOCSPURI).mockReturnValue("http://ocsp.example.com");

            // 2. Mock getCRLDistributionPoints to return a URL
            vi.mocked(crlUtils.getCRLDistributionPoints).mockReturnValue([
                "http://crl.example.com",
            ]);

            // 3. Mock fetchOCSPResponse to FAIL
            vi.mocked(ocspClient.fetchOCSPResponse).mockRejectedValue(new Error("Network Error"));

            // 4. Mock fetchCRL to SUCCEED
            const dummyCRL = new Uint8Array([0x04, 0x05, 0x06]);
            vi.mocked(crlClient.fetchCRL).mockResolvedValue(dummyCRL);

            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: { ...DEFAULT_TSA_CONFIG, url: "http://timestamp.digicert.com" },
                enableLTV: true,
            });

            // Verify LTV data
            expect(result.ltvData).toBeDefined();
            expect(result.ltvData?.ocspResponses.length).toBe(0); // Failed
            expect(result.ltvData?.crls.length).toBeGreaterThan(0); // Fallback succeeded

            // Verify mocks
            expect(ocspClient.fetchOCSPResponse).toHaveBeenCalled();
            expect(crlClient.fetchCRL).toHaveBeenCalledWith("http://crl.example.com");
        },
        30000
    );

    itLive(
        "should fallback to CRL when OCSP URI is missing",
        async () => {
            // Setup mocks
            // 1. Mock getOCSPURI to return null
            vi.mocked(ocspUtils.getOCSPURI).mockReturnValue(null);

            // 2. Mock getCRLDistributionPoints to return a URL
            vi.mocked(crlUtils.getCRLDistributionPoints).mockReturnValue([
                "http://crl.example.com",
            ]);

            // 3. Mock fetchCRL to SUCCEED
            const dummyCRL = new Uint8Array([0x07, 0x08, 0x09]);
            vi.mocked(crlClient.fetchCRL).mockResolvedValue(dummyCRL);

            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: { ...DEFAULT_TSA_CONFIG, url: "http://timestamp.digicert.com" },
                enableLTV: true,
            });

            // Verify LTV data
            expect(result.ltvData).toBeDefined();
            expect(result.ltvData?.ocspResponses.length).toBe(0);
            expect(result.ltvData?.crls.length).toBeGreaterThan(0);

            // Verify mocks
            expect(ocspClient.fetchOCSPResponse).not.toHaveBeenCalled();
            expect(crlClient.fetchCRL).toHaveBeenCalled();
        },
        30000
    );
});
