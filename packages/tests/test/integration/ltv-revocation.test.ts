import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_TSA_CONFIG, KNOWN_TSA_URLS, timestampPdf } from "pdf-rfc3161";
import { PDFDocument } from "pdf-lib-incremental-save";
import * as ocspClient from "../../../core/src/pki/ocsp-client.js";
import * as crlClient from "../../../core/src/pki/crl-client.js";
import * as ocspUtils from "../../../core/src/pki/ocsp-utils.js";
import * as crlUtils from "../../../core/src/pki/crl-utils.js";
import {
    createCrlCandidate,
    createOcspResponseCandidate,
} from "../fixtures/revocation-material.js";

vi.mock(
    "../../../core/src/pki/ocsp-client.js",
    async (importOriginal: <T = unknown>() => Promise<T>) => ({
        ...(await importOriginal<typeof ocspClient>()),
        fetchOCSPResponse: vi.fn(),
    })
);

vi.mock(
    "../../../core/src/pki/crl-client.js",
    async (importOriginal: <T = unknown>() => Promise<T>) => ({
        ...(await importOriginal<typeof crlClient>()),
        fetchCRL: vi.fn(),
    })
);

vi.mock(
    "../../../core/src/pki/ocsp-utils.js",
    async (importOriginal: <T = unknown>() => Promise<T>) => ({
        ...(await importOriginal<typeof ocspUtils>()),
        getOCSPURI: vi.fn(),
    })
);

vi.mock(
    "../../../core/src/pki/crl-utils.js",
    async (importOriginal: <T = unknown>() => Promise<T>) => ({
        ...(await importOriginal<typeof crlUtils>()),
        getCRLDistributionPoints: vi.fn(),
    })
);

describe("LTV revocation logic with a live TSA", () => {
    const itLive: typeof it = process.env.LIVE_TSA_TESTS === "true" ? it : it.skip;
    const tsaUrl = KNOWN_TSA_URLS.DIGICERT as string;

    let pdfBytes: Uint8Array;

    beforeEach(async () => {
        const doc = await PDFDocument.create();
        doc.addPage();
        pdfBytes = await doc.save();
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    itLive(
        "collects a complete OCSP response when the OCSP request succeeds",
        async () => {
            const ocsp = createOcspResponseCandidate("good");
            vi.mocked(ocspUtils.getOCSPURI).mockReturnValue("http://ocsp.example.com");
            vi.mocked(ocspClient.fetchOCSPResponse).mockResolvedValue(ocsp);
            vi.mocked(crlClient.fetchCRL).mockResolvedValue(new Uint8Array([]));

            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: { ...DEFAULT_TSA_CONFIG, url: tsaUrl },
                enableLTV: true,
            });

            expect(result.ltvData?.ocspResponses).toEqual([ocsp]);
            expect(result.ltvData?.crls).toEqual([]);
        },
        30000
    );

    itLive(
        "collects a complete CRL when the OCSP request fails",
        async () => {
            const crl = createCrlCandidate();
            vi.mocked(ocspUtils.getOCSPURI).mockReturnValue("http://ocsp.example.com");
            vi.mocked(crlUtils.getCRLDistributionPoints).mockReturnValue([
                "http://crl.example.com",
            ]);
            vi.mocked(ocspClient.fetchOCSPResponse).mockRejectedValue(new Error("Network Error"));
            vi.mocked(crlClient.fetchCRL).mockResolvedValue(crl);

            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: { ...DEFAULT_TSA_CONFIG, url: tsaUrl },
                enableLTV: true,
            });

            expect(result.ltvData?.ocspResponses).toEqual([]);
            expect(result.ltvData?.crls).toEqual([crl]);
        },
        30000
    );

    itLive(
        "collects a complete CRL when the certificate has no OCSP URI",
        async () => {
            const crl = createCrlCandidate();
            vi.mocked(ocspUtils.getOCSPURI).mockReturnValue(null);
            vi.mocked(crlUtils.getCRLDistributionPoints).mockReturnValue([
                "http://crl.example.com",
            ]);
            vi.mocked(crlClient.fetchCRL).mockResolvedValue(crl);

            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: { ...DEFAULT_TSA_CONFIG, url: tsaUrl },
                enableLTV: true,
            });

            expect(result.ltvData?.ocspResponses).toEqual([]);
            expect(result.ltvData?.crls).toEqual([crl]);
        },
        30000
    );
});
