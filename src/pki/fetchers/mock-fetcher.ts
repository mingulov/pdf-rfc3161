import type { RevocationDataFetcher } from "../validation-types.js";

/**
 * Mock fetcher for deterministic testing without network calls.
 *
 * @example
 * ```typescript
 * describe("ValidationSession", () => {
 *     let fetcher: MockFetcher;
 *
 *     beforeEach(() => {
 *         fetcher = new MockFetcher();
 *     });
 *
 *     it("should use mocked OCSP response", async () => {
 *         const mockResponse = createMockOCSPResponse();
 *         fetcher.setOCSPResponse("http://ocsp.test", mockResponse);
 *
 *         const session = new ValidationSession({ fetcher });
 *         // ...
 *     });
 * });
 * ```
 */
export class MockFetcher implements RevocationDataFetcher {
    private ocspResponses = new Map<string, Uint8Array>();
    private crlResponses = new Map<string, Uint8Array>();

    /**
     * Set a mock OCSP response for a specific URL
     */
    setOCSPResponse(url: string, response: Uint8Array): void {
        this.ocspResponses.set(url, response);
    }

    /**
     * Set a mock CRL response for a specific URL
     */
    setCRLResponse(url: string, response: Uint8Array): void {
        this.crlResponses.set(url, response);
    }

    /**
     * Clear all mocked responses
     */
    clear(): void {
        this.ocspResponses.clear();
        this.crlResponses.clear();
    }

    async fetchOCSP(url: string, _request: Uint8Array): Promise<Uint8Array> {
        const response = this.ocspResponses.get(url);
        if (!response) {
            throw new Error(`No mock OCSP response configured for URL: ${url}`);
        }
        return response;
    }

    async fetchCRL(url: string): Promise<Uint8Array> {
        const response = this.crlResponses.get(url);
        if (!response) {
            throw new Error(`No mock CRL response configured for URL: ${url}`);
        }
        return response;
    }
}
