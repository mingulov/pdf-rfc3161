// test/utils/mock-timestamp-server.ts - Simple mock TSA server for testing
import { createServer, IncomingMessage, ServerResponse } from "http";
import * as crypto from "crypto";

export class MockTimestampServer {
    private server: ReturnType<typeof createServer> | null = null;
    private port: number;
    private requestCount = 0;

    constructor(port = 31234) {
        this.port = port;
    }

    async start(): Promise<string> {
        return new Promise((resolve) => {
            this.server = createServer((req, res) => { this.handleRequest(req, res); });
            this.server.listen(this.port, () => {
                const url = `http://localhost:${String(this.port)}/tsr`;
                console.log(`Mock TSA server started at ${url}`);
                resolve(url);
            });
        });
    }

    async stop(): Promise<void> {
        return new Promise((resolve) => {
            if (this.server) {
                this.server.close(() => { resolve(); });
                this.server = null;
            } else {
                resolve();
            }
        });
    }

    getRequestCount(): number {
        return this.requestCount;
    }

    private handleRequest(req: IncomingMessage, res: ServerResponse): void {
        this.requestCount++;

        if (
            req.method === "POST" &&
            req.headers["content-type"] === "application/timestamp-query"
        ) {
            // Return a minimal valid timestamp response
            const response = this.createMockTimestampResponse();
            res.setHeader("Content-Type", "application/timestamp-reply");
            res.end(response);
        } else {
            res.statusCode = 400;
            res.end("Bad Request");
        }
    }

    private createMockTimestampResponse(): Buffer {
        // Create a minimal DER-encoded timestamp response
        // This is a simplified mock - real TSA would create proper CMS structure

        // Mock ASN.1 structure (TimeStampResp)
        // TimeStampResp ::= SEQUENCE {
        //     status PKIStatusInfo,
        //     timeStampToken TimeStampToken OPTIONAL
        // }

        const status = Buffer.from([0x30, 0x03, 0x0a, 0x01, 0x00]); // status = granted (0)

        // Mock timestamp token (simplified CMS SignedData)
        const token = Buffer.from([
            0x30, // SEQUENCE
            0x80 | 0x40, // Length (long form, ~64 bytes)
            0x06,
            0x0b,
            0x2a,
            0x86,
            0x48,
            0x86,
            0xf7,
            0x0d,
            0x01,
            0x07,
            0x02, // signed-data OID
            // Mock content...
            ...crypto.randomBytes(50),
        ]);

        // Combine status and token
        const response = Buffer.concat([
            Buffer.from([0x30]), // SEQUENCE
            Buffer.from([status.length + token.length]), // Length
            status,
            Buffer.from([0xa0, token.length]), // [0] EXPLICIT
            token,
        ]);

        return response;
    }
}
