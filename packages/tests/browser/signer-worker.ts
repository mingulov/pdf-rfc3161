// T00/T18 module-worker fixture: signs inside a real browser module worker.
//
// Bundled with esbuild (platform "browser", format "esm", no Node
// polyfills) against the same packed candidate as the page bundle and
// driven from the page via runWorkerJourney in signer.spec.ts on every
// engine (Chromium, Firefox, WebKit). Later tasks extend the
// request/response shapes here to cover worker-side regressions.
import { TimestampError, timestampPdf } from "pdf-rfc3161";

export interface WorkerSignRequest {
    pdf: number[];
    tsaUrl: string;
    policy?: string;
}

export interface WorkerSignResponse {
    ok: boolean;
    pdf?: number[];
    workerUserAgent?: string;
    code?: string | null;
    message?: string;
}

self.onmessage = (event: MessageEvent<WorkerSignRequest>): void => {
    void handleRequest(event.data).then((response) => {
        self.postMessage(response);
    });
};

async function handleRequest(request: WorkerSignRequest): Promise<WorkerSignResponse> {
    try {
        const result = await timestampPdf({
            pdf: new Uint8Array(request.pdf),
            tsa: {
                url: request.tsaUrl,
                ...(request.policy !== undefined && { policy: request.policy }),
                retry: 0,
            },
            enableLTV: true,
        });
        return {
            ok: true,
            pdf: Array.from(result.pdf),
            workerUserAgent: navigator.userAgent,
        };
    } catch (error) {
        return {
            ok: false,
            code: error instanceof TimestampError ? error.code : null,
            message: error instanceof Error ? error.message : String(error),
        };
    }
}
