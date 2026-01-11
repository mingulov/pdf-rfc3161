import { useState, useRef } from "react";
import {
    timestampPdf,
    KNOWN_TSA_URLS,
    extractTimestamps,
    TimestampSession,
    type ExtractedTimestamp,
    TimestampError,
} from "pdf-rfc3161";
import FileDrop from "./FileDrop";
import { Download, AlertCircle, Check, Loader2, FileCheck, AlertTriangle } from "lucide-react";

function downloadBlob(blob: Blob, name: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
}

export default function TimestampPanel() {
    const [file, setFile] = useState<File | null>(null);
    const [mode, setMode] = useState<"direct" | "manual">("manual");
    const [tsaUrl, setTsaUrl] = useState<string>(KNOWN_TSA_URLS.FREETSA);
    const [enableLTV, setEnableLTV] = useState(false);
    const [ltvWarning, setLtvWarning] = useState(false);

    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Manual state - Now cleaner with TimestampSession!
    const sessionRef = useRef<TimestampSession | null>(null);
    const [tsq, setTsq] = useState<Uint8Array | null>(null);
    const [step, setStep] = useState(1); // 1: Generate TSQ, 2: Upload TSR

    // Result state
    const [resultPdf, setResultPdf] = useState<{ blob: Blob; name: string } | null>(null);
    const [resultTimestamps, setResultTimestamps] = useState<ExtractedTimestamp[]>([]);

    const reset = () => {
        setFile(null);
        setError(null);
        setResultPdf(null);
        setResultTimestamps([]);
        setTsq(null);
        setStep(1);
        setLoading(false);
        setLtvWarning(false);
        sessionRef.current = null;
    };

    const handleSuccess = async (pdfBytes: Uint8Array, filename: string) => {
        const blob = new Blob([pdfBytes as unknown as BlobPart], { type: "application/pdf" });
        const timestamps = await extractTimestamps(pdfBytes);
        setResultPdf({ blob, name: filename });
        setResultTimestamps(timestamps);
    };

    // DIRECT MODE
    const handleDirectTimestamp = async () => {
        if (!file) return;
        setLoading(true);
        setError(null);
        try {
            const buffer = await file.arrayBuffer();
            const pdfBytes = new Uint8Array(buffer);

            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: { url: tsaUrl },
                enableLTV,
            });

            await handleSuccess(result.pdf, `timestamped-${file.name}`);

            // Check if LTV was requested but no revocation data was found (likely CORS)
            if (enableLTV && result.ltvData) {
                const hasRevocation =
                    result.ltvData.ocspResponses.length > 0 || result.ltvData.crls.length > 0;
                if (!hasRevocation) {
                    setLtvWarning(true);
                }
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
            if (
                String(err).includes("fetch") ||
                String(err).includes("Network") ||
                err instanceof TimestampError
            ) {
                setError(
                    `Network Error: ${String(err)}. Most public TSAs block browser requests (CORS). Try 'Manual Mode'.`
                );
            }
        } finally {
            setLoading(false);
        }
    };

    // MANUAL MODE - Step 1: Generate TSQ
    const generateTsq = async () => {
        if (!file) return;
        setLoading(true);
        setError(null);
        try {
            const buffer = await file.arrayBuffer();
            const pdfBytes = new Uint8Array(buffer);

            // Helper class simplifies the workflow!
            // New: Pass configuration to the constructor
            const session = new TimestampSession(pdfBytes, {
                enableLTV,
                prepareOptions: {
                    reason: "Demo Timestamp",
                    location: "Browser",
                    signatureSize: 0, // 0 = Auto/Default (16KB for LTV)
                },
                hashAlgorithm: "SHA-256",
            });
            sessionRef.current = session;

            // New: createTimestampRequest takes fewer args now
            const req = await session.createTimestampRequest();

            setTsq(req);
            setStep(2);
        } catch (err) {
            setError(String(err));
        } finally {
            setLoading(false);
        }
    };

    // MANUAL MODE - Step 2: Embed TSR
    const embedTsr = async (tsrBytes: Uint8Array) => {
        if (!sessionRef.current || !file) return;
        setLoading(true);
        setError(null);
        try {
            // Session handles embedding AND LTV (addDSS) automatically
            const finalPdf = await sessionRef.current.embedTimestampToken(tsrBytes);
            await handleSuccess(finalPdf, `timestamped-${file.name}`);
        } catch (err) {
            setError(String(err));
        } finally {
            setLoading(false);
        }
    };

    if (resultPdf) {
        return (
            <div className="done" role="status" aria-live="polite">
                <Check size={48} color="var(--green)" className="mb4" aria-hidden="true" />
                <h3>Timestamp Added Successfully!</h3>

                {ltvWarning && (
                    <div className="warn mt4 text-left" role="alert">
                        <div className="flex gap2 bold mb1">
                            <AlertTriangle size={20} color="#f97316" aria-hidden="true" />
                            <span>LTV Warning</span>
                        </div>
                        <p className="text-sm" style={{ margin: 0 }}>
                            Revocation data (OCSP/CRL) could not be fetched. This is common in
                            browsers due to <strong>CORS</strong> restrictions on public PKI
                            servers.
                        </p>
                        <p className="text-sm" style={{ margin: 0, marginTop: "0.25rem" }}>
                            The PDF is signed, but may not be fully LTV-enabled until verified by a
                            server or desktop software.
                        </p>
                    </div>
                )}

                <div className="card alt mt4">
                    <div className="flex gap2 mb4 bold">
                        <FileCheck size={20} className="gray" aria-hidden="true" />
                        <span>Signed Document Info</span>
                    </div>
                    <div className="grid" role="list">
                        <div className="tag">Filename:</div>
                        <div role="listitem">{resultPdf.name}</div>

                        <div className="tag">Size:</div>
                        <div role="listitem">{(resultPdf.blob.size / 1024).toFixed(2)} KB</div>

                        <div className="tag">Timestamps:</div>
                        <div role="listitem">{resultTimestamps.length} found</div>

                        {resultTimestamps.length > 0 && resultTimestamps[0].info.genTime && (
                            <>
                                <div className="tag">Latest Time:</div>
                                <div role="listitem">
                                    {resultTimestamps[
                                        resultTimestamps.length - 1
                                    ].info.genTime.toLocaleString()}
                                </div>
                            </>
                        )}
                    </div>
                </div>

                <div className="flex gap2 hcenter mt4">
                    <button
                        onClick={() => downloadBlob(resultPdf.blob, resultPdf.name)}
                        className="btn"
                        aria-label={`Download signed PDF: ${resultPdf.name}`}
                    >
                        <Download size={18} aria-hidden="true" /> Download Signed PDF
                    </button>
                    <button onClick={reset} className="sec">
                        Start Over
                    </button>
                </div>
            </div>
        );
    }

    if (!file) return <FileDrop onFileSelect={setFile} />;

    return (
        <div className="timestamp-panel">
            <div className="subhead">
                <div className="flex vcenter between mb2 w-full">
                    <span>
                        <strong className="bold">Selected File:</strong> {file.name}
                    </span>
                    <button onClick={reset} className="link">
                        Change File
                    </button>
                </div>

                <fieldset className="modes">
                    <legend className="sr-only">Timestamp Mode Selection</legend>
                    <label className="opts">
                        <input
                            type="radio"
                            name="timestamp-mode"
                            value="direct"
                            checked={mode === "direct"}
                            onChange={() => setMode("direct")}
                        />
                        Direct (Network)
                    </label>
                    <label className="opts">
                        <input
                            type="radio"
                            name="timestamp-mode"
                            value="manual"
                            checked={mode === "manual"}
                            onChange={() => setMode("manual")}
                        />
                        Manual (No CORS)
                    </label>
                </fieldset>

                <div className="mt2">
                    <label className="opts">
                        <input
                            type="checkbox"
                            checked={enableLTV}
                            onChange={(e) => setEnableLTV(e.target.checked)}
                        />
                        Enable LTV (Long-Term Validation)
                    </label>
                    {enableLTV && (
                        <div className="note mt1 flex">
                            <AlertTriangle size={12} className="mt1" aria-hidden="true" />
                            <span className="ml1">
                                Note: OCSP/CRL requests often fail in browsers (CORS).
                            </span>
                        </div>
                    )}
                </div>
            </div>

            {loading && (
                <div className="loading" role="status" aria-live="polite">
                    <Loader2 className="spin" aria-hidden="true" />
                    <span>Processing...</span>
                </div>
            )}

            {error && (
                <div className="error" role="alert" aria-live="assertive">
                    <AlertCircle size={20} aria-hidden="true" />
                    <span>{error}</span>
                </div>
            )}

            {!loading && mode === "direct" && (
                <div>
                    <p className="text-sm gray mb4">
                        Attempt to fetch timestamp directly from browser.{" "}
                        <strong className="bold">
                            Note: This often fails due to CORS on public TSAs.
                        </strong>
                    </p>
                    <div className="flex gap2 mb2">
                        <label htmlFor="tsa-url" className="sr-only">
                            TSA Server URL
                        </label>
                        <input
                            id="tsa-url"
                            type="text"
                            value={tsaUrl}
                            onChange={(e) => setTsaUrl(e.target.value)}
                            className="input"
                            placeholder="https://freetsa.org/tsr"
                            aria-describedby="tsa-url-desc"
                        />
                    </div>
                    <p id="tsa-url-desc" className="text-sm gray mb4">
                        You can use any RFC 3161 compatible TSA URL.
                    </p>
                    <button onClick={handleDirectTimestamp} className="btn wide">
                        Sign PDF
                    </button>
                </div>
            )}

            {!loading && mode === "manual" && step === 1 && (
                <div>
                    <p className="mb4 text-sm">
                        Step 1: Parse PDF and generate Timestamp Request (.tsq)
                    </p>
                    <button onClick={generateTsq} className="btn wide">
                        Generate Request
                    </button>
                </div>
            )}

            {!loading && mode === "manual" && step === 2 && tsq && (
                <div>
                    <h4 className="mt0">Step 2: Send Request & Upload Response</h4>

                    <div className="mb4">
                        <div className="mb1 bold text-sm">1. Download the request file (.tsq):</div>
                        <button
                            onClick={() =>
                                downloadBlob(new Blob([tsq as unknown as BlobPart]), "request.tsq")
                            }
                            className="sec"
                            aria-label="Download request.tsq file"
                        >
                            <Download size={16} aria-hidden="true" /> Download request.tsq
                        </button>
                    </div>

                    <div className="mb4">
                        <div className="mb1 bold text-sm">
                            2. Send to TSA (using curl in terminal):
                        </div>
                        <div className="code" role="presentation">
                            curl -H "Content-Type: application/timestamp-query" --data-binary
                            @request.tsq --output response.tsr {tsaUrl}
                        </div>
                        <p className="text-sm gray mt2">
                            Uses {tsaUrl} - replace with your server URL if needed.
                        </p>
                    </div>

                    <div>
                        <div className="mb1 bold text-sm">
                            3. Upload response (.tsr, .der, .bin):
                        </div>
                        <FileDrop
                            onFileSelect={async (f) => {
                                const buf = await f.arrayBuffer();
                                embedTsr(new Uint8Array(buf));
                            }}
                            accept=".tsr,.der,.bin"
                            label="Drop Response here or click to upload"
                            description="Supports .tsr, .der, .bin files"
                        />
                    </div>
                </div>
            )}
        </div>
    );
}
