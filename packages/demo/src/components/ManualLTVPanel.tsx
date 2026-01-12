import { useState, useRef } from "react";
import {
    TimestampSession,
    KNOWN_TSA_URLS,
    parseTimestampResponse,
    getOCSPURI,
    createOCSPRequest,
    getCRLDistributionPoints,
    getCaIssuers,
    addDSS,
} from "pdf-rfc3161";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import FileDrop from "./FileDrop";
import {
    Download,
    AlertCircle,
    CheckCircle,
    Loader2,
    ArrowRight,
    Upload,
    PenTool,
} from "lucide-react";
import { downloadBlob } from "../utils";

interface ValidationCommand {
    type: "OCSP" | "CRL" | "CERT";
    url: string;
    command: string;
    filename: string;
    requestFilename?: string;
    requestBytes?: Uint8Array;
}

export function ManualLTVPanel() {
    // Workflow State
    const [step, setStep] = useState(1);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Data State
    const [file, setFile] = useState<File | null>(null);
    const [tsaUrl, setTsaUrl] = useState<string>(KNOWN_TSA_URLS.AIMODA);
    const [tsq, setTsq] = useState<Uint8Array | null>(null);
    const sessionRef = useRef<TimestampSession | null>(null);
    const [tsr, setTsr] = useState<Uint8Array | null>(null);
    const [uploadedValidationData, setUploadedValidationData] = useState<{
        crls: Uint8Array[];
        ocspResponses: Uint8Array[];
        certificates: Uint8Array[];
    }>({ crls: [], ocspResponses: [], certificates: [] });
    const [validationCommands, setValidationCommands] = useState<ValidationCommand[]>([]);

    // Result State
    const [resultPdf, setResultPdf] = useState<{ blob: Blob; name: string } | null>(null);

    const reset = () => {
        setStep(1);
        setFile(null);
        setError(null);
        setTsq(null);
        setTsr(null);
        setUploadedValidationData({ crls: [], ocspResponses: [], certificates: [] });
        setValidationCommands([]);
        setResultPdf(null);
        sessionRef.current = null;
    };

    const handleFileSelect = (f: File) => {
        setFile(f);
        setStep(1);
    };

    // STEP 1: Generate TSQ
    const handleGenerateTsq = async () => {
        if (!file) return;
        setLoading(true);
        setError(null);
        try {
            const buffer = await file.arrayBuffer();
            const pdfBytes = new Uint8Array(buffer);
            const session = new TimestampSession(pdfBytes, {
                enableLTV: false, // We will add DSS manually in the final step
                prepareOptions: {
                    reason: "Manual LTV Timestamp",
                    location: "Browser",
                },
                hashAlgorithm: "SHA-256",
            });
            sessionRef.current = session;
            const req = await session.createTimestampRequest();
            setTsq(req);
            setStep(2);
        } catch (err) {
            setError("Failed to generate TSQ: " + err);
        } finally {
            setLoading(false);
        }
    };

    // STEP 2: Handle TSR Upload
    const handleTsrUpload = async (tsrBytes: Uint8Array) => {
        setLoading(true);
        setError(null);
        try {
            const parsed = parseTimestampResponse(tsrBytes);
            if (!parsed.token) throw new Error("Invalid TSR: no token found");
            setTsr(tsrBytes);

            // Extract certificates to determine validation sources
            const asn1 = asn1js.fromBER(parsed.token.slice().buffer);
            const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
            const signedData = new pkijs.SignedData({ schema: contentInfo.content });

            const commands: ValidationCommand[] = [];

            if (signedData.certificates && signedData.certificates.length > 0) {
                // Focus on the first cert (signer) for simplicity in demo
                const cert = signedData.certificates[0];
                if (cert instanceof pkijs.Certificate) {
                    // 1. OCSP
                    const ocspUrl = getOCSPURI(cert);
                    const issuer =
                        signedData.certificates.length > 1 ? signedData.certificates[1] : null;
                    if (ocspUrl && issuer instanceof pkijs.Certificate) {
                        const ocspReq = await createOCSPRequest(cert, issuer);
                        commands.push({
                            type: "OCSP",
                            url: ocspUrl,
                            command: `curl -H "Content-Type: application/ocsp-request" --data-binary @ocsp_req.der --output ocsp_resp.der ${ocspUrl}`,
                            filename: "ocsp_resp.der",
                            requestFilename: "ocsp_req.der",
                            requestBytes: new Uint8Array(ocspReq),
                        });
                    }

                    // 2. CRL
                    const crlUrls = getCRLDistributionPoints(cert);
                    for (const url of crlUrls) {
                        commands.push({
                            type: "CRL",
                            url: url,
                            command: `curl --output crl.der ${url}`,
                            filename: "crl.der",
                        });
                    }

                    // 3. AIA (Certs)
                    const aiaUrls = getCaIssuers(cert);
                    for (const url of aiaUrls) {
                        commands.push({
                            type: "CERT",
                            url: url,
                            command: `curl --output extra_cert.der ${url}`,
                            filename: "extra_cert.der",
                        });
                    }
                }
            }

            setValidationCommands(commands);
            setStep(4);
        } catch (err) {
            setError("Failed to process TSR: " + err);
        } finally {
            setLoading(false);
        }
    };

    // STEP 5: Finalize
    const handleFinalize = async () => {
        if (!sessionRef.current || !tsr) return;
        setLoading(true);
        setError(null);
        try {
            // First embed the timestamp token
            const pdfWithTimestamp = await sessionRef.current.embedTimestampToken(tsr);

            // Then manually add DSS with all gathered data
            const finalPdf = await addDSS(pdfWithTimestamp, {
                certificates: uploadedValidationData.certificates,
                crls: uploadedValidationData.crls,
                ocspResponses: uploadedValidationData.ocspResponses,
            });

            const blob = new Blob([finalPdf.buffer as ArrayBuffer], { type: "application/pdf" });
            setResultPdf({ blob, name: (file?.name || "signed.pdf").replace(".pdf", "_ltv.pdf") });
        } catch (err) {
            setError("Finalization failed: " + err);
        } finally {
            setLoading(false);
        }
    };

    if (!file) {
        return (
            <div className="manual-ltv-panel hcenter vcenter py20">
                <FileDrop onFileSelect={handleFileSelect} data-testid="ltv-pdf-drop" />
            </div>
        );
    }

    return (
        <div className="manual-ltv-panel">
            {resultPdf && (
                <div className="done" data-testid="ltv-success-message">
                    <CheckCircle size={48} className="text-green-600 mb-4" />
                    <h3>LTV Timestamp Added Successfully!</h3>
                    <div className="mt4 flex gap2 vcenter hcenter">
                        <button
                            className="btn"
                            data-testid="btn-download-final-ltv"
                            onClick={() => downloadBlob(resultPdf.blob, resultPdf.name)}
                        >
                            <Download size={20} /> Download Signed PDF
                        </button>
                        <button className="btn sec" onClick={reset}>
                            Sign Another
                        </button>
                    </div>
                </div>
            )}

            {!resultPdf && (
                <>
                    <h2 className="text-xl font-bold mb4 flex gap2 vcenter">
                        <PenTool className="text-blue-600" /> Manual LTV Timestamping
                    </h2>
                    <div className="subhead mb4">
                        <div className="flex vcenter between w-full">
                            <span>
                                <strong className="bold">File:</strong> {file.name}
                            </span>
                            <button onClick={reset} className="link">
                                Change File
                            </button>
                        </div>
                        <div className="steps-indicator flex gap2 mt2 text-sm gray hcenter">
                            <span className={step >= 1 ? "bold blue" : ""}>1. Request</span>
                            <ArrowRight size={14} />
                            <span className={step >= 2 ? "bold blue" : ""}>2. Fetch</span>
                            <ArrowRight size={14} />
                            <span className={step >= 3 ? "bold blue" : ""}>3. Analyze</span>
                            <ArrowRight size={14} />
                            <span className={step >= 4 ? "bold blue" : ""}>4. Validation</span>
                            <ArrowRight size={14} />
                            <span className={step >= 5 ? "bold blue" : ""}>5. Embed</span>
                        </div>
                    </div>

                    {loading && (
                        <div className="loading" role="status">
                            <Loader2 className="spin" /> <span>Processing...</span>
                        </div>
                    )}

                    {error && (
                        <div className="error mb4" role="alert">
                            <AlertCircle size={20} /> <span>{error}</span>
                        </div>
                    )}

                    {!loading && step === 1 && (
                        <div data-testid="ltv-step-1">
                            <h3>Step 1: Generate Request</h3>
                            <p className="mb2">Select the TSA URL you will use:</p>
                            <div className="flex flex-col gap2 mb4">
                                <select
                                    className="input"
                                    value={tsaUrl}
                                    onChange={(e) => setTsaUrl(e.target.value)}
                                >
                                    <option value={KNOWN_TSA_URLS.AIMODA}>
                                        AI Moda (Supports CORS/Automatic)
                                    </option>
                                    <option value={KNOWN_TSA_URLS.FREETSA}>
                                        FreeTSA.org (No CORS/Manual)
                                    </option>
                                    <option value={KNOWN_TSA_URLS.DIGICERT}>
                                        DigiCert (HTTP Only)
                                    </option>
                                    <option value="custom">-- Custom URL --</option>
                                </select>
                            </div>
                            <button
                                onClick={handleGenerateTsq}
                                className="btn wide"
                                data-testid="btn-generate-tsq"
                            >
                                Generate .tsq File
                            </button>
                        </div>
                    )}

                    {!loading && step === 2 && tsq && (
                        <div data-testid="ltv-step-2">
                            <h3>Step 2: Get Timestamp Response</h3>

                            <div className="section mb4">
                                <div className="bold mb1">A. Download Request File:</div>
                                <button
                                    onClick={() =>
                                        downloadBlob(
                                            new Blob([tsq as unknown as BlobPart]),
                                            "request.tsq"
                                        )
                                    }
                                    className="sec swide"
                                    data-testid="btn-download-tsq"
                                >
                                    <Download size={16} /> Download request.tsq
                                </button>
                            </div>

                            <div className="section mb4">
                                <div className="bold mb1">B. Run Curl Command (Terminal):</div>
                                <div className="code mb2" role="presentation">
                                    curl -H "Content-Type: application/timestamp-query"
                                    --data-binary @request.tsq --output response.tsr {tsaUrl}
                                </div>
                                {(tsaUrl.includes("ai.moda") || tsaUrl.includes("localhost")) && (
                                    <div className="mt2">
                                        <button
                                            className="btn wide"
                                            data-testid="btn-automatic-fetch"
                                            onClick={async () => {
                                                setLoading(true);
                                                setError(null);
                                                try {
                                                    const resp = await fetch(tsaUrl, {
                                                        method: "POST",
                                                        headers: {
                                                            "Content-Type":
                                                                "application/timestamp-query",
                                                        },
                                                        body: tsq! as unknown as BodyInit,
                                                    });
                                                    if (!resp.ok)
                                                        throw new Error(
                                                            `TSA server returned ${resp.status}`
                                                        );
                                                    const bytes = new Uint8Array(
                                                        await resp.arrayBuffer()
                                                    );
                                                    await handleTsrUpload(bytes);
                                                } catch (err) {
                                                    setError(
                                                        "Automatic fetch failed (CORS?): " + err
                                                    );
                                                } finally {
                                                    setLoading(false);
                                                }
                                            }}
                                        >
                                            Fetch Response Automatically (CORS)
                                        </button>
                                    </div>
                                )}
                            </div>

                            <div className="section" data-testid="upload-response-section">
                                <div className="bold mb1">C. Upload Response (.tsr):</div>
                                <FileDrop
                                    onFileSelect={async (f) => {
                                        const buf = await f.arrayBuffer();
                                        handleTsrUpload(new Uint8Array(buf));
                                    }}
                                    accept=".tsr,.der,.bin"
                                    label="Drop response.tsr here"
                                />
                            </div>
                        </div>
                    )}

                    {!loading && step === 4 && (
                        <div data-testid="ltv-step-4">
                            <h3>Step 3 & 4: Fetch & Upload Validation Data</h3>
                            <p className="mb4 text-sm">
                                We analyzed the timestamp. Fetch revocation data if needed.
                            </p>

                            {validationCommands.length === 0 ? (
                                <div className="info mb4">
                                    No external validation sources (OCSP/CRL/AIA) found. You can
                                    proceed to finalize.
                                </div>
                            ) : (
                                <div className="commands-list mb4">
                                    {validationCommands.map((cmd, idx) => (
                                        <div
                                            key={idx}
                                            className="cmd-item mb3 p2 border rounded bg-slate-50"
                                        >
                                            <div className="flex between mb1">
                                                <strong className="badge">{cmd.type}</strong>
                                                <span className="text-xs gray">{cmd.url}</span>
                                            </div>
                                            <div className="code text-xs break-all mb2">
                                                {cmd.command}
                                            </div>
                                            {cmd.requestBytes && (
                                                <button
                                                    onClick={() =>
                                                        downloadBlob(
                                                            new Blob([
                                                                cmd.requestBytes as unknown as BlobPart,
                                                            ]),
                                                            cmd.requestFilename!
                                                        )
                                                    }
                                                    className="text-xs link blue"
                                                >
                                                    Download {cmd.requestFilename}
                                                </button>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            )}

                            <div className="upload-section card alt">
                                <h4>Upload Fetched Files</h4>
                                <div className="flex gap2 wrap mb2">
                                    <label className="btn sec">
                                        <Upload size={16} /> Select Files
                                        <input
                                            type="file"
                                            multiple
                                            className="hidden"
                                            onChange={async (e) => {
                                                if (e.target.files) {
                                                    const newCrls: Uint8Array[] = [
                                                        ...uploadedValidationData.crls,
                                                    ];
                                                    const newOcsps: Uint8Array[] = [
                                                        ...uploadedValidationData.ocspResponses,
                                                    ];
                                                    const newCerts: Uint8Array[] = [
                                                        ...uploadedValidationData.certificates,
                                                    ];

                                                    for (
                                                        let i = 0;
                                                        i < e.target.files.length;
                                                        i++
                                                    ) {
                                                        const f = e.target.files[i];
                                                        const buf = new Uint8Array(
                                                            await f.arrayBuffer()
                                                        );
                                                        try {
                                                            const asn1 = asn1js.fromBER(
                                                                buf.slice().buffer
                                                            );
                                                            try {
                                                                const crl =
                                                                    new pkijs.CertificateRevocationList(
                                                                        { schema: asn1.result }
                                                                    );
                                                                if (crl.signature) {
                                                                    newCrls.push(buf);
                                                                    continue;
                                                                }
                                                            } catch {
                                                                /* ignore */
                                                            }
                                                            try {
                                                                const cert = new pkijs.Certificate({
                                                                    schema: asn1.result,
                                                                });
                                                                if (cert.serialNumber) {
                                                                    newCerts.push(buf);
                                                                    continue;
                                                                }
                                                            } catch {
                                                                /* ignore */
                                                            }
                                                            newOcsps.push(buf);
                                                        } catch {
                                                            /* ignore */
                                                        }
                                                    }
                                                    setUploadedValidationData({
                                                        crls: newCrls,
                                                        ocspResponses: newOcsps,
                                                        certificates: newCerts,
                                                    });
                                                }
                                            }}
                                        />
                                    </label>
                                    <div className="status-counts flex vcenter gap2">
                                        <span className="badge">
                                            {uploadedValidationData.crls.length} CRLs
                                        </span>
                                        <span className="badge">
                                            {uploadedValidationData.ocspResponses.length} OCSPs
                                        </span>
                                        <span className="badge">
                                            {uploadedValidationData.certificates.length} Certs
                                        </span>
                                    </div>
                                </div>
                            </div>

                            <button
                                onClick={handleFinalize}
                                className="btn wide mt4"
                                data-testid="btn-finalize-ltv"
                            >
                                Finalize & Sign PDF
                            </button>
                        </div>
                    )}
                </>
            )}
        </div>
    );
}
