import { useState } from "react";
import {
    timestampPdfLTA,
    extractTimestamps,
    verifyTimestamp,
    KNOWN_TSA_URLS,
    type ExtractedTimestamp,
} from "pdf-rfc3161";
import FileDrop from "./FileDrop";
import { Download, AlertCircle, Check, Loader2, Archive, Clock } from "lucide-react";

function downloadBlob(blob: Blob, name: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
}

export default function ArchivePanel() {
    const [file, setFile] = useState<File | null>(null);
    const [tsaUrl, setTsaUrl] = useState<string>(KNOWN_TSA_URLS.FREETSA);
    const [includeExistingRevocationData, setIncludeExistingRevocationData] = useState(true);

    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const [resultPdf, setResultPdf] = useState<{ blob: Blob; name: string } | null>(null);
    const [resultTimestamps, setResultTimestamps] = useState<ExtractedTimestamp[]>([]);
    const [originalTimestampCount, setOriginalTimestampCount] = useState(0);

    const reset = () => {
        setFile(null);
        setError(null);
        setResultPdf(null);
        setResultTimestamps([]);
        setOriginalTimestampCount(0);
        setLoading(false);
    };

    const processFile = async (f: File) => {
        setLoading(true);
        setError(null);

        try {
            const buffer = await f.arrayBuffer();
            const pdfBytes = new Uint8Array(buffer);

            // Check if PDF has existing timestamps
            const existingTimestamps = await extractTimestamps(pdfBytes);
            setOriginalTimestampCount(existingTimestamps.length);

            if (existingTimestamps.length === 0) {
                throw new Error(
                    "No existing timestamps found. Please add a timestamp first before archiving."
                );
            }

            // Verify existing timestamps
            const verifiedTimestamps = await Promise.all(
                existingTimestamps.map((ts) => verifyTimestamp(ts, { pdf: pdfBytes }))
            );

            const invalidTimestamps = verifiedTimestamps.filter((ts) => !ts.verified);
            if (invalidTimestamps.length > 0) {
                throw new Error(
                    `Found ${invalidTimestamps.length} invalid timestamp(s). Cannot archive invalid timestamps.`
                );
            }

            // Add archive timestamp
            const result = await timestampPdfLTA({
                pdf: pdfBytes,
                tsa: {
                    url: tsaUrl,
                    hashAlgorithm: "SHA-256",
                },
                signatureFieldName: "ArchiveTimestamp",
                includeExistingRevocationData,
            });

            // Extract final timestamps for display
            const finalTimestamps = await extractTimestamps(result.pdf);

            setResultPdf({
                blob: new Blob([new Uint8Array(result.pdf)], { type: "application/pdf" }),
                name: f.name.replace(/\.pdf$/i, "-archived.pdf"),
            });
            setResultTimestamps(finalTimestamps);
        } catch (err) {
            const errorMessage = err instanceof Error ? err.message : String(err);
            setError(errorMessage);
        } finally {
            setLoading(false);
        }
    };

    const handleFileSelect = (f: File) => {
        setFile(f);
        processFile(f);
    };

    if (!file) {
        return <FileDrop onFileSelect={handleFileSelect} />;
    }

    return (
        <div>
            <div className="subhead">
                <h3>Archive Timestamping: {file.name}</h3>
                <button onClick={reset} className="sec">
                    Archive Another
                </button>
            </div>

            {/* Configuration */}
            <div className="card mb4">
                <h4 className="mb3">Archive Configuration</h4>
                <div className="grid">
                    <div className="tag">TSA Server:</div>
                    <select
                        value={tsaUrl}
                        onChange={(e) => setTsaUrl(e.target.value)}
                        className="input"
                        disabled={loading}
                    >
                        <option value={KNOWN_TSA_URLS.FREETSA}>FreeTSA (freetsa.org)</option>
                        <option value={KNOWN_TSA_URLS.DIGICERT}>DigiCert</option>
                        <option value={KNOWN_TSA_URLS.SECTIGO}>Sectigo</option>
                    </select>

                    <div className="tag">Include Existing Revocation:</div>
                    <label className="flex items-center">
                        <input
                            type="checkbox"
                            checked={includeExistingRevocationData}
                            onChange={(e) => setIncludeExistingRevocationData(e.target.checked)}
                            disabled={loading}
                            className="mr2"
                        />
                        Include existing OCSP/CRL data from DSS
                    </label>
                </div>
            </div>

            {loading && (
                <div className="loading" role="status" aria-live="polite">
                    <Loader2 className="spin" aria-hidden="true" />
                    <span>Adding archive timestamp...</span>
                </div>
            )}

            {error && (
                <div className="error" role="alert" aria-live="assertive">
                    <AlertCircle size={20} aria-hidden="true" />
                    <span>{error}</span>
                </div>
            )}

            {!loading && resultPdf && (
                <div className="card success mb4">
                    <div className="flex gap2 mb2">
                        <Archive className="text-green-600" size={20} aria-hidden="true" />
                        <strong className="bold text-green-700">
                            Archive Timestamp Added Successfully!
                        </strong>
                    </div>

                    <div className="grid mb3">
                        <div className="tag">Original Timestamps:</div>
                        <div>{originalTimestampCount}</div>

                        <div className="tag">Final Timestamps:</div>
                        <div>{resultTimestamps.length} (+1 archive timestamp)</div>

                        <div className="tag">File Size:</div>
                        <div>{(resultPdf.blob.size / 1024).toFixed(1)} KB</div>
                    </div>

                    <button
                        onClick={() => downloadBlob(resultPdf.blob, resultPdf.name)}
                        className="flex items-center space-x-2 px-6 py-3 bg-green-500 text-white rounded-lg font-medium hover:bg-green-600"
                    >
                        <Download className="w-5 h-5" />
                        <span>Download Archived PDF</span>
                    </button>
                </div>
            )}

            {!loading && resultTimestamps.length > 0 && (
                <div className="card">
                    <h4 className="mb3">Final Timestamp Verification</h4>
                    <div className="space-y-3">
                        {resultTimestamps.map((ts, idx) => (
                            <div key={idx} className="border rounded p-3">
                                <div className="flex items-center justify-between mb-2">
                                    <span className="font-medium">
                                        {idx < originalTimestampCount
                                            ? "Document Timestamp"
                                            : "Archive Timestamp"}{" "}
                                        #{idx + 1}
                                    </span>
                                    <div className="flex items-center space-x-2">
                                        {ts.verified ? (
                                            <Check className="text-green-600" size={16} />
                                        ) : (
                                            <AlertCircle className="text-red-600" size={16} />
                                        )}
                                        <span
                                            className={`text-sm ${ts.verified ? "text-green-600" : "text-red-600"}`}
                                        >
                                            {ts.verified ? "Valid" : "Invalid"}
                                        </span>
                                    </div>
                                </div>
                                <div className="text-sm text-gray-600">
                                    <Clock size={14} className="inline mr-1" />
                                    {ts.info.genTime.toLocaleString()}
                                    {idx >= originalTimestampCount && (
                                        <span className="ml-2 px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded">
                                            ARCHIVE
                                        </span>
                                    )}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            <div className="card info mt4">
                <h4 className="text-blue-900 mb-2">About Archive Timestamps</h4>
                <div className="text-blue-800 text-sm space-y-2">
                    <p>
                        <strong>PAdES-LTA (Long-Term Archive)</strong> adds an additional timestamp
                        that "archives" the previous timestamps, ensuring long-term validity even
                        after TSA certificates expire.
                    </p>
                    <p>
                        The archive timestamp includes a hash of all previous signatures and
                        revocation data, creating an immutable record for legal and compliance
                        purposes.
                    </p>
                    <ul className="list-disc list-inside mt-2 space-y-1">
                        <li>Requires existing timestamps in the PDF</li>
                        <li>Can include existing DSS revocation data</li>
                        <li>Creates a timestamp chain for maximum longevity</li>
                        <li>Essential for legal document preservation</li>
                    </ul>
                </div>
            </div>
        </div>
    );
}
