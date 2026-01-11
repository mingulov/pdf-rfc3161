import { useState } from "react";
import {
    extractTimestamps,
    verifyTimestamp,
    getDSSInfo,
    validateTimestampTokenRFC8933Compliance,
    type ExtractedTimestamp,
} from "pdf-rfc3161";
import FileDrop from "./FileDrop";
import { CheckCircle, AlertCircle, Loader2, ShieldCheck, Shield } from "lucide-react";

interface RFC8933Result {
    compliant: boolean;
    issues: string[];
    digestAlgorithmConsistency: boolean;
    hasAlgorithmProtection: boolean;
}

export default function VerifyPanel() {
    const [file, setFile] = useState<File | null>(null);
    const [timestamps, setTimestamps] = useState<ExtractedTimestamp[]>([]);
    const [rfc8933Results, setRfc8933Results] = useState<RFC8933Result[]>([]);
    const [dssInfo, setDssInfo] = useState<{ certs: number; crls: number; ocsps: number } | null>(
        null
    );
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const processFile = async (f: File) => {
        setLoading(true);
        setError(null);
        setTimestamps([]);
        setRfc8933Results([]);
        setDssInfo(null);
        try {
            const buffer = await f.arrayBuffer();
            const pdfBytes = new Uint8Array(buffer);

            const extracted = await extractTimestamps(pdfBytes);

            const verifiedResults = await Promise.all(
                extracted.map((ts) => verifyTimestamp(ts, { pdf: pdfBytes }))
            );

            setTimestamps(verifiedResults);

            // RFC 8933 compliance validation (only for verified timestamps)
            const rfc8933Results = await Promise.all(
                verifiedResults.map((ts) =>
                    ts.verified && ts.token
                        ? validateTimestampTokenRFC8933Compliance(ts.token)
                        : null
                )
            );

            setTimestamps(verifiedResults);
            setRfc8933Results(rfc8933Results as RFC8933Result[]);

            const dss = await getDSSInfo(pdfBytes);
            if (dss.certs > 0 || dss.crls > 0 || dss.ocsps > 0) {
                setDssInfo(dss);
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
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
                <h3>Results for: {file.name}</h3>
                <button onClick={() => setFile(null)} className="sec">
                    Check Another
                </button>
            </div>

            {loading && (
                <div className="loading" role="status" aria-live="polite">
                    <Loader2 className="spin" aria-hidden="true" />
                    <span>Verifying...</span>
                </div>
            )}

            {error && (
                <div className="error" role="alert" aria-live="assertive">
                    <AlertCircle size={20} aria-hidden="true" />
                    <span>{error}</span>
                </div>
            )}

            {!loading && dssInfo && (
                <div
                    className="card info mb4"
                    role="region"
                    aria-label="Document Security Store Information"
                >
                    <div className="flex gap2 mb2">
                        <ShieldCheck aria-hidden="true" />
                        <strong className="bold">Document Security Store (LTV)</strong>
                    </div>
                    <div className="text-sm info-text">This document contains global LTV data:</div>
                    <div className="grid3 mt2 text-center">
                        <div className="cell" role="listitem">
                            <div
                                className="text-2xl bold"
                                aria-label={`${dssInfo.certs} certificates`}
                            >
                                {dssInfo.certs}
                            </div>
                            <div className="text-xs gray">Certificates</div>
                        </div>
                        <div className="cell" role="listitem">
                            <div className="text-2xl bold" aria-label={`${dssInfo.crls} CRLs`}>
                                {dssInfo.crls}
                            </div>
                            <div className="text-xs gray">CRLs</div>
                        </div>
                        <div className="cell" role="listitem">
                            <div
                                className="text-2xl bold"
                                aria-label={`${dssInfo.ocsps} OCSP responses`}
                            >
                                {dssInfo.ocsps}
                            </div>
                            <div className="text-xs gray">OCSP Responses</div>
                        </div>
                    </div>
                </div>
            )}

            {!loading && !error && timestamps.length === 0 && (
                <div className="text-center p8 gray" role="status">
                    No Document Timestamps found in this PDF.
                </div>
            )}

            {!loading &&
                timestamps.map((ts, idx) => (
                    <div
                        key={idx}
                        className="card"
                        role="article"
                        aria-label={`Timestamp ${idx + 1} verification result`}
                    >
                        <div className="flex gap2 mb2">
                            {ts.verified ? (
                                <CheckCircle className="status-ok" aria-hidden="true" />
                            ) : (
                                <AlertCircle className="status-err" aria-hidden="true" />
                            )}
                            <strong className="bold">Timestamp #{idx + 1}</strong>
                            <span
                                className="badge"
                                aria-label={`Signed at ${ts.info.genTime.toLocaleString()}`}
                            >
                                {ts.info.genTime.toLocaleString()}
                            </span>
                        </div>

                        <div className="grid">
                            <div className="tag">TSA Policy:</div>
                            <div>{ts.info.policy}</div>

                            <div className="tag">Hash Algo:</div>
                            <div>{ts.info.hashAlgorithm}</div>

                            <div className="tag">Message Digest:</div>
                            <div className="break mono">{ts.info.messageDigest}</div>

                            <div className="tag">Status:</div>
                            <div className={`bold ${ts.verified ? "status-ok" : "status-err"}`}>
                                {ts.verified
                                    ? "Cryptographically Valid"
                                    : `Invalid: ${ts.verificationError}`}
                            </div>

                            {ts.verified && rfc8933Results[idx] && (
                                <>
                                    <div className="tag">
                                        <Shield size={14} className="mr1" aria-hidden="true" />
                                        RFC 8933:
                                    </div>
                                    <div
                                        className={`bold ${rfc8933Results[idx].compliant ? "status-ok" : "status-warn"}`}
                                    >
                                        {rfc8933Results[idx].compliant
                                            ? "Compliant"
                                            : `Issues: ${rfc8933Results[idx].issues.join(", ")}`}
                                    </div>
                                </>
                            )}

                            {ts.certificates && ts.certificates.length > 0 && (
                                <>
                                    <div className="tag">Certificates:</div>
                                    <div className="text-xs slate">
                                        {ts.certificates.length} certificates embedded in signature
                                    </div>
                                </>
                            )}

                            {(ts.crlCount !== undefined || ts.ocspCount !== undefined) && (
                                <>
                                    <div className="tag">Local Revocation:</div>
                                    <div className="text-xs slate">
                                        {ts.crlCount || 0} CRLs, {ts.ocspCount || 0} OCSP responses
                                        (inside signature)
                                    </div>
                                </>
                            )}
                        </div>
                    </div>
                ))}
        </div>
    );
}
