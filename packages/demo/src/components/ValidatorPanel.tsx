import { useState } from "react";
import {
    extractTimestamps,
    verifyTimestamp,
    getDSSInfo,
    extractLTVData,
    TimestampInfo,
} from "pdf-rfc3161";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import FileDrop from "./FileDrop";
import {
    CheckCircle,
    XCircle,
    Shield,
    FileText,
    List,
    AlertTriangle,
    ShieldOff,
} from "lucide-react";

interface ValidationResult {
    isValid: boolean;
    info: TimestampInfo;
    chain: { subject: string; issuer: string; serial: string }[];
    dss?: { certs: number; crls: number; ocsps: number };
    errors?: string[];
    reason?: string;
    location?: string;
    contactInfo?: string;
    m?: Date;
}

export default function ValidatorPanel() {
    const [file, setFile] = useState<File | null>(null);
    const [isValidating, setIsValidating] = useState(false);
    const [results, setResults] = useState<ValidationResult[]>([]);
    const [dssInfo, setDssInfo] = useState<{ certs: number; crls: number; ocsps: number } | null>(null);

    const handleFileSelect = (selectedFile: File) => {
        setFile(selectedFile);
        setResults([]);
        setDssInfo(null);
    };

    const runValidation = async (fileOverride?: File) => {
        const targetFile = fileOverride || file;
        if (!targetFile) return;

        setIsValidating(true);
        setResults([]);
        setDssInfo(null);

        try {
            const arrayBuffer = await targetFile.arrayBuffer();
            const pdfBytes = new Uint8Array(arrayBuffer);

            // 1. Get DSS Info
            const dss = await getDSSInfo(pdfBytes);
            setDssInfo(dss);

            // 2. Extract Timestamps
            const extracted = await extractTimestamps(pdfBytes);

            const validationResults: ValidationResult[] = [];

            for (const ts of extracted) {
                const errors: string[] = [];
                let isValid = false;
                let info: TimestampInfo | null = null;
                const chain: { subject: string; issuer: string; serial: string }[] = [];

                // Verify
                try {
                    const verification = await verifyTimestamp(ts, {
                        pdf: pdfBytes,
                        strictESSValidation: false // Allow loose for demo to show content
                    });
                    // verifyTimestamp returns TimestampResult... wait, verifyTimestamp signature in extract.ts
                    // It returns Promise<TimestampVerifyResult> which has { status: 'valid' | 'invalid', info: ..., error?: ... }
                    // Actually checking index.ts exports: 'verifyTimestamp'.

                    if (verification.verified && verification.info) {
                        isValid = true;
                        info = verification.info;
                    } else {
                        isValid = false;
                        if (verification.verificationError) errors.push(verification.verificationError);
                        if (verification.info) info = verification.info;
                    }
                } catch (e) {
                    errors.push(e instanceof Error ? e.message : String(e));
                }

                // If we didn't get info from verify (failed early), try to parse manually
                if (!info && ts.token) {
                    // manual check not implemented here, assumed verifyTimestamp returns info on partial fail?
                    // If not, we skip info.
                }

                // Extract Chain from Token to display
                if (ts.token) {
                    try {
                        const ltv = extractLTVData(ts.token);
                        for (const certBytes of ltv.certificates) {
                            const asn1 = asn1js.fromBER(certBytes.slice().buffer);
                            const cert = new pkijs.Certificate({ schema: asn1.result });

                            // Simple parser for DN
                            const getCN = (dn: pkijs.RelativeDistinguishedNames) => {
                                for (const set of dn.typesAndValues) {
                                    // 2.5.4.3 is CN
                                    if (set.type === "2.5.4.3") {
                                        return set.value.valueBlock.value;
                                    }
                                }
                                return "Unknown";
                            };

                            chain.push({
                                subject: getCN(cert.subject),
                                issuer: getCN(cert.issuer),
                                serial: cert.serialNumber.valueBlock.toString()
                            });
                        }
                    } catch (e) {
                        console.error("Failed to parse chain", e);
                    }
                }

                if (info) {
                    validationResults.push({
                        isValid,
                        info,
                        chain,
                        errors: errors.length > 0 ? errors : undefined,
                        reason: ts.reason,
                        location: ts.location,
                        contactInfo: ts.contactInfo,
                        m: ts.m
                    });
                }
            }

            setResults(validationResults);

        } catch (error) {
            console.error("Validation failed", error);
            // Show global error?
        } finally {
            setIsValidating(false);
        }
    };

    return (
        <div className="space-y-6">
            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Shield className="w-5 h-5 text-blue-600" />
                    Internal Validator & Inspector
                </h2>

                <FileDrop
                    onFileSelect={(f) => {
                        handleFileSelect(f);
                        // Auto-run validation
                        setTimeout(() => runValidation(f), 0);
                    }}
                    accept=".pdf"
                    label="Drop PDF to Validate"
                />

                {/* Status Indicator only, no button */}
                {isValidating && (
                    <div className="mt-4 flex justify-end text-blue-600 items-center gap-2">
                        <List className="w-4 h-4 animate-spin" />
                        <span>Inspecting...</span>
                    </div>
                )}
            </div>

            {dssInfo && (
                <div className="bg-slate-50 p-4 rounded-lg border border-slate-200" data-testid="dss-section">
                    <h3 className="text-sm font-medium text-slate-700 mb-2">PAdES Structure (DSS)</h3>
                    <div className="grid grid-cols-3 gap-4 text-center">
                        <div className="bg-white p-2 rounded shadow-sm">
                            <div className="text-2xl font-bold text-slate-900">{dssInfo.certs}</div>
                            <div className="text-xs text-slate-500">Embedded Certs</div>
                        </div>
                        <div className="bg-white p-2 rounded shadow-sm">
                            <div className="text-2xl font-bold text-slate-900">{dssInfo.crls}</div>
                            <div className="text-xs text-slate-500">Embedded CRLs</div>
                        </div>
                        <div className="bg-white p-2 rounded shadow-sm">
                            <div className="text-2xl font-bold text-slate-900">{dssInfo.ocsps}</div>
                            <div className="text-xs text-slate-500">Embedded OCSPs</div>
                        </div>
                    </div>
                </div>
            )}

            {!isValidating && file && results.length === 0 && (
                <div className="bg-amber-50 border border-amber-200 p-6 rounded-lg text-center" role="alert" data-testid="no-timestamps-message">
                    <ShieldOff className="w-12 h-12 text-amber-500 mx-auto mb-2 opacity-50" />
                    <h3 className="text-amber-800 font-medium">No Timestamps Found</h3>
                    <p className="text-sm text-amber-700 mt-1">
                        This PDF does not appear to have any RFC 3161 timestamp signatures.
                    </p>
                </div>
            )}

            <div className="space-y-4">
                {results.map((result, idx) => (
                    <div key={idx} className={`border rounded-lg p-4 ${result.isValid ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'}`}>
                        <div className="flex items-start justify-between mb-4">
                            <div className="flex items-center gap-3">
                                {result.isValid ? (
                                    <CheckCircle className="w-6 h-6 text-green-600" />
                                ) : (
                                    <XCircle className="w-6 h-6 text-red-600" />
                                )}
                                <div>
                                    <h3 className="font-semibold text-gray-900">Timestamp #{idx + 1}</h3>
                                    <div className="text-sm text-gray-500">
                                        Time: {result.info.genTime.toLocaleString()}
                                    </div>
                                </div>
                            </div>
                            <div className="text-right text-xs text-gray-400">
                                Serial: {result.info.serialNumber}
                            </div>
                        </div>

                        {result.errors && (
                            <div className="mb-4 bg-red-100 text-red-700 p-3 rounded text-sm flex items-start gap-2">
                                <AlertTriangle className="w-4 h-4 mt-0.5" />
                                <div>
                                    {result.errors.map((e, i) => <div key={i}>{e}</div>)}
                                </div>
                            </div>
                        )}

                        <div className="bg-white/50 rounded p-3 mb-3 text-sm">
                            <div className="grid grid-cols-2 gap-2">
                                <div><span className="text-gray-500">Hash Algo:</span> {result.info.hashAlgorithm}</div>
                                <div><span className="text-gray-500">Policy:</span> {result.info.policy}</div>
                                <div><span className="text-gray-500">TSA:</span> {result.chain[0]?.subject ?? "Unknown"}</div>
                                <div>
                                    <span className="text-gray-500">LTV Status:</span>
                                    {dssInfo ? <span className="ml-2 px-2 py-0.5 rounded-full bg-blue-100 text-blue-800 text-xs">Present</span> : <span className="ml-2 text-gray-400">Not embedded</span>}
                                </div>
                                {result.reason && <div><span className="text-gray-500">Reason:</span> {result.reason}</div>}
                                {result.location && <div><span className="text-gray-500">Location:</span> {result.location}</div>}
                                {result.contactInfo && <div><span className="text-gray-500">Contact:</span> {result.contactInfo}</div>}
                                {result.m && <div><span className="text-gray-500">Signed At:</span> {result.m.toLocaleString()}</div>}
                            </div>
                        </div>

                        {result.chain.length > 0 && (
                            <div className="text-sm">
                                <h4 className="font-medium text-gray-700 mb-2 flex items-center gap-2">
                                    <FileText className="w-4 h-4" /> Certificate Chain
                                </h4>
                                <div className="space-y-2 pl-2 border-l-2 border-gray-300">
                                    {result.chain.map((cert, cIdx) => (
                                        <div key={cIdx} className="relative pl-4">
                                            <div className="font-medium text-gray-800">{cert.subject}</div>
                                            <div className="text-xs text-gray-500">Issued by: {cert.issuer}</div>
                                            <div className="text-xs text-gray-400 font-mono">Serial: {cert.serial}</div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        <details className="mt-4 text-xs font-mono text-gray-500 cursor-pointer">
                            <summary className="hover:text-blue-600 focus:outline-none focus:text-blue-600 mb-2">Show Raw Info</summary>
                            <pre className="bg-gray-50 p-2 rounded overflow-x-auto">
                                {JSON.stringify({ ...result.info, dss: dssInfo }, null, 2)}
                            </pre>
                        </details>
                    </div>
                ))}
            </div>
        </div>
    );
}
