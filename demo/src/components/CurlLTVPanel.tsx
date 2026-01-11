import React, { useState, useCallback } from "react";
import {
    Upload,
    Download,
    Play,
    CheckCircle,
    XCircle,
    AlertCircle,
    Terminal,
    Copy,
    Check,
} from "lucide-react";
import { timestampPdf, KNOWN_TSA_URLS } from "pdf-rfc3161";

interface CurlCommand {
    id: string;
    command: string;
    description: string;
    result?: Uint8Array;
    status: "pending" | "running" | "success" | "error";
    error?: string;
    pasteValue?: string;
}

// Browser Console Commands Panel Component
function BrowserConsolePanel() {
    const [copied, setCopied] = useState<string | null>(null);

    const generateConsoleCode = (step: number) => {
        switch (step) {
            case 1:
                return `// Step 1: Create hash of your document and request timestamp
const message = new TextEncoder().encode('YOUR_DOCUMENT_CONTENT_OR_HASH');
const hashBuffer = await crypto.subtle.digest('SHA-256', message);
const hashArray = new Uint8Array(hashBuffer);

// Generate proper TimeStampReq ASN.1 structure (simplified)
// Then send request:
const tspReq = new Uint8Array([/* Your TimeStampReq bytes */]);
const response = await fetch('${KNOWN_TSA_URLS.FREETSA}', {
  method: 'POST',
  headers: { 'Content-Type': 'application/timestamp-query' },
  body: tspReq
});
const tspResp = new Uint8Array(await response.arrayBuffer());
console.log('Base64 response:', btoa(String.fromCharCode(...tspResp)));`;

            case 2:
                return `// Step 2: Get OCSP response
// First, create OCSP request for your certificate
const cert = new Uint8Array([/* Your certificate bytes */]);

// Generate OCSP request ASN.1 (simplified)
const ocspReq = new Uint8Array([/* Your OCSPRequest bytes */]);

const response = await fetch('http://ocsp.example.com', {
  method: 'POST',
  headers: { 'Content-Type': 'application/ocsp-request' },
  body: ocspReq
});
const ocspResp = new Uint8Array(await response.arrayBuffer());
console.log('Base64 OCSP response:', btoa(String.fromCharCode(...ocspResp)));`;

            case 3:
                return `// Step 3: Download CRL
const response = await fetch('http://crl.example.com/ca.crl');
const crl = new Uint8Array(await response.arrayBuffer());
console.log('Base64 CRL:', btoa(String.fromCharCode(...crl)));`;

            case 4:
                return `// Helper: Convert Uint8Array to Base64 for pasting
function toBase64(data) {
  return btoa(String.fromCharCode(...data));
}

// Helper: Parse Base64 back to Uint8Array
function fromBase64(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Example usage:
console.log('Paste the Base64 response from Step 1-3 above');
const pastedData = fromBase64('TUlJRXRUQ0NBY2FnQXdJQkFnSUpBS0hWdExKNg==');
console.log('Parsed data length:', pastedData.length);`;

            default:
                return "";
        }
    };

    const copyToClipboard = async (step: number) => {
        const code = generateConsoleCode(step);
        await navigator.clipboard.writeText(code);
        setCopied(`step${step}`);
        setTimeout(() => setCopied(null), 2000);
    };

    const copyAllCode = async () => {
        const allCode = `// Browser Console Commands for LTV Generation
// Run these in your browser's Developer Console (F12)

// Step 1-3: Get timestamp, OCSP, and CRL data
// Step 4: Helper functions for Base64 conversion

${[1, 2, 3, 4].map((i) => `// --- Step ${i} ---\n${generateConsoleCode(i)}`).join("\n\n")}`;
        await navigator.clipboard.writeText(allCode);
        setCopied("all");
        setTimeout(() => setCopied(null), 2000);
    };

    return (
        <div className="bg-slate-900 rounded-lg p-6 text-white">
            <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-2">
                    <Terminal className="w-5 h-5 text-yellow-400" />
                    <h3 className="font-semibold text-yellow-400">Browser Console Commands</h3>
                </div>
                <button
                    onClick={copyAllCode}
                    className="flex items-center space-x-1 px-3 py-1 bg-slate-700 rounded text-sm hover:bg-slate-600"
                >
                    {copied === "all" ? (
                        <Check className="w-4 h-4" />
                    ) : (
                        <Copy className="w-4 h-4" />
                    )}
                    <span>Copy All</span>
                </button>
            </div>
            <p className="text-gray-400 text-sm mb-4">
                For advanced users: Run these commands in browser console to get data, then paste
                Base64 output here.
            </p>
            <div className="space-y-4">
                {[1, 2, 3, 4].map((step) => (
                    <div key={step} className="relative">
                        <div className="bg-slate-800 rounded-lg p-4 font-mono text-sm overflow-x-auto">
                            <pre className="text-green-400 whitespace-pre-wrap">
                                {generateConsoleCode(step)}
                            </pre>
                        </div>
                        <button
                            onClick={() => copyToClipboard(step)}
                            className="absolute top-2 right-2 p-1 bg-slate-700 rounded hover:bg-slate-600"
                            title="Copy code"
                        >
                            {copied === `step${step}` ? (
                                <Check className="w-4 h-4 text-green-400" />
                            ) : (
                                <Copy className="w-4 h-4 text-gray-400" />
                            )}
                        </button>
                    </div>
                ))}
            </div>
        </div>
    );
}

export function CurlLTVPanel() {
    const [pdfFile, setPdfFile] = useState<File | null>(null);
    const [curlCommands, setCurlCommands] = useState<CurlCommand[]>([
        {
            id: "1",
            command:
                'curl -s --data-binary @timestamp_request.der -H "Content-Type: application/timestamp-query" -X POST https://freetsa.org/tsr > timestamp_response.tsr',
            description: "Get timestamp token from TSA",
            status: "pending",
        },
        {
            id: "2",
            command:
                'curl -s --data-binary @ocsp_request.der -H "Content-Type: application/ocsp-request" -X POST http://ocsp.example.com > ocsp_response.der',
            description: "Get OCSP response for certificate",
            status: "pending",
        },
        {
            id: "3",
            command: "curl -s http://crl.example.com/ca.crl > crl_response.crl",
            description: "Download CRL for certificate authority",
            status: "pending",
        },
    ]);
    const [isProcessing, setIsProcessing] = useState(false);
    const [resultPdf, setResultPdf] = useState<Uint8Array | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [showBrowserCommands, setShowBrowserCommands] = useState(false);

    const handlePdfUpload = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (file) {
            setPdfFile(file);
        }
    }, []);

    const handleFileUpload = useCallback(
        (commandId: string) => (event: React.ChangeEvent<HTMLInputElement>) => {
            const file = event.target.files?.[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    const arrayBuffer = e.target?.result as ArrayBuffer;
                    const uint8Array = new Uint8Array(arrayBuffer);

                    setCurlCommands((prev) =>
                        prev.map((cmd) =>
                            cmd.id === commandId
                                ? { ...cmd, result: uint8Array, status: "success", pasteValue: "" }
                                : cmd
                        )
                    );
                };
                reader.readAsArrayBuffer(file);
            }
        },
        []
    );

    const handlePasteInput = useCallback(
        (commandId: string) => (event: React.ChangeEvent<HTMLTextAreaElement>) => {
            const value = event.target.value.trim();
            if (!value) return;

            try {
                let uint8Array: Uint8Array;

                // Try base64 first
                if (/^[A-Za-z0-9+/=]+$/.test(value) && value.length % 4 === 0) {
                    const binaryString = atob(value);
                    uint8Array = new Uint8Array(binaryString.length);
                    for (let i = 0; i < binaryString.length; i++) {
                        uint8Array[i] = binaryString.charCodeAt(i);
                    }
                } else if (/^[0-9A-Fa-f]+$/.test(value)) {
                    // Hex format
                    const hex = value.replace(/\s/g, "");
                    uint8Array = new Uint8Array(hex.length / 2);
                    for (let i = 0; i < hex.length; i += 2) {
                        uint8Array[i / 2] = parseInt(hex.substr(i, 2), 16);
                    }
                } else {
                    // Try as raw text
                    const encoder = new TextEncoder();
                    uint8Array = encoder.encode(value);
                }

                setCurlCommands((prev) =>
                    prev.map((cmd) =>
                        cmd.id === commandId
                            ? { ...cmd, result: uint8Array, status: "success", pasteValue: value }
                            : cmd
                    )
                );
            } catch {
                setCurlCommands((prev) =>
                    prev.map((cmd) =>
                        cmd.id === commandId
                            ? {
                                  ...cmd,
                                  status: "error",
                                  error: "Invalid format. Use Base64 or Hex.",
                              }
                            : cmd
                    )
                );
            }
        },
        []
    );

    const runCommand = useCallback(async (command: CurlCommand) => {
        setCurlCommands((prev) =>
            prev.map((cmd) => (cmd.id === command.id ? { ...cmd, status: "running" } : cmd))
        );

        try {
            // In a real implementation, this would execute the curl command
            // For demo purposes, we'll simulate the result
            await new Promise((resolve) => setTimeout(resolve, 2000));

            // Simulate success for demo
            setCurlCommands((prev) =>
                prev.map((cmd) => (cmd.id === command.id ? { ...cmd, status: "success" } : cmd))
            );
        } catch (err) {
            setCurlCommands((prev) =>
                prev.map((cmd) =>
                    cmd.id === command.id ? { ...cmd, status: "error", error: String(err) } : cmd
                )
            );
        }
    }, []);

    const generateLTV = useCallback(async () => {
        if (!pdfFile) return;

        setIsProcessing(true);
        setError(null);

        try {
            const pdfArrayBuffer = await pdfFile.arrayBuffer();
            const pdfBytes = new Uint8Array(pdfArrayBuffer);

            // Check if we have a timestamp token from command 1
            const timestampCmd = curlCommands.find((cmd) => cmd.id === "1");
            if (!timestampCmd?.result) {
                // If no pre-fetched timestamp token, request one from TSA
                const result = await timestampPdf({
                    pdf: pdfBytes,
                    tsa: {
                        url: KNOWN_TSA_URLS.FREETSA,
                        hashAlgorithm: "SHA-256",
                    },
                    enableLTV: true,
                });

                setResultPdf(result.pdf);
            } else {
                // Use pre-fetched revocation data if available
                const revocationData = {
                    certificates: [] as Uint8Array[],
                    crls: [] as Uint8Array[],
                    ocspResponses: [] as Uint8Array[],
                };

                curlCommands.forEach((cmd) => {
                    if (cmd.result) {
                        if (cmd.id === "2") {
                            revocationData.ocspResponses.push(cmd.result);
                        } else if (cmd.id === "3") {
                            revocationData.crls.push(cmd.result);
                        }
                    }
                });

                // Request timestamp with pre-fetched revocation data
                const result = await timestampPdf({
                    pdf: pdfBytes,
                    tsa: {
                        url: KNOWN_TSA_URLS.FREETSA,
                        hashAlgorithm: "SHA-256",
                    },
                    enableLTV: true,
                    revocationData,
                });

                setResultPdf(result.pdf);
            }
        } catch (err) {
            const errorMessage = err instanceof Error ? err.message : String(err);
            setError(`LTV generation failed: ${errorMessage}`);
        } finally {
            setIsProcessing(false);
        }
    }, [pdfFile, curlCommands]);

    const downloadResult = useCallback(() => {
        if (!resultPdf) return;

        const blob = new Blob([new Uint8Array(resultPdf)], { type: "application/pdf" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "timestamped-ltv.pdf";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }, [resultPdf]);

    const getStatusIcon = (status: CurlCommand["status"]) => {
        switch (status) {
            case "pending":
                return <AlertCircle className="w-5 h-5 text-gray-400" />;
            case "running":
                return <Play className="w-5 h-5 text-blue-500 animate-pulse" />;
            case "success":
                return <CheckCircle className="w-5 h-5 text-green-500" />;
            case "error":
                return <XCircle className="w-5 h-5 text-red-500" />;
        }
    };

    return (
        <div className="max-w-4xl mx-auto p-6 space-y-6">
            <div className="text-center">
                <h2 className="text-2xl font-bold text-gray-900 mb-2">Curl-Based LTV Generation</h2>
                <p className="text-gray-600 mb-4">
                    Generate Long-Term Validation PDFs using pre-fetched revocation data from curl
                    commands
                </p>
                <label className="inline-flex items-center cursor-pointer bg-gray-100 px-4 py-2 rounded-lg">
                    <input
                        type="checkbox"
                        checked={showBrowserCommands}
                        onChange={(e) => setShowBrowserCommands(e.target.checked)}
                        className="mr-2"
                    />
                    <span className="text-sm text-gray-700">Show browser console commands</span>
                </label>
            </div>

            {/* Browser Console Commands Panel */}
            {showBrowserCommands && <BrowserConsolePanel />}

            {/* PDF Upload */}
            <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold mb-4">Step 1: Upload PDF Document</h3>
                <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center">
                    <input
                        type="file"
                        accept=".pdf"
                        onChange={handlePdfUpload}
                        className="hidden"
                        id="pdf-upload"
                    />
                    <label htmlFor="pdf-upload" className="cursor-pointer">
                        <Upload className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                        <p className="text-gray-600">
                            {pdfFile ? pdfFile.name : "Click to upload PDF document"}
                        </p>
                    </label>
                </div>
            </div>

            {/* Curl Commands */}
            <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold mb-4">Step 2: Execute Curl Commands</h3>
                <div className="space-y-4">
                    {curlCommands.map((cmd) => (
                        <div key={cmd.id} className="border rounded-lg p-4">
                            <div className="flex items-start justify-between mb-2">
                                <div className="flex items-center space-x-2">
                                    {getStatusIcon(cmd.status)}
                                    <span className="font-medium">{cmd.description}</span>
                                </div>
                                <div className="flex space-x-2">
                                    {cmd.status === "pending" && (
                                        <button
                                            onClick={() => runCommand(cmd)}
                                            className="px-3 py-1 bg-blue-500 text-white rounded text-sm hover:bg-blue-600"
                                        >
                                            Simulate
                                        </button>
                                    )}
                                    {cmd.id !== "1" && cmd.status === "pending" && (
                                        <>
                                            <input
                                                type="file"
                                                onChange={handleFileUpload(cmd.id)}
                                                className="hidden"
                                                id={`file-upload-${cmd.id}`}
                                            />
                                            <label
                                                htmlFor={`file-upload-${cmd.id}`}
                                                className="px-3 py-1 bg-gray-500 text-white rounded text-sm cursor-pointer hover:bg-gray-600"
                                            >
                                                Upload File
                                            </label>
                                        </>
                                    )}
                                </div>
                            </div>
                            <div className="bg-gray-100 rounded p-3 font-mono text-sm overflow-x-auto">
                                {cmd.command}
                            </div>
                            {cmd.id !== "1" && cmd.status === "pending" && (
                                <div className="mt-3">
                                    <label className="block text-sm font-medium text-gray-700 mb-1">
                                        Or paste response (Base64 or Hex):
                                    </label>
                                    <textarea
                                        value={cmd.pasteValue || ""}
                                        onChange={handlePasteInput(cmd.id)}
                                        placeholder={`Paste ${cmd.id === "2" ? "OCSP response" : "CRL"} data here...`}
                                        className="w-full p-2 border rounded text-sm font-mono"
                                        rows={3}
                                    />
                                </div>
                            )}
                            {cmd.error && (
                                <div className="mt-2 p-2 bg-red-50 border border-red-200 rounded text-red-700 text-sm">
                                    {cmd.error}
                                </div>
                            )}
                            {cmd.result && (
                                <div className="mt-2 p-2 bg-green-50 border border-green-200 rounded text-green-700 text-sm">
                                    {cmd.pasteValue
                                        ? "Data pasted successfully"
                                        : "File uploaded successfully"}{" "}
                                    ({cmd.result.length} bytes)
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            </div>

            {/* Generate LTV */}
            <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold mb-4">Step 3: Generate LTV PDF</h3>
                <div className="flex items-center justify-between">
                    <div>
                        <p className="text-gray-600 mb-2">
                            Generate PDF with embedded Long-Term Validation data using the uploaded
                            revocation materials.
                        </p>
                        <div className="text-sm text-gray-500">
                            Status: {pdfFile ? "✅ PDF loaded" : "❌ PDF required"} | Revocation
                            data: {curlCommands.filter((cmd) => cmd.result).length} files uploaded |
                            Timestamp token: ✅ Ready for demo
                        </div>
                    </div>
                    <button
                        onClick={generateLTV}
                        disabled={
                            !pdfFile ||
                            curlCommands.filter((cmd) => cmd.result).length === 0 ||
                            isProcessing
                        }
                        className="px-6 py-3 bg-green-500 text-white rounded-lg font-medium disabled:bg-gray-300 disabled:cursor-not-allowed hover:bg-green-600"
                    >
                        {isProcessing ? "Generating..." : "Generate LTV PDF"}
                    </button>
                </div>
                {error && (
                    <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded text-red-700">
                        {error}
                    </div>
                )}
            </div>

            {/* Download Result */}
            {resultPdf && (
                <div className="bg-white rounded-lg shadow p-6">
                    <h3 className="text-lg font-semibold mb-4 text-green-700">Success!</h3>
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-gray-600 mb-2">
                                LTV-enabled PDF generated successfully with embedded revocation
                                data.
                            </p>
                            <div className="text-sm text-gray-500">
                                File size: {(resultPdf.length / 1024).toFixed(1)} KB
                            </div>
                        </div>
                        <button
                            onClick={downloadResult}
                            className="flex items-center space-x-2 px-6 py-3 bg-blue-500 text-white rounded-lg font-medium hover:bg-blue-600"
                        >
                            <Download className="w-5 h-5" />
                            <span>Download PDF</span>
                        </button>
                    </div>
                </div>
            )}

            {/* Instructions */}
            <div className="bg-slate-800 rounded-lg p-6 text-white">
                <h4 className="font-semibold text-yellow-400 mb-3">Console Instructions:</h4>
                <div className="font-mono text-sm space-y-2 mb-4">
                    <div className="bg-slate-900 rounded p-3">
                        <p className="text-gray-400 text-xs mb-1"># 1. Get timestamp token:</p>
                        <p className="text-green-400">
                            curl -s --data-binary @doc.pdf.hash -H "Content-Type:
                            application/timestamp-query" https://freetsa.org/tsr &gt; timestamp.tsr
                        </p>
                    </div>
                    <div className="bg-slate-900 rounded p-3">
                        <p className="text-gray-400 text-xs mb-1">
                            # 2. Get OCSP response (replace with your cert URL):
                        </p>
                        <p className="text-green-400">
                            curl -s --data-binary @ocsp_request.der -H "Content-Type:
                            application/ocsp-request" http://ocsp.example.com &gt; ocsp.der
                        </p>
                    </div>
                    <div className="bg-slate-900 rounded p-3">
                        <p className="text-gray-400 text-xs mb-1"># 3. Download CRL:</p>
                        <p className="text-green-400">
                            curl -s http://crl.example.com/ca.crl &gt; ca.crl
                        </p>
                    </div>
                    <div className="bg-slate-900 rounded p-3">
                        <p className="text-gray-400 text-xs mb-1">
                            # 4. Convert to Base64 for pasting:
                        </p>
                        <p className="text-green-400">base64 -w 0 timestamp.tsr</p>
                    </div>
                </div>
                <p className="text-yellow-400 text-sm mt-3 mb-2">
                    <strong>Tip:</strong> After running commands, paste the Base64 or Hex encoded
                    response directly in the text areas above!
                </p>
            </div>

            {/* How to Use */}
            <div className="bg-blue-50 rounded-lg p-6">
                <h4 className="font-semibold text-blue-900 mb-2">How to use:</h4>
                <ol className="text-blue-800 space-y-1 text-sm">
                    <li>1. Upload your PDF document</li>
                    <li>
                        2. Run curl commands locally (see Console Instructions above) or paste
                        Base64/Hex responses
                    </li>
                    <li>3. Click "Generate LTV PDF" to embed the revocation data</li>
                    <li>4. Download the resulting LTV-enabled PDF</li>
                </ol>
            </div>
        </div>
    );
}
