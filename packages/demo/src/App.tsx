import { useState } from "react";
import { ShieldCheck, PenTool, Terminal } from "lucide-react";
import ValidatorPanel from "./components/ValidatorPanel";
import TimestampPanel from "./components/TimestampPanel";
import { ManualLTVPanel } from "./components/ManualLTVPanel";

function App() {
    const [activeTab, setActiveTab] = useState<"verify" | "timestamp" | "manual-ltv">("verify");

    return (
        <div className="app text-center">
            <header className="head">
                <h1>PDF RFC 3161 Demo</h1>
                <p className="text-sm gray">
                    Pure JavaScript / Client-side Timestamping & Verification
                </p>
            </header>

            <div className="tabs hcenter" role="tablist" aria-label="Application tabs">
                <button
                    className={`tab ${activeTab === "verify" ? "active" : ""}`}
                    onClick={() => setActiveTab("verify")}
                    role="tab"
                    aria-selected={activeTab === "verify"}
                    aria-controls="verify-panel"
                    id="verify-tab"
                    data-testid="tab-verify"
                >
                    <ShieldCheck size={18} aria-hidden="true" /> Validate & Inspect
                </button>
                <button
                    className={`tab ${activeTab === "timestamp" ? "active" : ""}`}
                    onClick={() => setActiveTab("timestamp")}
                    role="tab"
                    aria-selected={activeTab === "timestamp"}
                    aria-controls="timestamp-panel"
                    id="timestamp-tab"
                    data-testid="tab-timestamp"
                >
                    <PenTool size={18} aria-hidden="true" /> Add Timestamp
                </button>
                <button
                    className={`tab ${activeTab === "manual-ltv" ? "active" : ""}`}
                    onClick={() => setActiveTab("manual-ltv")}
                    role="tab"
                    aria-selected={activeTab === "manual-ltv"}
                    aria-controls="manual-ltv-panel"
                    id="manual-ltv-tab"
                    data-testid="tab-manual-ltv"
                >
                    <Terminal size={18} aria-hidden="true" /> Add Timestamp with LTV
                </button>
            </div>

            <main className="content text-left">
                {activeTab === "verify" ? (
                    <div role="tabpanel" id="verify-panel" aria-labelledby="verify-tab">
                        <ValidatorPanel />
                    </div>
                ) : activeTab === "timestamp" ? (
                    <div role="tabpanel" id="timestamp-panel" aria-labelledby="timestamp-tab">
                        <TimestampPanel />
                    </div>
                ) : (
                    <div role="tabpanel" id="manual-ltv-panel" aria-labelledby="manual-ltv-tab">
                        <ManualLTVPanel />
                    </div>
                )}
            </main>

            <footer className="foot">
                <p>
                    Powered by{" "}
                    <a
                        href="https://github.com/mingulov/pdf-rfc3161"
                        target="_blank"
                        rel="noopener noreferrer"
                    >
                        pdf-rfc3161
                    </a>
                    <br />
                    &copy; 2026 Denis Mingulov
                </p>
            </footer>
        </div>
    );
}

export default App;
