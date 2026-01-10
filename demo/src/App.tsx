import { useState } from "react";
import { ShieldCheck, PenTool } from "lucide-react";
import VerifyPanel from "./components/VerifyPanel";
import TimestampPanel from "./components/TimestampPanel";

function App() {
    const [activeTab, setActiveTab] = useState<"verify" | "timestamp">("verify");

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
                >
                    <ShieldCheck size={18} aria-hidden="true" /> Verify PDF
                </button>
                <button
                    className={`tab ${activeTab === "timestamp" ? "active" : ""}`}
                    onClick={() => setActiveTab("timestamp")}
                    role="tab"
                    aria-selected={activeTab === "timestamp"}
                    aria-controls="timestamp-panel"
                    id="timestamp-tab"
                >
                    <PenTool size={18} aria-hidden="true" /> Add Timestamp
                </button>
            </div>

            <main className="content text-left">
                {activeTab === "verify" ? (
                    <div role="tabpanel" id="verify-panel" aria-labelledby="verify-tab">
                        <VerifyPanel />
                    </div>
                ) : (
                    <div role="tabpanel" id="timestamp-panel" aria-labelledby="timestamp-tab">
                        <TimestampPanel />
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
