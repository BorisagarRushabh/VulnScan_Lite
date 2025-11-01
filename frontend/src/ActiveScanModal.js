import React, { useState, useEffect, useRef } from "react";
import "./ActiveScanModal.css";

export default function ActiveScanModal({ open, onClose, defaultUrl }) {
  const [modules, setModules] = useState({
    nmap: true,
    "nikto-like": true,
    "safe-sqli-xss": true,
  });
  const [consent, setConsent] = useState(false);
  const [jobId, setJobId] = useState(null);
  const [logs, setLogs] = useState([]);
  const [results, setResults] = useState({});
  const [status, setStatus] = useState(null);
  const [isAnimating, setIsAnimating] = useState(false);
  const logsEndRef = useRef(null);

  const API_BASE = process.env.REACT_APP_API_BASE || "http://localhost:5000";

  // ESC key closes modal
  useEffect(() => {
    const handleKey = (e) => {
      if (e.key === "Escape") onClose && onClose();
    };
    if (open) window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [open, onClose]);

  // Animate blur transition
  useEffect(() => {
    if (!open) {
      setIsAnimating(true);
      const t = setTimeout(() => setIsAnimating(false), 220);
      return () => clearTimeout(t);
    }
  }, [open]);

  // Auto-scroll logs
  useEffect(() => {
    if (logsEndRef.current)
      logsEndRef.current.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  if (!open && !isAnimating) return null;

  const toggleModule = (name) =>
    setModules((m) => ({ ...m, [name]: !m[name] }));
  const selectedModules = Object.keys(modules).filter((k) => modules[k]);

  const flashConsent = () => {
    const el = document.querySelector(".asm-consent-box");
    if (!el) return;
    el.classList.remove("flash");
    void el.offsetWidth;
    el.classList.add("flash");
  };

  const startScan = async () => {
    if (!consent) {
      flashConsent();
      return alert("Confirm permission to scan.");
    }
    if (selectedModules.length === 0)
      return alert("Pick at least one module.");

    try {
      setLogs([]);
      setResults({});
      setJobId(null);
      setStatus("starting");

      const res = await fetch(`${API_BASE}/active/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: defaultUrl || "",
          modules: selectedModules,
          consent: true,
        }),
      });

      const text = await res.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch (e) {
        throw new Error(
          `Invalid JSON response from server.\n\nServer replied:\n${text.slice(
            0,
            2000
          )}`
        );
      }

      if (!res.ok || !data.ok)
        throw new Error(data?.error || "Scan failed or invalid response.");

      setJobId(data.job_id);
      setStatus("queued");
      pollJob(data.job_id);
    } catch (err) {
      console.error("startScan error:", err);
      alert("Failed to start scan: " + err.message);
      setStatus("failed");
    }
  };

  const pollJob = async (id) => {
    try {
      const res = await fetch(`${API_BASE}/active/job/${id}`);
      const text = await res.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch (e) {
        throw new Error(`Invalid JSON in poll: ${text.slice(0, 1000)}`);
      }

      if (!res.ok || !data.ok) throw new Error(data?.error || "Job fetch failed");

      setLogs(data.job.logs || []);
      setResults(data.job.result || {});
      setStatus(data.job.status || null);

      if (
        data.job.status !== "finished" &&
        data.job.status !== "failed"
      ) {
        setTimeout(() => pollJob(id), 2000);
      }
    } catch (err) {
      console.error("Polling failed:", err);
      setStatus("failed");
    }
  };

  const startDisabled =
    !(consent && selectedModules.length > 0 && !jobId);

  return (
    <div
      className={`asm-overlay ${open ? "open" : ""}`}
      role="dialog"
      aria-modal="true"
      aria-label="Active scan dialog"
    >
      <div
        className={`asm-card ${open ? "asm-open" : "asm-close"}`}
        role="document"
      >
        {/* Header */}
        <div className="asm-header">
          <div className="asm-title">⚡ Active Scan</div>
          <button
            className="asm-close-btn"
            onClick={onClose}
            title="Close"
          >
            ✕
          </button>
        </div>

        {/* Body */}
        <div className="asm-body">
          <div className="asm-warning">
            <strong>Warning:</strong> Active scans are intrusive and may be
            logged. Only scan systems you <strong>own or have permission</strong>.
          </div>

          {/* Modules */}
          <div className="asm-section">
            <div className="asm-sub">Select tools</div>
            <div className="asm-modules">
              {Object.keys(modules).map((mod) => (
                <label
                  key={mod}
                  className={`asm-module ${modules[mod] ? "active" : ""}`}
                >
                  <input
                    type="checkbox"
                    checked={modules[mod]}
                    onChange={() => toggleModule(mod)}
                  />
                  <span style={{ marginLeft: 8, cursor: "pointer" }}>
                    {mod}
                  </span>
                </label>
              ))}
            </div>
          </div>

          {/* Consent */}
          <div className={`asm-consent-box ${consent ? "granted" : ""}`}>
            <input
              type="checkbox"
              checked={consent}
              onChange={(e) => setConsent(e.target.checked)}
            />
            <label style={{ marginLeft: 8 }}>
              I confirm permission to actively scan this target.
            </label>
          </div>

          {/* Logs */}
          {jobId && (
            <div className="asm-section asm-logs">
              <div className="asm-sub">Logs ({status})</div>
              <div
                className="asm-log-container"
                style={{
                  maxHeight: 180,
                  overflowY: "auto",
                  background: "#000",
                  color: "#0f0",
                  fontFamily: "monospace",
                  padding: "8px",
                  borderRadius: "8px",
                }}
              >
                {logs.map((l, i) => (
                  <div key={i}>{l}</div>
                ))}
                <div ref={logsEndRef}></div>
              </div>
            </div>
          )}

          {/* Results */}
          {jobId && results && Object.keys(results).length > 0 && (
            <div className="asm-section asm-results-section">
              <div className="asm-sub">Scan Results</div>

              {results.nmap && (
                <pre>
                  <strong>Nmap:</strong>
                  {"\n"}
                  {results.nmap}
                </pre>
              )}

              {results.open_ports && (
                <div>
                  <strong>Open Ports:</strong>{" "}
                  {results.open_ports.join(", ")}
                </div>
              )}

              {results["nikto-like"]?.length > 0 && (
                <div>
                  <strong>Accessible Paths:</strong>
                  <ul>
                    {results["nikto-like"].map((p, i) => (
                      <li key={i}>
                        {p.path} ({p.status})
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {results["safe-sqli-xss"] && (
                <div>
                  <strong>SQLi/XSS Checks:</strong>
                  <ul>
                    {Object.entries(results["safe-sqli-xss"]).map(
                      ([k, v], i) => (
                        <li key={i}>
                          {k}: {v}
                        </li>
                      )
                    )}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="asm-footer">
          <div className="asm-actions">
            <button
              className="btn asm-start"
              onClick={startScan}
              disabled={startDisabled}
            >
              🚀 Start
            </button>
            <button className="btn asm-cancel" onClick={onClose}>
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
