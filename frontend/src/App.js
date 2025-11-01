// App.js
import React, { useState, useRef, useEffect } from "react";
import ScanForm from "./ScanForm";
import ScanResult from "./ScanResult";
import ActiveScanModal from "./ActiveScanModal";
import "./index.css";

const API_BASE = process.env.REACT_APP_API_BASE || "http://localhost:5000";

function App() {
  const [job, setJob] = useState(null); // { id, url, status, kind }
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [logs, setLogs] = useState([]);
  const [activeModalOpen, setActiveModalOpen] = useState(false);
  const [toolsDetected, setToolsDetected] = useState({ nmap: false }); // sample detection state
  const pollRef = useRef(null);
  const activeBtnRef = useRef(null);

  const appendLog = (text) =>
    setLogs((prev) => [...prev, `${new Date().toLocaleTimeString()} › ${text}`].slice(-200));

  // detect whether nmap exists on server by calling an endpoint (optional)
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`${API_BASE}/tools`, { method: "GET" });
        if (res.ok) {
          const data = await res.json();
          if (data && data.tools) setToolsDetected(data.tools);
          appendLog(`Detected tools: nmap=${!!data.tools?.nmap}`);
        }
      } catch (e) {
        appendLog("Failed to fetch tool list: " + e.message);
      }
    })();
    // eslint-disable-next-line
  }, []);

  // Passive scan
  const startScan = async (url) => {
    setResult(null);
    setJob(null);
    setLoading(true);
    appendLog(`Starting scan for ${url}`);
    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || "Unknown error");
      setJob({ id: data.job_id, url, status: "queued", kind: "passive" });
      appendLog(`Job queued: ${data.job_id}`);
      pollJob(data.job_id);
    } catch (err) {
      appendLog(`Error starting scan: ${err.message}`);
      alert("Failed to start scan: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  // poll passive
  const pollJob = (jobId) => {
    appendLog("Polling job status...");
    if (pollRef.current) clearInterval(pollRef.current);

    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/job/${jobId}`);
        const data = await res.json();
        if (!data.ok) {
          appendLog("Job not found or error.");
          clearInterval(pollRef.current);
          return;
        }
        const status = data.job.status;
        appendLog(`Job ${jobId} status: ${status}`);
        setJob((prev) => ({ ...(prev || {}), id: jobId, status, kind: "passive" }));

        if (data.job.logs && data.job.logs.length) {
          data.job.logs.slice(-10).forEach((l) => appendLog(l.replace(/^\[?\d{2}:\d{2}:\d{2}\]?\s*/, "")));
        }

        if (status === "finished") {
          setResult(data.job.result || {});
          appendLog("Scan finished — results received.");
          clearInterval(pollRef.current);
        } else if (status === "failed") {
          appendLog("Scan failed: " + (data.job.error || "unknown"));
          clearInterval(pollRef.current);
        }
      } catch (err) {
        appendLog("Polling error: " + err.message);
        clearInterval(pollRef.current);
      }
    }, 1200);
  };

  // Active scan start
  const startActiveScan = async (selectedModules, note) => {
    if (!job || !job.url) {
      return alert("Start a passive scan first or set a target URL before running active scan.");
    }
    appendLog("Requesting active scan...");
    try {
      const res = await fetch(`${API_BASE}/active/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: job.url, modules: selectedModules, consent: true, note }),
      });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || "active scan failed");
      setJob((j) => ({ ...(j || {}), id: data.job_id, status: "queued", kind: "active" }));
      appendLog(`Active job queued: ${data.job_id}`);
      pollActiveJob(data.job_id);
      setActiveModalOpen(false);
    } catch (e) {
      appendLog("Active scan start failed: " + e.message);
      alert("Active scan failed: " + e.message);
    }
  };

  // poll active job
  const pollActiveJob = (jobId) => {
    appendLog("Polling active job status...");
    if (pollRef.current) clearInterval(pollRef.current);

    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/active/job/${jobId}`);
        const data = await res.json();
        if (!data.ok) {
          appendLog("Active job not found or error.");
          clearInterval(pollRef.current);
          return;
        }

        const status = data.job.status;
        appendLog(`Active job ${jobId} status: ${status}`);
        setJob((prev) => ({ ...(prev || {}), id: jobId, status, kind: "active" }));

        if (data.job.logs && data.job.logs.length) {
          data.job.logs.slice(-10).forEach((l) => appendLog(l.replace(/^\[?\d{2}:\d{2}:\d{2}\]?\s*/, "")));
        }

        if (status === "finished") {
          // merge active results into result.active
          setResult((prev) => ({ ...(prev || {}), active: data.job.result || {} }));
          appendLog("Active scan finished — results received.");
          clearInterval(pollRef.current);
        } else if (status === "failed") {
          appendLog("Active scan failed: " + (data.job.error || "unknown"));
          clearInterval(pollRef.current);
        }
      } catch (e) {
        appendLog("Polling active error: " + e.message);
        clearInterval(pollRef.current);
      }
    }, 1500);
  };

  // Open active modal with pop animation
  const openActiveModal = () => {
    // button pop
    if (activeBtnRef.current) {
      activeBtnRef.current.classList.add("pop");
      setTimeout(() => activeBtnRef.current && activeBtnRef.current.classList.remove("pop"), 320);
    }
    setActiveModalOpen(true);
  };

  const clearAll = () => {
    setResult(null);
    setJob(null);
    setLogs([]);
    if (pollRef.current) clearInterval(pollRef.current);
  };

  return (
    <div className="container">
      <div className="header">
        <div className="logo"><h1>VSL</h1></div>
        <div className="title">
          <h2 className="hacker-title">VulnScan Lite <span className="blinking">_</span></h2>
          <p style={{ margin: 0 }}>Passive web security health-check — non-invasive</p>
        </div>
      </div>

      <div className="grid">
        <div className="panel">
          <ScanForm onStart={startScan} disabled={loading} />

          <div className="actions" style={{ marginTop: 14, justifyContent: "space-between" }}>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span className="tag">API: <strong style={{ marginLeft: 6 }}>{API_BASE}</strong></span>
              <div className="tool-badge" title={`nmap: ${toolsDetected.nmap ? "available" : "not found"}`}>
                <span className={`dot ${toolsDetected.nmap ? "on" : "off"}`}></span> tools
              </div>
            </div>

            <div style={{ textAlign: "right" }}>
              {job ? (
                <span className="tag">Job: <strong style={{ marginLeft: 8 }}>{job.id}</strong></span>
              ) : (
                <span className="tag">No job</span>
              )}
            </div>
          </div>

          <div style={{ marginTop: 14 }}>
            <div className="card-title"><h4>Live Terminal</h4><div className="card-sub">real-time job logs</div></div>
            <div className="terminal" aria-live="polite">
              {logs.length ? logs.map((l, i) => <div key={i}>{l}</div>) : <div style={{ color: "rgba(36,255,107,0.5)" }}>Idle — start a scan to see logs.</div>}
            </div>
          </div>

          <div style={{ marginTop: 12, display: "flex", gap: 10 }}>
            <button
              ref={activeBtnRef}
              className={`btn active-scan-trigger ${toolsDetected.nmap ? "neon" : ""}`}
              onClick={openActiveModal}
              title="Start an active scan (requires consent)"
            >
              ⚡ Active Scan
              <span className="mini-hint">intrusive</span>
            </button>

            <button className="btn" onClick={clearAll}>RESET</button>
          </div>
        </div>

        <div className="panel">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontSize: 18, fontWeight: 800 }}>Scan Results</div>
              <div style={{ color: "var(--muted)", fontSize: 13, marginTop: 4 }}>Results will appear here after the scan completes</div>
            </div>
            <div>
              <button
                className="btn"
                onClick={() => { clearAll(); }}
              >
                CLEAR
              </button>
            </div>
          </div>

          <div style={{ marginTop: 14 }}>
            <ScanResult result={result} />
          </div>
        </div>
      </div>

      <ActiveScanModal
        open={activeModalOpen}
        onClose={() => setActiveModalOpen(false)}
        onStart={startActiveScan}
        defaultUrl={job?.url}
      />

      <div className="footer">Only scan sites you own or have permission for — VulnScan Lite is passive only.</div>
    </div>
  );
}

export default App;
