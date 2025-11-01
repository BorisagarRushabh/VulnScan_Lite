// ScanResult.js
import React from "react";

function Badge({ type }) {
  if (type === "good") return React.createElement("span", { className: "badge good" }, "GOOD");
  if (type === "warn") return React.createElement("span", { className: "badge warn" }, "WARN");
  return React.createElement("span", { className: "badge bad" }, "CRITICAL");
}

function SafeValue({ value }) {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") {
    return Object.entries(value).map(([k, v]) => `${k}: ${v}`).join(", ");
  }
  return value;
}

function NullableLine({ label, value }) {
  return React.createElement(
    "div",
    { style: { marginTop: 6 } },
    React.createElement("strong", { style: { color: "var(--muted)" } }, `${label}: `),
    React.createElement(SafeValue, { value })
  );
}

export default function ScanResult({ result }) {
  if (!result) {
    return React.createElement(
      "div",
      { style: { marginTop: 12, color: "var(--muted)" } },
      "No result yet — start a scan to analyze headers, cookies, SSL & CMS."
    );
  }

  const modules = result.modules || {};
  const headers = modules.headers || result.headers || {};
  const cookies = modules.cookies || result.cookies || { cookies: [] };
  const ssl = modules.ssl || result.ssl || {};
  const cms = modules.cms || result.cms || {};

  const missingCount = headers.missing?.length || 0;

  return React.createElement(
    "div",
    { style: { marginTop: 8 } },
    // Overview
    React.createElement(
      "div",
      { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 } },
      React.createElement("div", { style: { fontWeight: 800, fontSize: 16 } }, "Overview"),
      React.createElement(
        "div",
        { style: { display: "flex", gap: 8 } },
        React.createElement(
          "div",
          { style: { display: "flex", gap: 6, alignItems: "center" } },
          React.createElement(Badge, { type: missingCount === 0 ? "good" : missingCount <= 2 ? "warn" : "bad" }),
          React.createElement("div", { style: { color: "var(--muted)", fontSize: 13 } }, `${missingCount} missing header(s)`)
        )
      )
    ),
    // Result Grid
    React.createElement(
      "div",
      { className: "result-grid" },
      // Headers
      React.createElement(
        "div",
        { className: "result-card" },
        React.createElement(
          "div",
          { className: "card-title" },
          React.createElement("h4", null, "HTTP Headers"),
          React.createElement("div", { className: "card-sub" }, "Security headers check")
        ),
        headers.present || headers.missing
          ? headers.missing && headers.missing.length
            ? React.createElement(
                "ul",
                { style: { marginTop: 8 } },
                headers.missing.map((h) =>
                  React.createElement("li", { key: h, style: { color: "var(--accent-red)" } }, h)
                )
              )
            : React.createElement("div", { className: "kv" }, "All recommended headers present")
          : React.createElement("div", { className: "kv" }, "Could not fetch headers")
      ),
      // SSL
      React.createElement(
        "div",
        { className: "result-card" },
        React.createElement(
          "div",
          { className: "card-title" },
          React.createElement("h4", null, "SSL / TLS"),
          React.createElement("div", { className: "card-sub" }, "Certificate details")
        ),
        ssl
          ? React.createElement(
              React.Fragment,
              null,
              React.createElement(NullableLine, { label: "Issuer", value: ssl.issuer }),
              React.createElement(NullableLine, { label: "Subject", value: ssl.subject }),
              React.createElement(NullableLine, { label: "Valid From", value: ssl.valid_from }),
              React.createElement(NullableLine, { label: "Valid To", value: ssl.valid_to }),
              React.createElement(NullableLine, { label: "Days Left", value: ssl.days_left })
            )
          : React.createElement("div", { className: "kv" }, "Unable to fetch certificate")
      ),
      // Cookies
      React.createElement(
        "div",
        { className: "result-card" },
        React.createElement(
          "div",
          { className: "card-title" },
          React.createElement("h4", null, "Cookies"),
          React.createElement("div", { className: "card-sub" }, "Secure / HttpOnly flags")
        ),
        cookies.cookies && cookies.cookies.length
          ? React.createElement(
              "ul",
              { style: { marginTop: 8 } },
              cookies.cookies.map((c, i) =>
                React.createElement(
                  "li",
                  { key: i },
                  React.createElement("strong", { style: { color: "var(--white)" } }, c.name),
                  React.createElement("div", { className: "kv" }, c.attrs?.raw || "—"),
                  React.createElement(
                    "div",
                    { style: { marginTop: 6 } },
                    React.createElement(Badge, { type: c.attrs?.secure ? "good" : "bad" }),
                    React.createElement("span", { style: { width: 8, display: "inline-block" } }),
                    React.createElement(Badge, { type: c.attrs?.httponly ? "good" : "bad" })
                  )
                )
              )
            )
          : React.createElement("div", { className: "kv" }, "Could not read cookies")
      ),
      // CMS
      React.createElement(
        "div",
        { className: "result-card" },
        React.createElement(
          "div",
          { className: "card-title" },
          React.createElement("h4", null, "CMS Detection"),
          React.createElement("div", { className: "card-sub" }, "Platform fingerprints")
        ),
        cms.detected && cms.detected.length
          ? React.createElement(
              "ul",
              null,
              cms.detected.map((c, i) => React.createElement("li", { key: i }, c))
            )
          : cms.cms
          ? React.createElement("div", { className: "kv" }, cms.cms)
          : React.createElement("div", { className: "kv" }, "CMS detection failed")
      )
    ),
    // Active Scan
    result.active &&
      React.createElement(
        "div",
        { style: { marginTop: 14 } },
        React.createElement(
          "div",
          { className: "card-title" },
          React.createElement("h4", null, "Active Scan Results"),
          React.createElement("div", { className: "card-sub" }, "nmap / nikto / sqlmap")
        ),
        result.active.nmap && result.active.nmap.hosts
          ? React.createElement(
              "div",
              { className: "result-card" },
              React.createElement("h5", null, "nmap"),
              result.active.nmap.hosts.map((h, idx) =>
                React.createElement(
                  "div",
                  { key: idx, className: "kv", style: { marginBottom: 8 } },
                  React.createElement("strong", null, h.addr),
                  React.createElement(
                    "ul",
                    null,
                    h.ports.map((p, i) =>
                      React.createElement("li", { key: i }, `${p.port}/${p.proto} — ${p.service || "unknown"} ${p.product ? `(${p.product})` : ""}`)
                    )
                  )
                )
              )
            )
          : result.active.nmap
          ? React.createElement("div", { className: "kv" }, `nmap: ${result.active.nmap.error || "no data"}`)
          : null,
        result.active.nikto &&
          React.createElement(
            "div",
            { className: "result-card" },
            React.createElement("h5", null, "Nikto-like"),
            result.active.nikto.raw
              ? React.createElement("pre", { className: "kv", style: { whiteSpace: "pre-wrap" } }, result.active.nikto.raw)
              : React.createElement("div", { className: "kv" }, JSON.stringify(result.active.nikto))
          ),
        result.active.sqlmap &&
          React.createElement(
            "div",
            { className: "result-card" },
            React.createElement("h5", null, "sqlmap"),
            React.createElement("div", { className: "kv" }, `Evidence: ${result.active.sqlmap.evidence ? "Yes" : "No"}`),
            React.createElement("pre", { className: "kv", style: { whiteSpace: "pre-wrap" } }, result.active.sqlmap.raw)
          )
      )
  );
}
