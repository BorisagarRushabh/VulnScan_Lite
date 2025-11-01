// ScanForm.js
import React, { useState } from "react";

function ScanForm({ onStart, disabled }) {
  const [url, setUrl] = useState("");

  const normalize = (u) => {
    let v = u.trim();
    if (!v) return "";
    if (!v.startsWith("http://") && !v.startsWith("https://")) v = "https://" + v;
    return v;
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    const n = normalize(url);
    if (!n) return;
    onStart(n);
  };

  return React.createElement(
    "form",
    { onSubmit: handleSubmit },
    React.createElement(
      "div",
      { style: { marginBottom: 10 } },
      React.createElement(
        "label",
        { style: { color: "var(--muted)", fontSize: 13 } },
        "Target URL"
      ),
      React.createElement(
        "div",
        { className: "form-row", style: { marginTop: 8 } },
        React.createElement("input", {
          className: "input",
          value: url,
          onChange: (e) => setUrl(e.target.value),
          placeholder: "example.com or https://example.com",
          required: true,
          disabled: disabled,
        }),
        React.createElement(
          "button",
          { className: "btn", type: "submit", disabled: disabled },
          "SCAN"
        )
      )
    ),
    React.createElement(
      "div",
      { style: { display: "flex", gap: 8, alignItems: "center", marginTop: 6 } },
      React.createElement("div", { className: "switch" }, "Mode: Passive"),
      React.createElement(
        "div",
        { style: { marginLeft: "auto", color: "var(--muted)", fontSize: 13 } },
        "Free — 1 daily scan"
      )
    )
  );
}

export default ScanForm;
