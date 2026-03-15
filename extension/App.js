import React, { useState } from "react";
const createElement = React.createElement;

const DEFAULT_PAYLOAD = {
  sender_domain: "example.edu",
  subject_flags: {},
  body_flags: { urgency_language: true, credential_request: true },
  highlighted_phrases: ["urgent action required", "verify your account"],
  link_domains: ["security-check.example-login.com"],
  link_count: 1,
  suspicious_link_flags: ["suspicious_domain_pattern"],
  generic_greeting: true,
  domain_mismatch: true,
  brand_impersonation_signals: ["mentions_microsoft"],
  flags: ["urgency_language", "credential_request", "suspicious_link"],
  risk_score: 82,
  classification: "phishing"
};

export default function App() {
  const [payloadText, setPayloadText] = useState(JSON.stringify(DEFAULT_PAYLOAD, null, 2));
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  async function handleAnalyze() {
    setError("");
    setResult(null);

    let payload;
    try {
      payload = JSON.parse(payloadText);
    } catch (_) {
      setError("Payload must be valid JSON.");
      return;
    }

    setLoading(true);

    try {
      const response = await fetch("http://127.0.0.1:8000/analyze-email", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.detail || `Server error: ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  }

  return createElement(
    "div",
    { className: "container" },
    createElement("h1", null, "AI Email Threat Analyzer"),
    createElement("p", null, "Debug view: send sanitized phishing features only."),
    createElement("label", { htmlFor: "payload" }, "Sanitized Payload JSON"),
    createElement("textarea", {
      id: "payload",
      rows: "14",
      value: payloadText,
      onChange: (event) => setPayloadText(event.target.value)
    }),
    createElement(
      "button",
      { onClick: handleAnalyze, disabled: loading },
      loading ? "Analyzing..." : "Analyze"
    ),
    error ? createElement("div", { className: "error" }, error) : null,
    result
      ? createElement(
          "div",
          { className: "result" },
          createElement("h2", null, "Analysis Result"),
          createElement("p", null, createElement("strong", null, "Classification:"), " ", result.classification),
          createElement("p", null, createElement("strong", null, "Risk Score:"), " ", result.risk_score),
          createElement(
            "div",
            null,
            createElement("strong", null, "Reasons:"),
            createElement("ul", null, ...result.reasons.map((reason, index) => createElement("li", { key: index }, reason)))
          )
        )
      : null
  );
}
