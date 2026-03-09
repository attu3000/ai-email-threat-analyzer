import React, { useState } from "https://esm.sh/react@18";

const e = React.createElement;

export default function App() {
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  async function handleAnalyze() {
    setError("");
    setResult(null);

    if (!subject.trim() || !body.trim()) {
      setError("Please enter both subject and body.");
      return;
    }

    setLoading(true);

    try {
      const response = await fetch("http://127.0.0.1:8000/analyze-email", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ sender, subject, body })
      });

      if (!response.ok) {
        throw new Error(`Server error: ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      console.error(err);
      setError("Could not connect to the backend. Make sure FastAPI is running on port 8000.");
    } finally {
      setLoading(false);
    }
  }

  const reasonsList = result
    ? result.reasons.map((reason, index) => e("li", { key: index }, reason))
    : null;

  const highlightedList = result
    ? result.highlighted_phrases.length > 0
      ? result.highlighted_phrases.map((phrase, index) => e("li", { key: index }, phrase))
      : [e("li", { key: "none" }, "None")]
    : null;

  return e(
    "div",
    { className: "container" },
    e("h1", null, "AI Email Threat Analyzer"),

    e("label", { htmlFor: "sender" }, "Sender"),
    e("input", {
      id: "sender",
      type: "text",
      placeholder: "sender@example.com",
      value: sender,
      onChange: (event) => setSender(event.target.value)
    }),

    e("label", { htmlFor: "subject" }, "Subject"),
    e("input", {
      id: "subject",
      type: "text",
      placeholder: "Email subject",
      value: subject,
      onChange: (event) => setSubject(event.target.value)
    }),

    e("label", { htmlFor: "body" }, "Email Body"),
    e("textarea", {
      id: "body",
      rows: "10",
      placeholder: "Paste the email body here",
      value: body,
      onChange: (event) => setBody(event.target.value)
    }),

    e(
      "button",
      { onClick: handleAnalyze, disabled: loading },
      loading ? "Analyzing..." : "Analyze"
    ),

    error ? e("div", { className: "error" }, error) : null,

    result
      ? e(
          "div",
          { className: "result" },
          e("h2", null, "Analysis Result"),
          e("p", null, e("strong", null, "Classification:"), " ", result.classification),
          e("p", null, e("strong", null, "Risk Score:"), " ", result.risk_score),
          e("div", null, e("strong", null, "Reasons:"), e("ul", null, reasonsList)),
          e(
            "div",
            null,
            e("strong", null, "Highlighted Phrases:"),
            e("ul", null, highlightedList)
          ),
          e("p", null, e("strong", null, "Recommended Action:"), " ", result.recommended_action)
        )
      : null
  );
}
