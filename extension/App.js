import React, { useState } from "https://esm.sh/react@18";

const createElement = React.createElement;

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
        body: JSON.stringify({
          sender,
          subject,
          body
        })
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

  return createElement(
    "div",
    { className: "container" },
    createElement("h1", null, "AI Email Threat Analyzer"),

    createElement("label", { htmlFor: "sender" }, "Sender"),
    createElement("input", {
      id: "sender",
      type: "text",
      placeholder: "sender@example.com",
      value: sender,
      onChange: (event) => setSender(event.target.value)
    }),

    createElement("label", { htmlFor: "subject" }, "Subject"),
    createElement("input", {
      id: "subject",
      type: "text",
      placeholder: "Email subject",
      value: subject,
      onChange: (event) => setSubject(event.target.value)
    }),

    createElement("label", { htmlFor: "body" }, "Email Body"),
    createElement("textarea", {
      id: "body",
      rows: "10",
      placeholder: "Paste the email body here",
      value: body,
      onChange: (event) => setBody(event.target.value)
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
          createElement(
            "p",
            null,
            createElement("strong", null, "Classification:"),
            " ",
            result.classification
          ),
          createElement(
            "p",
            null,
            createElement("strong", null, "Risk Score:"),
            " ",
            result.risk_score
          ),
          createElement(
            "div",
            null,
            createElement("strong", null, "Reasons:"),
            createElement(
              "ul",
              null,
              ...result.reasons.map((reason, index) => createElement("li", { key: index }, reason))
            )
          ),
          createElement(
            "div",
            null,
            createElement("strong", null, "Highlighted Phrases:"),
            createElement(
              "ul",
              null,
              ...(result.highlighted_phrases.length > 0
                ? result.highlighted_phrases.map((phrase, index) =>
                    createElement("li", { key: index }, phrase)
                  )
                : [createElement("li", { key: "none" }, "None")])
            )
          ),
          createElement(
            "p",
            null,
            createElement("strong", null, "Recommended Action:"),
            " ",
            result.recommended_action
          )
        )
      : null
  );
}
