import React, { useState } from "https://esm.sh/react@18";

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

  return (
    <div className="container">
      <h1>AI Email Threat Analyzer</h1>

      <label htmlFor="sender">Sender</label>
      <input
        id="sender"
        type="text"
        placeholder="sender@example.com"
        value={sender}
        onChange={(e) => setSender(e.target.value)}
      />

      <label htmlFor="subject">Subject</label>
      <input
        id="subject"
        type="text"
        placeholder="Email subject"
        value={subject}
        onChange={(e) => setSubject(e.target.value)}
      />

      <label htmlFor="body">Email Body</label>
      <textarea
        id="body"
        rows="10"
        placeholder="Paste the email body here"
        value={body}
        onChange={(e) => setBody(e.target.value)}
      />

      <button onClick={handleAnalyze} disabled={loading}>
        {loading ? "Analyzing..." : "Analyze"}
      </button>

      {error && <div className="error">{error}</div>}

      {result && (
        <div className="result">
          <h2>Analysis Result</h2>
          <p>
            <strong>Classification:</strong> {result.classification}
          </p>
          <p>
            <strong>Risk Score:</strong> {result.risk_score}
          </p>

          <div>
            <strong>Reasons:</strong>
            <ul>
              {result.reasons.map((reason, index) => (
                <li key={index}>{reason}</li>
              ))}
            </ul>
          </div>

          <div>
            <strong>Highlighted Phrases:</strong>
            <ul>
              {result.highlighted_phrases.length > 0 ? (
                result.highlighted_phrases.map((phrase, index) => (
                  <li key={index}>{phrase}</li>
                ))
              ) : (
                <li>None</li>
              )}
            </ul>
          </div>

          <p>
            <strong>Recommended Action:</strong> {result.recommended_action}
          </p>
        </div>
      )}
    </div>
  );
}