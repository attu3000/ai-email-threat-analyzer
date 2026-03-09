function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export default function initApp(root) {
  root.innerHTML = `
    <div class="container">
      <h1>AI Email Threat Analyzer</h1>

      <label for="sender">Sender</label>
      <input id="sender" type="text" placeholder="sender@example.com" />

      <label for="subject">Subject</label>
      <input id="subject" type="text" placeholder="Email subject" />

      <label for="body">Email Body</label>
      <textarea id="body" rows="10" placeholder="Paste the email body here"></textarea>

      <button id="analyzeButton" type="button">Analyze</button>
      <div id="error" class="error" hidden></div>
      <div id="result" class="result" hidden></div>
    </div>
  `;

  const senderInput = root.querySelector("#sender");
  const subjectInput = root.querySelector("#subject");
  const bodyInput = root.querySelector("#body");
  const analyzeButton = root.querySelector("#analyzeButton");
  const errorContainer = root.querySelector("#error");
  const resultContainer = root.querySelector("#result");

  function setError(message) {
    if (!message) {
      errorContainer.textContent = "";
      errorContainer.hidden = true;
      return;
    }

    errorContainer.textContent = message;
    errorContainer.hidden = false;
  }

  function setResult(result) {
    if (!result) {
      resultContainer.innerHTML = "";
      resultContainer.hidden = true;
      return;
    }

    const reasons = Array.isArray(result.reasons)
      ? result.reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")
      : "";

    const highlightedPhrases = Array.isArray(result.highlighted_phrases) && result.highlighted_phrases.length > 0
      ? result.highlighted_phrases.map((phrase) => `<li>${escapeHtml(phrase)}</li>`).join("")
      : "<li>None</li>";

    resultContainer.innerHTML = `
      <h2>Analysis Result</h2>
      <p><strong>Classification:</strong> ${escapeHtml(result.classification ?? "Unknown")}</p>
      <p><strong>Risk Score:</strong> ${escapeHtml(result.risk_score ?? "N/A")}</p>
      <div>
        <strong>Reasons:</strong>
        <ul>${reasons}</ul>
      </div>
      <div>
        <strong>Highlighted Phrases:</strong>
        <ul>${highlightedPhrases}</ul>
      </div>
      <p><strong>Recommended Action:</strong> ${escapeHtml(result.recommended_action ?? "N/A")}</p>
    `;
    resultContainer.hidden = false;
  }

  async function handleAnalyze() {
    setError("");
    setResult(null);

    const subject = subjectInput.value.trim();
    const body = bodyInput.value.trim();

    if (!subject || !body) {
      setError("Please enter both subject and body.");
      return;
    }

    analyzeButton.disabled = true;
    analyzeButton.textContent = "Analyzing...";

    try {
      const response = await fetch("http://127.0.0.1:8000/analyze-email", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          sender: senderInput.value.trim(),
          subject,
          body
        })
      });

      if (!response.ok) {
        throw new Error(`Server error: ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (error) {
      console.error(error);
      setError("Could not connect to the backend. Make sure FastAPI is running on port 8000.");
    } finally {
      analyzeButton.disabled = false;
      analyzeButton.textContent = "Analyze";
    }
  }

  analyzeButton.addEventListener("click", handleAnalyze);
}
