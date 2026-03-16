const scanBtn = document.getElementById("scanBtn");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");

function getRecommendedAction(classification) {
  if (classification === "phishing") {
    return "Do not click links or share credentials. Report this email to IT/security immediately.";
  }
  if (classification === "suspicious") {
    return "Verify the sender through a trusted channel before taking any action.";
  }
  return "No major phishing signals detected. Continue normal caution practices.";
}

function buildFallbackResult(localRisk) {
  const reasons = localRisk.flags.length
    ? localRisk.flags.map((flag) => flag.replace(/_/g, " "))
    : ["No high-confidence phishing patterns detected"];

  return {
    classification: localRisk.classification,
    risk_score: localRisk.risk_score,
    reasons,
    highlighted_phrases: [],
    recommended_action: getRecommendedAction(localRisk.classification)
  };
}

function clampRiskScore(score) {
  const numericScore = Number(score);
  if (!Number.isFinite(numericScore)) {
    return 0;
  }
  return Math.max(0, Math.min(100, Math.round(numericScore)));
}

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatClassification(classification = "") {
  if (!classification) {
    return "Unknown";
  }

  return classification
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function renderList(items = [], emptyLabel) {
  if (!Array.isArray(items) || !items.length) {
    return `<li class="empty-item">${escapeHtml(emptyLabel)}</li>`;
  }

  return items.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
}

function renderResult(data) {
  const classification = data?.classification || "unknown";
  const riskScore = clampRiskScore(data?.risk_score);
  const reasons = Array.isArray(data?.reasons) ? data.reasons : [];
  const highlightedPhrases = Array.isArray(data?.highlighted_phrases) ? data.highlighted_phrases : [];
  const recommendedAction = data?.recommended_action || getRecommendedAction(classification);

  resultEl.className = `result-card severity-${classification}`;
  resultEl.innerHTML = `
    <section class="verdict-card">
      <div class="verdict-heading">Threat Verdict</div>
      <div class="verdict-row">
        <span class="classification-pill">${escapeHtml(formatClassification(classification))}</span>
        <span class="risk-value">Risk ${riskScore}/100</span>
      </div>
      <div class="risk-meter-wrap" aria-label="Risk score ${riskScore} out of 100">
        <div class="risk-meter-track">
          <div class="risk-meter-fill" style="width: ${riskScore}%"></div>
        </div>
        <div class="risk-meter-labels"><span>Low</span><span>Moderate</span><span>High</span></div>
      </div>
    </section>

    <section class="info-section">
      <h2>Reasons</h2>
      <ul>${renderList(reasons, "No specific reasons were returned.")}</ul>
    </section>

    <section class="info-section phrases-section">
      <h2>Highlighted Phrases</h2>
      <ul>${renderList(highlightedPhrases, "No risky phrases detected.")}</ul>
    </section>

    <section class="info-section action-section">
      <h2>Recommended Action</h2>
      <p>${escapeHtml(recommendedAction)}</p>
    </section>
  `;
}

scanBtn.addEventListener("click", async () => {
  resultEl.textContent = "";
  resultEl.className = "";
  statusEl.textContent = "Reading current Gmail message...";

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab || !tab.id || !tab.url?.includes("mail.google.com")) {
    statusEl.textContent = "Open a Gmail email first.";
    return;
  }

  try {
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ["content.js"]
    });

    const response = await chrome.tabs.sendMessage(tab.id, { type: "EXTRACT_EMAIL" });

    if (!response?.ok) {
      statusEl.textContent = response?.error || "Could not read email.";
      return;
    }

    statusEl.textContent = "Analyzing locally...";
    const features = window.FeatureEngine.buildSanitizedFeatures(response.email);
    const localRisk = window.RiskEngine.scoreRisk(features);

    const aiPayload = window.EmailNormalizer.buildAiContext(response.email, features, localRisk);

    statusEl.textContent = "Fetching AI explanation...";
    let data;

    try {
      const apiRes = await fetch("http://localhost:8000/analyze-email", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(aiPayload)
      });

      if (!apiRes.ok) {
        throw new Error(`Backend returned ${apiRes.status}`);
      }

      data = await apiRes.json();
    } catch (_) {
      data = buildFallbackResult(localRisk);
      statusEl.textContent = "Backend unavailable. Showing local analysis.";
      renderResult(data);
      return;
    }

    statusEl.textContent = "Done.";
    renderResult(data);
  } catch (err) {
    statusEl.textContent = `Error: ${err.message}`;
  }
});
