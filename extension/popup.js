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

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function titleCase(value) {
  return String(value || "unknown").replace(/\b\w/g, (char) => char.toUpperCase());
}

function getRiskTone(score) {
  if (score >= 80) {
    return "high";
  }
  if (score >= 50) {
    return "medium";
  }
  return "low";
}

function renderBulletList(items, emptyMessage) {
  const listItems = (items || []).length
    ? items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")
    : `<li class=\"muted\">${emptyMessage}</li>`;

  return `<ul>${listItems}</ul>`;
}

function renderResult(data) {
  const score = Number(data.risk_score) || 0;
  const tone = getRiskTone(score);

  resultEl.classList.remove("low", "medium", "high");
  resultEl.classList.add(tone);

  resultEl.innerHTML = `
    <section class="result-summary">
      <div class="pill pill-${tone}">${escapeHtml(titleCase(data.classification))}</div>
      <div class="score-wrap">
        <span class="score-label">Risk Score</span>
        <span class="score-value">${score}</span>
      </div>
    </section>

    <section class="result-section">
      <h2>Why this rating</h2>
      ${renderBulletList(data.reasons, "No reasons provided by analyzer.")}
    </section>

    <section class="result-section">
      <h2>Highlighted phrases</h2>
      ${renderBulletList(data.highlighted_phrases, "No risky phrases highlighted.")}
    </section>

    <section class="result-section">
      <h2>Recommended action</h2>
      <p>${escapeHtml(data.recommended_action)}</p>
    </section>
  `;
}

scanBtn.addEventListener("click", async () => {
  resultEl.innerHTML = "";
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
