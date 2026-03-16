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

function getVerdictMeta(classification) {
  const safeClassification = ["safe", "suspicious", "phishing"].includes(classification)
    ? classification
    : "safe";

  const map = {
    safe: {
      label: "Safe",
      subtitle: "No major phishing indicators detected",
      badge: "Low Risk"
    },
    suspicious: {
      label: "Suspicious",
      subtitle: "Signals require verification before interacting",
      badge: "Medium Risk"
    },
    phishing: {
      label: "Phishing",
      subtitle: "High-confidence attack characteristics detected",
      badge: "High Risk"
    }
  };

  return {
    key: safeClassification,
    ...map[safeClassification]
  };
}

function createSection(title, contentNode) {
  const section = document.createElement("section");
  section.className = "result-section";

  const heading = document.createElement("h3");
  heading.className = "section-title";
  heading.textContent = title;

  section.appendChild(heading);
  section.appendChild(contentNode);

  return section;
}

function createList(items, emptyMessage, className) {
  const hasItems = Array.isArray(items) && items.length > 0;

  if (!hasItems) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = emptyMessage;
    return empty;
  }

  const list = document.createElement("ul");
  list.className = className;

  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    list.appendChild(li);
  });

  return list;
}

function createPhraseChips(phrases) {
  if (!Array.isArray(phrases) || !phrases.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No specific phrases were highlighted.";
    return empty;
  }

  const wrapper = document.createElement("div");
  wrapper.className = "chip-list";

  phrases.forEach((phrase) => {
    const chip = document.createElement("span");
    chip.className = "phrase-chip";
    chip.textContent = phrase;
    wrapper.appendChild(chip);
  });

  return wrapper;
}

function renderResult(data) {
  const riskScore = Number.isFinite(Number(data.risk_score))
    ? Math.max(0, Math.min(100, Math.round(Number(data.risk_score))))
    : 0;

  const verdict = getVerdictMeta(String(data.classification || "safe").toLowerCase());

  resultEl.textContent = "";
  resultEl.className = "result-card";

  const verdictCard = document.createElement("section");
  verdictCard.className = `verdict-card verdict-${verdict.key}`;

  const verdictTop = document.createElement("div");
  verdictTop.className = "verdict-top";

  const titleWrap = document.createElement("div");
  titleWrap.className = "verdict-title-wrap";

  const verdictTitle = document.createElement("h2");
  verdictTitle.className = "verdict-title";
  verdictTitle.textContent = verdict.label;

  const verdictSubtitle = document.createElement("p");
  verdictSubtitle.className = "verdict-subtitle";
  verdictSubtitle.textContent = verdict.subtitle;

  const badge = document.createElement("span");
  badge.className = "verdict-badge";
  badge.textContent = verdict.badge;

  titleWrap.append(verdictTitle, verdictSubtitle);
  verdictTop.append(titleWrap, badge);

  const scoreBlock = document.createElement("div");
  scoreBlock.className = "score-block";

  const scoreLabel = document.createElement("p");
  scoreLabel.className = "score-label";
  scoreLabel.textContent = "Risk Score";

  const scoreValue = document.createElement("p");
  scoreValue.className = "score-value";
  scoreValue.innerHTML = `${riskScore}<span>/100</span>`;

  const meter = document.createElement("div");
  meter.className = "risk-meter";
  meter.setAttribute("role", "meter");
  meter.setAttribute("aria-label", "Risk score");
  meter.setAttribute("aria-valuemin", "0");
  meter.setAttribute("aria-valuemax", "100");
  meter.setAttribute("aria-valuenow", String(riskScore));

  const meterFill = document.createElement("div");
  meterFill.className = "risk-meter-fill";
  meterFill.style.width = `${riskScore}%`;

  const meterMarker = document.createElement("span");
  meterMarker.className = "risk-meter-marker";
  meterMarker.style.left = `${riskScore}%`;
  meterMarker.textContent = verdict.badge;

  meter.append(meterFill, meterMarker);
  scoreBlock.append(scoreLabel, scoreValue, meter);

  verdictCard.append(verdictTop, scoreBlock);

  const reasonsSection = createSection(
    "Why this was flagged",
    createList(data.reasons, "No detailed reasons were provided.", "reason-list")
  );

  const phrasesSection = createSection(
    "Highlighted phrases",
    createPhraseChips(data.highlighted_phrases)
  );

  const actionNode = document.createElement("p");
  actionNode.className = "action-text";
  actionNode.textContent =
    data.recommended_action || getRecommendedAction(verdict.key);

  const actionSection = createSection("Recommended action", actionNode);

  resultEl.append(verdictCard, reasonsSection, phrasesSection, actionSection);
}

scanBtn.addEventListener("click", async () => {
  resultEl.textContent = "";
  statusEl.textContent = "Reading current Gmail message...";
  scanBtn.disabled = true;

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab || !tab.id || !tab.url?.includes("mail.google.com")) {
      statusEl.textContent = "Open a Gmail email first.";
      return;
    }

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
  } finally {
    scanBtn.disabled = false;
  }
});
