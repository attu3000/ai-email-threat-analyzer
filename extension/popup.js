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

function renderResult(data) {
  resultEl.textContent =
    `Classification: ${data.classification}\n` +
    `Risk Score: ${data.risk_score}\n\n` +
    `Reasons:\n- ${data.reasons.join("\n- ")}\n\n` +
    `Highlighted Phrases:\n- ${(data.highlighted_phrases || []).join("\n- ")}\n\n` +
    `Recommended Action:\n${data.recommended_action}`;
}

scanBtn.addEventListener("click", async () => {
  resultEl.textContent = "";
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
