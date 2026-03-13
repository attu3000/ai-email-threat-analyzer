const scanBtn = document.getElementById("scanBtn");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");

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

    statusEl.textContent = "Analyzing...";
    const apiRes = await fetch("http://localhost:8000/analyze-email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(response.email)
    });

    const data = await apiRes.json();

    statusEl.textContent = "Done.";
    resultEl.textContent =
      `Classification: ${data.classification}\n` +
      `Risk Score: ${data.risk_score}\n\n` +
      `Reasons:\n- ${data.reasons.join("\n- ")}\n\n` +
      `Highlighted Phrases:\n- ${data.highlighted_phrases.join("\n- ")}\n\n` +
      `Recommended Action:\n${data.recommended_action}`;
  } catch (err) {
    statusEl.textContent = `Error: ${err.message}`;
  }
});