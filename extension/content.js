function getText(el) {
  return el ? el.innerText.trim() : "";
}

function extractLinksFromMessage(messageBodyEl) {
  if (!messageBodyEl) {
    return [];
  }

  return Array.from(messageBodyEl.querySelectorAll("a[href]"))
    .map((anchor) => ({
      href: anchor.getAttribute("href") || "",
      text: (anchor.innerText || anchor.textContent || "").trim()
    }))
    .filter((link) => link.href);
}

function extractGmailEmail() {
  // Gmail selectors can change; we use fallback selectors to preserve compatibility.
  const subject =
    getText(document.querySelector("h2[data-thread-perm-id]")) ||
    getText(document.querySelector("h2.hP"));

  const sender =
    document.querySelector("span[email]")?.getAttribute("email") ||
    document.querySelector("span.gD")?.getAttribute("email") ||
    "";

  const messageBodyEl =
    document.querySelector("div.a3s.aiL") ||
    document.querySelector("div[role='listitem'] .a3s");

  const body = getText(messageBodyEl);
  const links = extractLinksFromMessage(messageBodyEl);

  if (!subject && !sender && !body) {
    return {
      ok: false,
      error: "No open Gmail message detected."
    };
  }

  return {
    ok: true,
    email: { sender, subject, body, links }
  };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "EXTRACT_EMAIL") {
    sendResponse(extractGmailEmail());
  }
});
