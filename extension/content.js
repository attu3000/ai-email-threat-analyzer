function getText(el) {
  return el ? el.innerText.trim() : "";
}

function isElementVisible(el) {
  if (!el) {
    return false;
  }

  const style = window.getComputedStyle(el);
  if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity) === 0) {
    return false;
  }

  const rect = el.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
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

function getActiveMessageBodyElement() {
  const bodyCandidates = Array.from(document.querySelectorAll("div.a3s"))
    .filter((el) => isElementVisible(el) && getText(el));

  if (!bodyCandidates.length) {
    return null;
  }

  // In Gmail threads, the latest expanded/active message body typically appears last.
  return bodyCandidates[bodyCandidates.length - 1];
}

function getMessageContainerFromBody(messageBodyEl) {
  if (!messageBodyEl) {
    return null;
  }

  return (
    messageBodyEl.closest("div.adn") ||
    messageBodyEl.closest("div[data-message-id]") ||
    messageBodyEl.closest("div[role='listitem']") ||
    messageBodyEl.parentElement
  );
}

function extractSenderFromMessageContainer(messageContainerEl) {
  if (!messageContainerEl) {
    return "";
  }

  return (
    messageContainerEl.querySelector("span.gD[email]")?.getAttribute("email") ||
    messageContainerEl.querySelector("span[email]")?.getAttribute("email") ||
    ""
  );
}

function extractGmailEmail() {
  // Gmail selectors can change; we use fallback selectors to preserve compatibility.
  const subject =
    getText(document.querySelector("h2[data-thread-perm-id]")) ||
    getText(document.querySelector("h2.hP"));

  const messageBodyEl = getActiveMessageBodyElement();
  const messageContainerEl = getMessageContainerFromBody(messageBodyEl);
  const sender = extractSenderFromMessageContainer(messageContainerEl);

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
