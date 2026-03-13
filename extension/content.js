function getText(el) {
    return el ? el.innerText.trim() : "";
  }
  
  function extractGmailEmail() {
    const subject =
      getText(document.querySelector("h2[data-thread-perm-id]")) ||
      getText(document.querySelector("h2.hP"));
  
    const sender =
      document.querySelector("span[email]")?.getAttribute("email") ||
      document.querySelector("span.gD")?.getAttribute("email") ||
      "";
  
    const body =
      getText(document.querySelector("div.a3s.aiL")) ||
      getText(document.querySelector("div[role='listitem'] .a3s")) ||
      "";
  
    if (!subject && !sender && !body) {
      return {
        ok: false,
        error: "No open Gmail message detected."
      };
    }
  
    return {
      ok: true,
      email: { sender, subject, body }
    };
  }
  
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "EXTRACT_EMAIL") {
      sendResponse(extractGmailEmail());
    }
  });