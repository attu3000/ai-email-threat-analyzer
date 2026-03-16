(function () {
  const MAX_BODY_CHARS = 7000;
  const MAX_SELECTED_LINES = 26;

  const EMAIL_REGEX = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
  const PHONE_REGEX = /\b(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b/g;
  const DATE_REGEX = /\b(?:\d{1,2}[/-]\d{1,2}(?:[/-]\d{2,4})?|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\s+\d{1,2}(?:,\s*\d{2,4})?)\b/gi;
  const ADDRESS_REGEX = /\b\d{1,6}\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+){0,5}\s+(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|way|suite|ste|apt|apartment)\b/gi;
  const ID_REGEX = /\b(?:order|invoice|account|ticket|reference|ref|id)\s*[:#-]?\s*[A-Z0-9-]{5,}\b/gi;
  const TOKEN_REGEX = /\b[A-Za-z0-9_-]{24,}\b/g;
  const NAME_HEADER_REGEX = /\b(?:hi|hello|dear)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})(?=[,!.?\s]|$)/gi;

  const CTA_REGEX = /\b(click|confirm|verify|review|reset|login|log in|sign in|activate|update|open|visit|continue|download|view)\b/i;
  const DEADLINE_REGEX = /\b(within\s+\d+\s*(?:minutes?|hours?|days?)|by\s+\[DATE\]|by\s+end of day|expires?|expiration|deadline|final notice)\b/i;
  const ALL_CAPS_REGEX = /\b[A-Z]{4,}\b/;

  const HOSTED_CONTENT_DOMAINS = [
    "sites.google.com",
    "storage.googleapis.com",
    "drive.google.com",
    "docs.google.com",
    "github.io",
    "notion.site",
    "webflow.io",
    "pages.dev",
    "netlify.app",
    "vercel.app",
    "firebaseapp.com",
    "onrender.com",
    "azurewebsites.net",
    "herokuapp.com"
  ];

  function normalizeText(value) {
    return (value || "").replace(/\s+/g, " ").trim();
  }

  function extractDomainFromEmail(value) {
    const match = normalizeText(value).toLowerCase().match(/@([a-z0-9.-]+\.[a-z]{2,})/);
    return match ? match[1] : "";
  }

  function baseDomain(hostname) {
    const host = hostname || "";
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
      return host;
    }
    const parts = host.split(".").filter(Boolean);
    if (parts.length <= 2) {
      return parts.join(".");
    }
    return parts.slice(-2).join(".");
  }

  function parseUrl(url) {
    try {
      const parsed = new URL(url);
      return {
        protocol: parsed.protocol.toLowerCase(),
        hostname: parsed.hostname.toLowerCase(),
        pathname: parsed.pathname || "/"
      };
    } catch (_) {
      return null;
    }
  }

  function isHostedContentDomain(hostname) {
    const base = baseDomain(hostname);
    return HOSTED_CONTENT_DOMAINS.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`) || base === domain);
  }

  function normalizeLink(url) {
    const parsed = parseUrl(url);
    if (!parsed || !parsed.hostname) {
      return { sanitized_url: "", actual_domain: "" };
    }

    return {
      sanitized_url: `${parsed.protocol}//${parsed.hostname}${parsed.pathname}`,
      actual_domain: parsed.hostname
    };
  }

  function visibleDomain(text) {
    const parsed = parseUrl(text || "");
    return parsed ? parsed.hostname : "";
  }

  function normalizeTimeWindow(text) {
    return text
      .replace(/\bwithin\s+(\d+\s*(?:minutes?|hours?|days?))\b/gi, "[TIME_WINDOW: $1]")
      .replace(/\bin\s+(\d+\s*(?:minutes?|hours?|days?))\b/gi, "[TIME_WINDOW: $1]")
      .replace(/\b(immediately|right away|asap|now)\b/gi, "[TIME_WINDOW: immediate]");
  }

  function normalizeSentence(text) {
    return normalizeTimeWindow(text)
      .replace(EMAIL_REGEX, "[EMAIL]")
      .replace(PHONE_REGEX, "[PHONE]")
      .replace(ADDRESS_REGEX, "[ADDRESS]")
      .replace(ID_REGEX, "[ID]")
      .replace(DATE_REGEX, "[DATE]")
      .replace(NAME_HEADER_REGEX, (full) => `${full.split(/\s+/)[0]} [NAME]`)
      .replace(TOKEN_REGEX, "[TOKEN]");
  }

  function buildNormalizedSubject(subject) {
    return normalizeSentence(normalizeText(subject));
  }

  function isRelevantLine(line) {
    if (!line) {
      return false;
    }
    return CTA_REGEX.test(line) || DEADLINE_REGEX.test(line) || ALL_CAPS_REGEX.test(line) || /\[LINK_TO_DOMAIN:/.test(line);
  }

  function selectRelevantLines(lines) {
    const selected = new Set();

    lines.forEach((line, index) => {
      if (!isRelevantLine(line)) {
        return;
      }

      selected.add(index);
      if (index > 0) {
        selected.add(index - 1);
      }
      if (index < lines.length - 1) {
        selected.add(index + 1);
      }
    });

    return Array.from(selected)
      .sort((a, b) => a - b)
      .slice(0, MAX_SELECTED_LINES)
      .map((idx) => lines[idx]);
  }

  function linkReferences(links) {
    const normalized = [];

    for (const link of links || []) {
      const href = normalizeText(link?.href);
      if (!href) {
        continue;
      }

      const linkInfo = normalizeLink(href);
      if (!linkInfo.actual_domain) {
        continue;
      }

      const visible = visibleDomain(normalizeText(link?.text));
      normalized.push({
        actual_domain: linkInfo.actual_domain,
        visible_domain: visible || null,
        sanitized_url: linkInfo.sanitized_url,
        is_hosted_content_platform: isHostedContentDomain(linkInfo.actual_domain)
      });
    }

    return normalized;
  }

  function appendLinkContext(line, links) {
    if (!line || !links.length) {
      return line;
    }

    const tokens = links.slice(0, 3).map((link) => {
      if (link.visible_domain && baseDomain(link.visible_domain) !== baseDomain(link.actual_domain)) {
        return `[VISIBLE_DOMAIN: ${baseDomain(link.visible_domain)} | ACTUAL_DOMAIN: ${baseDomain(link.actual_domain)}]`;
      }
      return `[LINK_TO_DOMAIN: ${baseDomain(link.actual_domain) || link.actual_domain}]`;
    });

    return `${line} ${tokens.join(" ")}`.trim();
  }

  function buildNormalizedBody(email) {
    const rawBody = (email?.body || "").replace(/\r/g, "");
    const originalBody = normalizeText(rawBody);
    const links = linkReferences(email?.links || []);

    const normalizedLines = normalizeSentence(rawBody)
      .split(/\n+/)
      .map((line) => normalizeText(line))
      .filter(Boolean);

    const isLong = originalBody.length > MAX_BODY_CHARS || normalizedLines.length > 40;
    const selectedLines = isLong ? selectRelevantLines(normalizedLines) : normalizedLines;
    const bodyWithLinkContext = selectedLines.map((line, index) => (index === 0 ? appendLinkContext(line, links) : line));

    return {
      normalized_body: bodyWithLinkContext.join("\n").slice(0, 5000),
      links,
      body_was_truncated: isLong
    };
  }

  function buildAiContext(email, localFeatures, localRisk) {
    const senderDomain = extractDomainFromEmail(email?.sender);
    const normalizedSubject = buildNormalizedSubject(email?.subject);
    const normalizedBodyData = buildNormalizedBody(email);

    return {
      sender_domain: senderDomain,
      normalized_subject: normalizedSubject,
      normalized_body: normalizedBodyData.normalized_body,
      links: normalizedBodyData.links.map((link) => ({
        actual_domain: baseDomain(link.actual_domain) || link.actual_domain,
        visible_domain: link.visible_domain ? baseDomain(link.visible_domain) : null,
        sanitized_url: link.sanitized_url,
        reputation: "unknown",
        is_hosted_content_platform: link.is_hosted_content_platform
      })),
      local_evidence: {
        sender_link_match: localFeatures.sender_link_match,
        visible_actual_mismatch: localFeatures.visible_actual_mismatch,
        links_all_same_domain: localFeatures.links_all_same_domain,
        hosted_content_domain_present: localFeatures.hosted_content_domain_present,
        ip_link_present: localFeatures.ip_link_present,
        punycode_present: localFeatures.punycode_present,
        suspicious_sender_domain_structure: localFeatures.suspicious_sender_domain_structure
      },
      local_risk_score: localRisk.risk_score,
      local_classification: localRisk.classification
    };
  }

  window.EmailNormalizer = {
    buildAiContext,
    buildNormalizedBody,
    buildNormalizedSubject,
    normalizeLink,
    normalizeSentence
  };
})();
