(function () {
  const MAX_BODY_CHARS = 7000;
  const MAX_SELECTED_LINES = 22;

  const EMAIL_REGEX = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
  const PHONE_REGEX = /\b(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b/g;
  const DATE_REGEX = /\b(?:\d{1,2}[/-]\d{1,2}(?:[/-]\d{2,4})?|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\s+\d{1,2}(?:,\s*\d{2,4})?)\b/gi;
  const ADDRESS_REGEX = /\b\d{1,6}\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+){0,5}\s+(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|way|suite|ste|apt|apartment)\b/gi;
  const ID_REGEX = /\b(?:order|invoice|account|ticket|reference|ref|id)\s*[:#-]?\s*[A-Z0-9-]{5,}\b/gi;
  const TOKEN_REGEX = /\b[A-Za-z0-9_-]{24,}\b/g;
  const NAME_HEADER_REGEX = /\b(?:hi|hello|dear)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})(?=[,!.?\s]|$)/gi;

  const CTA_REGEX = /\b(click|confirm|verify|review|reset|login|log in|sign in|activate|update|open|visit|continue)\b/i;
  const URGENCY_REGEX = /\b(immediately|urgent|asap|right away|within\s+\d+\s*(?:minutes?|hours?|days?)|today|now|expire|suspension|locked|disabled|final notice)\b/i;
  const ACCOUNT_REGEX = /\b(account|password|credentials|security|verification|confirm email|sign in|log in|mfa|2fa|otp)\b/i;

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
      .replace(NAME_HEADER_REGEX, (full) => full.split(/\s+/)[0] + " [NAME]")
      .replace(TOKEN_REGEX, "[TOKEN]");
  }

  function buildNormalizedSubject(subject) {
    return normalizeSentence(normalizeText(subject));
  }

  function isRelevantLine(line) {
    if (!line) {
      return false;
    }
    return CTA_REGEX.test(line) || URGENCY_REGEX.test(line) || ACCOUNT_REGEX.test(line) || /\[LINK_TO_DOMAIN:/.test(line);
  }

  function selectRelevantLines(lines) {
    const selected = new Set();

    lines.forEach((line, index) => {
      const relevant = isRelevantLine(line);
      if (!relevant) {
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
        sanitized_url: linkInfo.sanitized_url
      });
    }

    return normalized;
  }

  function appendLinkContext(line, links) {
    if (!line) {
      return line;
    }

    let enriched = line;
    for (const link of links) {
      const actualToken = `[LINK_TO_DOMAIN: ${baseDomain(link.actual_domain) || link.actual_domain}]`;
      if (link.visible_domain && baseDomain(link.visible_domain) !== baseDomain(link.actual_domain)) {
        enriched += ` ${`[VISIBLE_DOMAIN: ${baseDomain(link.visible_domain)} | ACTUAL_DOMAIN: ${baseDomain(link.actual_domain)}]`}`;
      } else {
        enriched += ` ${actualToken}`;
      }
    }

    return enriched.trim();
  }

  function buildNormalizedBody(email) {
    const rawBody = (email?.body || "").replace(/\r/g, "");
    const originalBody = normalizeText(rawBody);
    const links = linkReferences(email?.links || []);


    const lines = normalizeSentence(rawBody)
      .split(/\n+/)
      .map((line) => normalizeText(line))
      .filter(Boolean);

    const isLong = originalBody.length > MAX_BODY_CHARS || lines.length > 40;
    const selectedLines = isLong ? selectRelevantLines(lines) : lines;
    const bodyWithLinkContext = selectedLines.map((line, index) => (index === 0 ? appendLinkContext(line, links.slice(0, 3)) : line));

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

    const positiveSignals = [];
    const bodyLower = normalizedBodyData.normalized_body.toLowerCase();

    if (/\b(welcome|create account|confirm email|account confirmation|activate your account)\b/.test(bodyLower)) {
      positiveSignals.push("onboarding_or_account_activation_flow");
    }

    if (!localFeatures.domain_mismatch && senderDomain) {
      positiveSignals.push("sender_domain_matches_link_context");
    }

    const linkDomains = normalizedBodyData.links.map((l) => baseDomain(l.actual_domain)).filter(Boolean);
    const uniqueLinkDomains = Array.from(new Set(linkDomains));
    if (uniqueLinkDomains.length === 1 && uniqueLinkDomains[0]) {
      positiveSignals.push("links_point_to_single_domain");
    }

    return {
      sender_domain: senderDomain,
      normalized_subject: normalizedSubject,
      normalized_body: normalizedBodyData.normalized_body,
      links: normalizedBodyData.links.map((link) => ({
        actual_domain: baseDomain(link.actual_domain) || link.actual_domain,
        visible_domain: link.visible_domain ? baseDomain(link.visible_domain) : null,
        sanitized_url: link.sanitized_url,
        reputation: "unknown"
      })),
      local_features: localFeatures,
      local_risk_score: localRisk.risk_score,
      local_classification: localRisk.classification,
      positive_signals: Array.from(new Set(positiveSignals))
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
