(function () {
  const CATEGORY_RULES = {
    urgency_language: [
      /\b(urgent|immediately|asap|right away|action required|important notice|final notice|last reminder)\b/i,
      /\b(respond|act|review|update)\s+(today|now)\b/i
    ],
    deadline_pressure: [
      /\b(within|in)\s+\d+\s*(minute|minutes|hour|hours|day|days)\b/i,
      /\bby\s+(end of day|eod|tomorrow|\d{1,2}\/\d{1,2}(?:\/\d{2,4})?)\b/i,
      /\b(deadline|expires?|expiration|time-?sensitive)\b/i
    ],
    threat_of_consequence: [
      /\b(account|access|profile|service)\s+(will|may)\s+(be\s+)?(locked|suspended|disabled|terminated|restricted)\b/i,
      /\b(failure to comply|or else|avoid (?:suspension|termination)|permanent loss)\b/i
    ],
    credential_request: [
      /\b(verify|confirm|validate|re-authenticate)\s+(your\s+)?(account|identity|credentials)\b/i,
      /\b(reset|update)\s+(your\s+)?password\b/i,
      /\b(log\s?in|sign\s?in)\s+(now|here|immediately)?\b/i,
      /\b(mfa|2fa|one-time code|otp|security code)\b/i
    ],
    payment_request: [
      /\b(invoice|payment|billing|overdue|outstanding|past due|wire transfer)\b/i,
      /\b(card|bank|payment method)\s+(expired|failed|declined|needs update)\b/i
    ],
    reward_bait: [
      /\b(prize|reward|gift card|bonus|lottery|winner|claim now)\b/i,
      /\b(free|exclusive)\s+(offer|access|trial)\b/i
    ],
    account_security_action: [
      /\b(unusual|suspicious)\s+(login|activity|attempt)\b/i,
      /\b(security alert|security check|breach detected)\b/i,
      /\b(secure|protect)\s+your\s+account\b/i
    ]
  };

  const GENERIC_GREETING_PATTERNS = [
    /\b(dear (?:customer|user|member|client))\b/i,
    /\b(hello|hi|greetings)\b\s*(customer|user|member)?\b/i,
    /\b(to whom it may concern)\b/i
  ];

  const BRAND_TERMS = [
    "microsoft",
    "google",
    "apple",
    "paypal",
    "amazon",
    "university",
    "it help desk"
  ];

  const SUSPICIOUS_DOMAIN_PATTERNS = [
    /\bsecure-login\b/i,
    /\baccount-?verify\b/i,
    /\bupdate-?security\b/i,
    /\blogin-?confirm\b/i,
    /\bfree-?gift\b/i
  ];

  function normalizeText(value) {
    return (value || "").replace(/\s+/g, " ").trim();
  }

  function extractDomain(emailAddress) {
    const normalized = normalizeText(emailAddress).toLowerCase();
    const parts = normalized.split("@");
    return parts.length === 2 ? parts[1] : "";
  }

  function toHostname(rawUrl) {
    try {
      return new URL(rawUrl).hostname.toLowerCase();
    } catch (_) {
      return "";
    }
  }

  function dedupe(values) {
    return Array.from(new Set(values.filter(Boolean)));
  }

  function collectCategoryMatches(text, patterns, label) {
    const hits = [];
    for (const pattern of patterns) {
      const match = text.match(pattern);
      if (match) {
        hits.push({ category: label, phrase: normalizeText(match[0]) });
      }
    }
    return hits;
  }

  function detectCategoryFlags(subject, body) {
    const subjectFlags = {};
    const bodyFlags = {};
    const highlighted = [];

    for (const [category, patterns] of Object.entries(CATEGORY_RULES)) {
      const subjectHits = collectCategoryMatches(subject, patterns, category);
      const bodyHits = collectCategoryMatches(body, patterns, category);

      subjectFlags[category] = subjectHits.length > 0;
      bodyFlags[category] = bodyHits.length > 0;

      highlighted.push(...subjectHits.map((h) => h.phrase));
      highlighted.push(...bodyHits.map((h) => h.phrase));
    }

    return {
      subject_flags: subjectFlags,
      body_flags: bodyFlags,
      highlighted_phrases: dedupe(highlighted).slice(0, 20)
    };
  }

  function detectGenericGreeting(body) {
    return GENERIC_GREETING_PATTERNS.some((pattern) => pattern.test(body));
  }

  function detectBrandImpersonation(text, senderDomain) {
    const lowered = text.toLowerCase();
    const signals = [];
    for (const term of BRAND_TERMS) {
      if (lowered.includes(term) && senderDomain && !senderDomain.includes(term.replace(/\s+/g, ""))) {
        signals.push(`mentions_${term.replace(/\s+/g, "_")}`);
      }
    }
    return dedupe(signals);
  }

  function getTopLevelDomain(hostname) {
    const parts = hostname.split(".");
    return parts.slice(-2).join(".");
  }

  function detectLinkSignals(links, senderDomain) {
    const suspiciousFlags = [];
    const linkDomains = [];
    let domainMismatch = false;

    for (const link of links || []) {
      const href = normalizeText(link.href);
      const text = normalizeText(link.text);
      if (!href) {
        continue;
      }

      const hostname = toHostname(href);
      if (hostname) {
        linkDomains.push(hostname);
      }

      if (!/^https:\/\//i.test(href)) {
        suspiciousFlags.push("non_https_link");
      }
      if (/https?:\/\/(\d{1,3}\.){3}\d{1,3}/i.test(href)) {
        suspiciousFlags.push("ip_address_link");
      }
      if (hostname.includes("xn--")) {
        suspiciousFlags.push("punycode_link");
      }
      if (SUSPICIOUS_DOMAIN_PATTERNS.some((pattern) => pattern.test(hostname))) {
        suspiciousFlags.push("suspicious_domain_pattern");
      }

      if (senderDomain && hostname) {
        const senderTld = getTopLevelDomain(senderDomain);
        const linkTld = getTopLevelDomain(hostname);
        if (senderTld && linkTld && senderTld !== linkTld) {
          domainMismatch = true;
        }
      }

      if (/^https?:\/\//i.test(text)) {
        const textHost = toHostname(text);
        if (textHost && hostname && textHost !== hostname) {
          suspiciousFlags.push("visible_destination_mismatch");
        }
      }
    }

    return {
      link_domains: dedupe(linkDomains),
      link_count: (links || []).length,
      suspicious_link_flags: dedupe(suspiciousFlags),
      domain_mismatch: domainMismatch
    };
  }

  function buildSanitizedFeatures(email) {
    const sender = normalizeText(email?.sender);
    const subject = normalizeText(email?.subject);
    const body = normalizeText(email?.body);
    const senderDomain = extractDomain(sender);

    const categorySignals = detectCategoryFlags(subject, body);
    const genericGreeting = detectGenericGreeting(body);
    const brandSignals = detectBrandImpersonation(`${subject} ${body}`, senderDomain);
    const linkSignals = detectLinkSignals(email?.links || [], senderDomain);

    return {
      sender_domain: senderDomain,
      subject_flags: categorySignals.subject_flags,
      body_flags: categorySignals.body_flags,
      highlighted_phrases: categorySignals.highlighted_phrases,
      link_domains: linkSignals.link_domains,
      link_count: linkSignals.link_count,
      suspicious_link_flags: linkSignals.suspicious_link_flags,
      generic_greeting: genericGreeting,
      domain_mismatch: linkSignals.domain_mismatch,
      brand_impersonation_signals: brandSignals
    };
  }

  window.FeatureEngine = {
    buildSanitizedFeatures
  };
})();
