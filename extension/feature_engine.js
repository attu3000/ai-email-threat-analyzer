(function () {
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

  const SUSPICIOUS_TLDS = new Set(["zip", "top", "click", "gq", "work", "country", "kim", "xyz"]);
  const DOMAIN_TOKEN_STOPWORDS = new Set(["mail", "email", "auth", "login", "support", "cdn", "api", "app", "secure"]);

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

  function getBaseDomain(hostname) {
    const parts = (hostname || "").split(".").filter(Boolean);
    if (parts.length <= 2) {
      return parts.join(".");
    }

    const secondLevel = parts[parts.length - 2];
    const countryCode = parts[parts.length - 1];
    const secondLevelTlds = new Set(["co", "com", "org", "net", "gov", "edu"]);
    if (countryCode.length === 2 && secondLevelTlds.has(secondLevel) && parts.length >= 3) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  function getDomainTokens(domain) {
    return (domain || "")
      .replace(/\.[a-z]{2,}$/i, "")
      .split(/[^a-z0-9]+/i)
      .map((token) => token.toLowerCase())
      .filter((token) => token.length >= 4 && !DOMAIN_TOKEN_STOPWORDS.has(token));
  }

  function isCommonServiceSubdomain(hostname) {
    return /\b(auth|login|support|help|cdn|static|assets|status|accounts?)\b/i.test(hostname || "");
  }

  function senderLinkRelationship(senderDomain, linkDomains) {
    if (!senderDomain || !linkDomains.length) {
      return "mismatch";
    }

    const senderBase = getBaseDomain(senderDomain);
    const linkBases = dedupe(linkDomains.map((d) => getBaseDomain(d)).filter(Boolean));

    if (!senderBase || !linkBases.length) {
      return "mismatch";
    }

    if (linkBases.every((base) => base === senderBase)) {
      return "match";
    }

    const senderTokens = getDomainTokens(senderBase);
    const related = linkDomains.some((hostname) => {
      const linkBase = getBaseDomain(hostname);
      const linkTokens = getDomainTokens(linkBase);
      const sharesBrandToken = senderTokens.some((token) => linkTokens.includes(token));
      return sharesBrandToken && (isCommonServiceSubdomain(hostname) || isCommonServiceSubdomain(senderDomain));
    });

    if (related) {
      return "related";
    }

    return "mismatch";
  }

  function hasSuspiciousSenderDomainStructure(senderDomain) {
    if (!senderDomain) {
      return false;
    }

    const hyphenCount = (senderDomain.match(/-/g) || []).length;
    const digitCount = (senderDomain.match(/\d/g) || []).length;
    const labels = senderDomain.split(".").filter(Boolean);
    const longestLabel = labels.reduce((max, part) => Math.max(max, part.length), 0);

    return hyphenCount >= 3 || digitCount >= 5 || longestLabel > 30;
  }

  function isHostedContentDomain(hostname) {
    const base = getBaseDomain(hostname);
    return HOSTED_CONTENT_DOMAINS.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`) || base === domain);
  }

  function detectLinkSignals(links) {
    const linkDomains = [];
    let visibleActualMismatch = false;
    let ipLinkPresent = false;
    let punycodePresent = false;
    let suspiciousTldPresent = false;
    let hostedContentDomainPresent = false;

    for (const link of links || []) {
      const href = normalizeText(link.href);
      const text = normalizeText(link.text);
      if (!href) {
        continue;
      }

      const hostname = toHostname(href);
      if (!hostname) {
        continue;
      }

      linkDomains.push(hostname);

      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
        ipLinkPresent = true;
      }
      if (hostname.includes("xn--")) {
        punycodePresent = true;
      }
      const tld = hostname.split(".").pop() || "";
      if (SUSPICIOUS_TLDS.has(tld)) {
        suspiciousTldPresent = true;
      }
      if (isHostedContentDomain(hostname)) {
        hostedContentDomainPresent = true;
      }

      if (/^https?:\/\//i.test(text)) {
        const textHost = toHostname(text);
        if (textHost && textHost !== hostname) {
          visibleActualMismatch = true;
        }
      }
    }

    const uniqueDomains = dedupe(linkDomains);

    return {
      link_domains: uniqueDomains,
      link_count: (links || []).length,
      links_all_same_domain: uniqueDomains.length <= 1,
      visible_actual_mismatch: visibleActualMismatch,
      hosted_content_domain_present: hostedContentDomainPresent,
      ip_link_present: ipLinkPresent,
      punycode_present: punycodePresent,
      suspicious_tld_present: suspiciousTldPresent
    };
  }

  function buildSanitizedFeatures(email) {
    const sender = normalizeText(email?.sender);
    const senderDomain = extractDomain(sender);

    const linkSignals = detectLinkSignals(email?.links || []);
    const senderLinkMatch = senderLinkRelationship(senderDomain, linkSignals.link_domains);

    return {
      sender_domain: senderDomain,
      link_domains: linkSignals.link_domains,
      link_count: linkSignals.link_count,
      links_all_same_domain: linkSignals.links_all_same_domain,
      sender_link_match: senderLinkMatch,
      visible_actual_mismatch: linkSignals.visible_actual_mismatch,
      hosted_content_domain_present: linkSignals.hosted_content_domain_present,
      ip_link_present: linkSignals.ip_link_present,
      punycode_present: linkSignals.punycode_present,
      suspicious_tld_present: linkSignals.suspicious_tld_present,
      suspicious_sender_domain_structure: hasSuspiciousSenderDomainStructure(senderDomain)
    };
  }

  window.FeatureEngine = {
    buildSanitizedFeatures
  };
})();
