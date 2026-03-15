(function () {
  const WEIGHTS = {
    urgency_language: 6,
    deadline_pressure: 6,
    threat_of_consequence: 16,
    credential_request: 18,
    account_security_action: 6,
    payment_request: 12,
    reward_bait: 8,
    contains_links: 1,
    suspicious_link: 16,
    domain_mismatch: 4,
    generic_greeting: 4,
    brand_impersonation: 12,
    malicious_url_reputation: 35,
    text_destination_mismatch: 22,
    punycode_or_ip_link: 24,
    suspicious_link_structure: 14,
    strong_brand_impersonation: 22
  };

  const STRONG_LINK_FLAGS = new Set([
    "visible_destination_mismatch",
    "punycode_link",
    "ip_address_link",
    "suspicious_domain_pattern",
    "credential_lure_hostname_link",
    "suspicious_tld_link",
    "excessive_hyphens_link",
    "long_hostname_link"
  ]);

  function hasAnyFlag(flags, key) {
    return Boolean(flags?.subject_flags?.[key] || flags?.body_flags?.[key]);
  }

  function scoreRisk(features) {
    let score = 0;
    const flags = [];
    const strongSignals = [];

    const categoryKeys = [
      "urgency_language",
      "deadline_pressure",
      "threat_of_consequence",
      "credential_request",
      "account_security_action",
      "payment_request",
      "reward_bait"
    ];

    for (const key of categoryKeys) {
      if (hasAnyFlag(features, key)) {
        score += WEIGHTS[key];
        flags.push(key);
      }
    }

    if ((features.link_count || 0) > 0) {
      score += WEIGHTS.contains_links;
      flags.push("contains_links");
    }

    const suspiciousFlags = features.suspicious_link_flags || [];

    if (suspiciousFlags.length > 0) {
      score += WEIGHTS.suspicious_link;
      flags.push("suspicious_link");
    }

    if (features.domain_mismatch) {
      score += WEIGHTS.domain_mismatch;
      flags.push("domain_mismatch");
    }

    if (features.generic_greeting) {
      score += WEIGHTS.generic_greeting;
      flags.push("generic_greeting");
    }

    const brandSignals = features.brand_impersonation_signals || [];
    if (brandSignals.length > 0) {
      score += WEIGHTS.brand_impersonation;
      flags.push("brand_impersonation");
      if (features.domain_mismatch) {
        score += WEIGHTS.strong_brand_impersonation;
        strongSignals.push("strong_brand_impersonation");
      }
    }

    if (suspiciousFlags.includes("visible_destination_mismatch")) {
      score += WEIGHTS.text_destination_mismatch;
      strongSignals.push("text_destination_mismatch");
    }

    if (suspiciousFlags.includes("punycode_link") || suspiciousFlags.includes("ip_address_link")) {
      score += WEIGHTS.punycode_or_ip_link;
      strongSignals.push("punycode_or_ip_link");
    }

    if (suspiciousFlags.some((flag) => STRONG_LINK_FLAGS.has(flag))) {
      score += WEIGHTS.suspicious_link_structure;
      strongSignals.push("suspicious_link_structure");
    }

    if (features.url_reputation?.malicious) {
      score += WEIGHTS.malicious_url_reputation;
      strongSignals.push("malicious_url_reputation");
      flags.push("malicious_url_reputation");
    }

    const riskScore = Math.min(100, score);
    let classification = "safe";

    // Domain mismatch or soft pressure language alone should not trigger phishing.
    if (strongSignals.length > 0 && riskScore >= 65) {
      classification = "phishing";
    } else if (riskScore >= 30) {
      classification = "suspicious";
    }

    return {
      risk_score: riskScore,
      classification,
      flags,
      strong_signals: Array.from(new Set(strongSignals))
    };
  }

  window.RiskEngine = {
    scoreRisk
  };
})();
