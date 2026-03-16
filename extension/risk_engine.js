(function () {
  const WEIGHTS = {
    link_present: 2,
    sender_link_mismatch: 24,
    sender_link_related: 8,
    visible_actual_mismatch: 24,
    malicious_url_reputation: 40,
    suspicious_url_reputation: 18,
    ip_link_present: 24,
    punycode_present: 22,
    suspicious_tld_present: 12,
    suspicious_sender_domain_structure: 10,
    hosted_content_domain_present: 4,
    links_all_same_domain_match_bonus: -6,
    links_all_same_domain_related_bonus: -2
  };

  function scoreRisk(features) {
    let score = 0;
    const flags = [];
    const strongSignals = [];

    if ((features.link_count || 0) > 0) {
      score += WEIGHTS.link_present;
      flags.push("link_present");
    }

    if (features.sender_link_match === "mismatch") {
      score += WEIGHTS.sender_link_mismatch;
      flags.push("sender_link_mismatch");
      strongSignals.push("sender_link_mismatch");
    } else if (features.sender_link_match === "related") {
      score += WEIGHTS.sender_link_related;
      flags.push("sender_link_related");
    }

    if (features.visible_actual_mismatch) {
      score += WEIGHTS.visible_actual_mismatch;
      flags.push("visible_actual_mismatch");
      strongSignals.push("visible_actual_mismatch");
    }

    if (features.ip_link_present) {
      score += WEIGHTS.ip_link_present;
      flags.push("ip_link_present");
      strongSignals.push("ip_link_present");
    }

    if (features.punycode_present) {
      score += WEIGHTS.punycode_present;
      flags.push("punycode_present");
      strongSignals.push("punycode_present");
    }

    if (features.suspicious_tld_present) {
      score += WEIGHTS.suspicious_tld_present;
      flags.push("suspicious_tld_present");
    }

    if (features.suspicious_sender_domain_structure) {
      score += WEIGHTS.suspicious_sender_domain_structure;
      flags.push("suspicious_sender_domain_structure");
    }

    if (features.hosted_content_domain_present) {
      score += WEIGHTS.hosted_content_domain_present;
      flags.push("hosted_content_domain_present");
    }

    const malicious = Boolean(features.url_reputation?.malicious);
    const suspicious = Boolean(features.url_reputation?.suspicious);

    if (malicious) {
      score += WEIGHTS.malicious_url_reputation;
      flags.push("malicious_url_reputation");
      strongSignals.push("malicious_url_reputation");
    } else if (suspicious) {
      score += WEIGHTS.suspicious_url_reputation;
      flags.push("suspicious_url_reputation");
    }

    if (features.links_all_same_domain && (features.sender_link_match === "match" || features.sender_link_match === "related")) {
      score +=
        features.sender_link_match === "match"
          ? WEIGHTS.links_all_same_domain_match_bonus
          : WEIGHTS.links_all_same_domain_related_bonus;
      flags.push("links_all_same_domain");
    }

    const riskScore = Math.max(0, Math.min(100, score));
    let classification = "safe";

    if (strongSignals.length >= 2 || riskScore >= 65) {
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
