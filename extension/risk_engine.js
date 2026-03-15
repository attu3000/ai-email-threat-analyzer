(function () {
  const WEIGHTS = {
    urgency_language: 10,
    deadline_pressure: 12,
    threat_of_consequence: 18,
    credential_request: 22,
    account_security_action: 8,
    payment_request: 14,
    reward_bait: 10,
    contains_links: 4,
    suspicious_link: 18,
    domain_mismatch: 12,
    generic_greeting: 6,
    brand_impersonation: 10
  };

  function hasAnyFlag(flags, key) {
    return Boolean(flags?.subject_flags?.[key] || flags?.body_flags?.[key]);
  }

  function scoreRisk(features) {
    let score = 0;
    const flags = [];

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

    if ((features.suspicious_link_flags || []).length > 0) {
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

    if ((features.brand_impersonation_signals || []).length > 0) {
      score += WEIGHTS.brand_impersonation;
      flags.push("brand_impersonation");
    }

    const riskScore = Math.min(100, score);
    let classification = "safe";
    if (riskScore >= 65) {
      classification = "phishing";
    } else if (riskScore >= 25) {
      classification = "suspicious";
    }

    return {
      risk_score: riskScore,
      classification,
      flags
    };
  }

  window.RiskEngine = {
    scoreRisk
  };
})();
