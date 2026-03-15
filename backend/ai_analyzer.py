import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

SYSTEM_PROMPT = """
You are an email security explanation assistant.

You are given sanitized phishing-detection features generated locally by a browser extension.
Do not infer access to raw email body, raw subject, sender mailbox, or full URLs.
Use the provided local risk score, strong signals, and flags as primary evidence.
If URL reputation indicates malicious/social-engineering URLs, treat that as strong phishing evidence.
If URL reputation is not listed or unavailable, do not treat URLs as automatically safe.

Return ONLY valid JSON with:
- classification: one of ["safe", "suspicious", "phishing"]
- risk_score: integer from 0 to 100
- reasons: list of short strings (3-6 items)
- highlighted_phrases: list of suspicious phrases from provided sanitized phrases only
- recommended_action: short user-friendly advice

Keep output stable and concise.
"""


def _build_user_prompt(sanitized_features: dict) -> str:
    prompt_data = {
        "sender_domain": sanitized_features.get("sender_domain", ""),
        "subject_flags": sanitized_features.get("subject_flags", {}),
        "body_flags": sanitized_features.get("body_flags", {}),
        "highlighted_phrases": sanitized_features.get("highlighted_phrases", [])[:12],
        "link_domains": sanitized_features.get("link_domains", [])[:10],
        "link_count": sanitized_features.get("link_count", 0),
        "suspicious_link_flags": sanitized_features.get("suspicious_link_flags", []),
        "generic_greeting": sanitized_features.get("generic_greeting", False),
        "domain_mismatch": sanitized_features.get("domain_mismatch", False),
        "brand_impersonation_signals": sanitized_features.get("brand_impersonation_signals", []),
        "flags": sanitized_features.get("flags", []),
        "strong_signals": sanitized_features.get("strong_signals", []),
        "url_reputation": sanitized_features.get("url_reputation", {}),
        "local_risk_score": sanitized_features.get("risk_score", 0),
        "local_classification": sanitized_features.get("classification", "safe"),
    }
    return f"Sanitized analysis context: {json.dumps(prompt_data)}"


def analyze_with_ai(sanitized_features: dict) -> dict:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY is missing")

    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model="gpt-4.1-mini",
        temperature=0.1,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(sanitized_features)},
        ],
    )

    content = response.choices[0].message.content
    parsed = json.loads(content)

    parsed["risk_score"] = max(0, min(100, int(parsed.get("risk_score", 0))))
    parsed["classification"] = parsed.get("classification", "safe")
    parsed["reasons"] = parsed.get("reasons", [])
    parsed["highlighted_phrases"] = parsed.get("highlighted_phrases", [])
    parsed["recommended_action"] = parsed.get("recommended_action", "Use caution and verify through trusted channels.")

    return parsed
