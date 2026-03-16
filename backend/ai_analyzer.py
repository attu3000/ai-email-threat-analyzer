import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

SYSTEM_PROMPT = """
You are an email security contextual verification assistant.

You receive:
- local_features/local_risk_score/local_classification from local first-pass detectors.
- normalized_subject and normalized_body (privacy-preserving placeholders, not raw email text).
- link domain and reputation data.

Rules:
1) Treat local risk as prior evidence, not a final answer.
2) Use normalized content for context; do not assume missing details.
3) Account confirmation alone is not phishing evidence.
4) Legitimate onboarding/reset flows can include links and action requests.
5) Multiple links to the same legitimate domain with clean reputation are positive signals.
6) Raise risk materially only with evidence of deception/impersonation, visible-vs-actual mismatch,
   malicious/suspicious links, credential harvesting patterns, or coercive urgency.
7) For weak/mixed evidence, prefer lower scores with cautious reasoning.
8) Never invent raw sender/recipient addresses or hidden content.

Return ONLY valid JSON with:
- classification: one of ["safe", "suspicious", "phishing"]
- risk_score: integer from 0 to 100
- reasons: list of short strings (3-6 items)
- highlighted_phrases: list of short snippets found in normalized_body/normalized_subject
- recommended_action: short user-friendly advice
"""


def _build_user_prompt(payload: dict) -> str:
    prompt_data = {
        "sender_domain": payload.get("sender_domain", ""),
        "normalized_subject": payload.get("normalized_subject", ""),
        "normalized_body": payload.get("normalized_body", "")[:5000],
        "links": payload.get("links", []),
        "local_features": payload.get("local_features", {}),
        "local_risk_score": payload.get("local_risk_score", 0),
        "local_classification": payload.get("local_classification", "safe"),
        "positive_signals": payload.get("positive_signals", []),
        "url_reputation_summary": payload.get("url_reputation_summary", {}),
    }
    return f"Normalized email analysis context: {json.dumps(prompt_data)}"


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
