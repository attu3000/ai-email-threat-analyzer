from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Any, Dict, List
from ai_analyzer import analyze_with_ai
from url_reputation import URLReputationService

app = FastAPI(title="AI Email Threat Analyzer API")
reputation_service = URLReputationService()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SanitizedEmailInput(BaseModel):
    sender_domain: str = ""
    subject_flags: Dict[str, bool] = Field(default_factory=dict)
    body_flags: Dict[str, bool] = Field(default_factory=dict)
    highlighted_phrases: List[str] = Field(default_factory=list)
    link_domains: List[str] = Field(default_factory=list)
    link_urls: List[str] = Field(default_factory=list)
    link_count: int = 0
    suspicious_link_flags: List[str] = Field(default_factory=list)
    generic_greeting: bool = False
    domain_mismatch: bool = False
    brand_impersonation_signals: List[str] = Field(default_factory=list)
    flags: List[str] = Field(default_factory=list)
    strong_signals: List[str] = Field(default_factory=list)
    risk_score: int = 0
    classification: str = "safe"


class AnalysisResult(BaseModel):
    classification: str
    risk_score: int
    reasons: List[str]
    highlighted_phrases: List[str]
    recommended_action: str


def apply_reputation_to_local_result(payload: Dict[str, Any], url_reputation: Dict[str, Any]) -> Dict[str, Any]:
    risk_score = int(payload.get("risk_score", 0))
    classification = payload.get("classification", "safe")
    strong_signals = list(payload.get("strong_signals", []))
    flags = list(payload.get("flags", []))

    if url_reputation.get("malicious"):
        risk_score = min(100, risk_score + 35)
        if "malicious_url_reputation" not in strong_signals:
            strong_signals.append("malicious_url_reputation")
        if "malicious_url_reputation" not in flags:
            flags.append("malicious_url_reputation")

    if strong_signals and risk_score >= 65:
        classification = "phishing"
    elif risk_score >= 30:
        classification = "suspicious"
    else:
        classification = "safe"

    payload["risk_score"] = risk_score
    payload["classification"] = classification
    payload["strong_signals"] = strong_signals
    payload["flags"] = flags
    payload["url_reputation"] = url_reputation
    return payload


def select_urls_for_reputation(payload: Dict[str, Any]) -> List[str]:
    urls = list(dict.fromkeys(payload.get("link_urls", [])[:15]))
    if not urls:
        return []

    suspicious_flags = payload.get("suspicious_link_flags", [])
    # Privacy/API-minimizing strategy: check more URLs only when local link signals already look suspicious.
    if suspicious_flags:
        return urls[:8]
    return urls[:2]


@app.get("/")
def root():
    return {"message": "AI Email Threat Analyzer API is running"}


@app.post("/analyze-email", response_model=AnalysisResult)
def analyze_email(payload: SanitizedEmailInput):
    try:
        serialized = payload.model_dump()
        # Privacy note: only extracted URLs are sent to remote reputation checks, never raw body/subject.
        urls_to_check = select_urls_for_reputation(serialized)
        url_reputation = reputation_service.lookup_urls(urls_to_check)
        enriched = apply_reputation_to_local_result(serialized, url_reputation)

        result = analyze_with_ai(enriched)
        return AnalysisResult(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")
