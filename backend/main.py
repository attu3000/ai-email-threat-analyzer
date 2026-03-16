from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
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


class LinkInput(BaseModel):
    actual_domain: str
    visible_domain: Optional[str] = None
    sanitized_url: Optional[str] = None
    reputation: str = "unknown"
    is_hosted_content_platform: bool = False


class SanitizedEmailInput(BaseModel):
    sender_domain: str = ""
    normalized_subject: str = ""
    normalized_body: str = ""
    links: List[LinkInput] = Field(default_factory=list)
    local_evidence: Dict[str, Any] = Field(default_factory=dict)
    local_risk_score: int = 0
    local_classification: str = "safe"


class AnalysisResult(BaseModel):
    classification: str
    risk_score: int
    reasons: List[str]
    highlighted_phrases: List[str]
    recommended_action: str


def reputation_label(entry: Dict[str, Any]) -> str:
    if entry.get("malicious"):
        return "malicious"
    verdict = entry.get("verdict", "")
    if verdict in {"invalid_url", "provider_error"}:
        return "suspicious"
    if verdict in {"not_listed", "not_checked"}:
        return "clean"
    return "unknown"


@app.get("/")
def root():
    return {"message": "AI Email Threat Analyzer API is running"}


@app.post("/analyze-email", response_model=AnalysisResult)
def analyze_email(payload: SanitizedEmailInput):
    try:
        serialized = payload.model_dump()
        link_urls = [link.get("sanitized_url") for link in serialized.get("links", []) if link.get("sanitized_url")]
        url_reputation = reputation_service.lookup_urls(link_urls[:8])

        rep_map = {
            (entry.get("normalized_url") or ""): reputation_label(entry)
            for entry in url_reputation.get("results", [])
        }

        enriched_links = []
        for link in serialized.get("links", []):
            key = (link.get("sanitized_url") or "")
            enriched_links.append(
                {
                    "actual_domain": link.get("actual_domain", ""),
                    "visible_domain": link.get("visible_domain"),
                    "reputation": rep_map.get(key, "unknown"),
                    "is_hosted_content_platform": bool(link.get("is_hosted_content_platform", False)),
                }
            )

        ai_payload = {
            "sender_domain": serialized.get("sender_domain", ""),
            "normalized_subject": serialized.get("normalized_subject", ""),
            "normalized_body": serialized.get("normalized_body", ""),
            "links": enriched_links,
            "local_evidence": serialized.get("local_evidence", {}),
            "local_risk_score": serialized.get("local_risk_score", 0),
            "local_classification": serialized.get("local_classification", "safe"),
            "url_reputation_summary": {
                "malicious": url_reputation.get("malicious", False),
                "suspicious": url_reputation.get("verdict") in {"invalid_url", "provider_error"},
                "verdict": url_reputation.get("verdict", "unknown"),
            },
        }

        result = analyze_with_ai(ai_payload)
        return AnalysisResult(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")
