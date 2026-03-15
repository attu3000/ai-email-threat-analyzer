from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List
from ai_analyzer import analyze_with_ai

app = FastAPI(title="AI Email Threat Analyzer API")

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
    link_count: int = 0
    suspicious_link_flags: List[str] = Field(default_factory=list)
    generic_greeting: bool = False
    domain_mismatch: bool = False
    brand_impersonation_signals: List[str] = Field(default_factory=list)
    flags: List[str] = Field(default_factory=list)
    risk_score: int = 0
    classification: str = "safe"


class AnalysisResult(BaseModel):
    classification: str
    risk_score: int
    reasons: List[str]
    highlighted_phrases: List[str]
    recommended_action: str


@app.get("/")
def root():
    return {"message": "AI Email Threat Analyzer API is running"}


@app.post("/analyze-email", response_model=AnalysisResult)
def analyze_email(payload: SanitizedEmailInput):
    try:
        result = analyze_with_ai(payload.model_dump())
        return AnalysisResult(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")
