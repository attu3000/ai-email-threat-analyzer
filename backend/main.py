from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional


app = FastAPI(title="AI Email Threat Analyzer API")

# Allow requests from your Chrome extension during local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EmailInput(BaseModel):
    sender: Optional[str] = ""
    subject: str
    body: str


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
def analyze_email(payload: EmailInput):
    """
    Mock analysis logic for MVP.
    Later, you can replace this with an LLM call.
    """
    text = f"{payload.sender} {payload.subject} {payload.body}".lower()

    suspicious_keywords = [
        "urgent",
        "click here",
        "verify your account",
        "reset your password",
        "suspended",
        "login now",
        "act now",
        "payment failed",
        "confirm your identity",
        "wire transfer",
    ]

    found_phrases = [phrase for phrase in suspicious_keywords if phrase in text]

    risk_score = min(len(found_phrases) * 20, 100)

    if risk_score >= 60:
        classification = "phishing"
    elif risk_score >= 20:
        classification = "suspicious"
    else:
        classification = "safe"

    reasons = []
    if found_phrases:
        reasons.append("Detected suspicious language commonly used in phishing emails.")
    if payload.sender and "@" in payload.sender:
        domain = payload.sender.split("@")[-1]
        if any(char.isdigit() for char in domain):
            reasons.append("Sender domain looks unusual.")
    if not reasons:
        reasons.append("No strong phishing indicators were detected in the provided text.")

    recommended_action = (
        "Do not click links or share credentials until the sender is verified."
        if classification != "safe"
        else "No immediate red flags detected, but continue to verify unexpected requests."
    )

    return AnalysisResult(
        classification=classification,
        risk_score=risk_score,
        reasons=reasons,
        highlighted_phrases=found_phrases,
        recommended_action=recommended_action,
    )