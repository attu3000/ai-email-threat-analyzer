from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from ai_analyzer import analyze_with_ai

app = FastAPI(title="AI Email Threat Analyzer API")

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
    try:
        result = analyze_with_ai(
            sender=payload.sender or "",
            subject=payload.subject,
            body=payload.body,
        )
        return AnalysisResult(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")