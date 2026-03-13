import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

SYSTEM_PROMPT = """
You are a phishing email detection assistant.

Analyze the provided email and return ONLY valid JSON with:
- classification: one of ["safe", "suspicious", "phishing"]
- risk_score: integer from 0 to 100
- reasons: list of short strings
- highlighted_phrases: list of suspicious phrases found in the email
- recommended_action: short user-friendly advice

Focus on:
- urgency or pressure tactics
- requests for passwords, MFA codes, or personal info
- suspicious login/reset/payment language
- impersonation or social engineering
- unusual sender/domain clues
- suspicious financial requests
"""


def analyze_with_ai(sender: str, subject: str, body: str) -> dict:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY is missing")

    client = OpenAI(api_key=api_key)

    user_prompt = f"""
        Sender: {sender}
        Subject: {subject}
        Body:
        {body}
        """

    response = client.chat.completions.create(
        model="gpt-4.1-mini",
        temperature=0,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    )
    print("TOKEN USAGE:", response.usage)

    content = response.choices[0].message.content
    return json.loads(content)
