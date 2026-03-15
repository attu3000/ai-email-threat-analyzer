# ai-email-threat-analyzer

AI-powered Chrome extension and FastAPI backend for phishing and social engineering risk analysis.

## Privacy-first architecture

### Previous behavior
- The extension extracted raw sender/subject/body content from Gmail.
- Raw email content was posted to the backend.
- The backend sent raw content to OpenAI for detection and explanation.

### New behavior (privacy-preserving)
- Detection happens locally in the extension using pattern-based feature extraction and deterministic scoring.
- Raw sender address, raw subject text, raw body text, and full raw URLs stay local in the browser.
- The extension sends only sanitized signals to the backend (e.g., sender domain, category flags, link/domain metadata, local risk score, and highlighted pattern snippets).
- OpenAI is used only to generate a polished explanation from sanitized features, not as the primary detector.

### URL reputation integration
- Backend includes a provider abstraction for URL reputation checks in `backend/url_reputation.py`.
- Current provider: Google Web Risk (optional, configured with `GOOGLE_WEB_RISK_API_KEY`).
- Reputation responses are normalized into a shared structure:
  - `malicious` (boolean)
  - `verdict` / `confidence`
  - `categories` / threat types
  - `provider`
- Reputation checks use timeout + in-memory TTL caching to reduce repeated API calls.
- If reputation lookup fails or is not configured, analysis continues without blocking.
- Only extracted URLs are checked remotely; raw subject/body content is never sent.

### Why this is better for startups and universities
- Reduces privacy risk and data governance concerns by keeping sensitive content local.
- Supports compliance reviews more easily by minimizing transferred data.
- Keeps phishing detection behavior deterministic and explainable via local signal categories.
- Allows centralized explanation quality without exposing raw inbox contents.

## Configuration
Set backend environment variables:

- `OPENAI_API_KEY` (required for explanation generation)
- `GOOGLE_WEB_RISK_API_KEY` (optional for URL maliciousness checks)
