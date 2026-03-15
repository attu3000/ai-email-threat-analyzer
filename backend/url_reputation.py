import os
import time
from typing import Any, Dict, List, Optional

import httpx


class URLReputationProvider:
    provider_name = "none"

    def lookup(self, url: str) -> Dict[str, Any]:
        raise NotImplementedError


class GoogleWebRiskProvider(URLReputationProvider):
    provider_name = "google_web_risk"
    THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]

    def __init__(self, api_key: str, timeout_s: float = 2.5):
        self.api_key = api_key
        self.timeout_s = timeout_s

    def lookup(self, url: str) -> Dict[str, Any]:
        endpoint = "https://webrisk.googleapis.com/v1/uris:search"
        params = {
            "uri": url,
            "threatTypes": self.THREAT_TYPES,
            "key": self.api_key,
        }

        with httpx.Client(timeout=self.timeout_s) as client:
            response = client.get(endpoint, params=params)
            response.raise_for_status()
            data = response.json()

        threat = data.get("threat") or {}
        threat_type = threat.get("threatTypes", [None])[0]
        malicious = bool(threat_type)
        categories = [threat_type] if threat_type else []

        return {
            "malicious": malicious,
            "verdict": "listed" if malicious else "not_listed",
            "confidence": "high" if malicious else "low",
            "categories": categories,
            "provider": self.provider_name,
        }


class URLReputationService:
    def __init__(self, ttl_seconds: int = 600):
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}
        api_key = os.getenv("GOOGLE_WEB_RISK_API_KEY", "").strip()
        self.provider: Optional[URLReputationProvider] = (
            GoogleWebRiskProvider(api_key=api_key) if api_key else None
        )

    def _read_cache(self, url: str) -> Optional[Dict[str, Any]]:
        entry = self._cache.get(url)
        if not entry:
            return None
        if time.time() - entry["ts"] > self.ttl_seconds:
            self._cache.pop(url, None)
            return None
        return entry["result"]

    def _write_cache(self, url: str, result: Dict[str, Any]) -> None:
        self._cache[url] = {"ts": time.time(), "result": result}

    def lookup_urls(self, urls: List[str]) -> Dict[str, Any]:
        normalized_urls = list(dict.fromkeys((urls or [])[:15]))
        base_result = {
            "malicious": False,
            "verdict": "not_checked",
            "confidence": "unknown",
            "categories": [],
            "provider": self.provider.provider_name if self.provider else "disabled",
            "matches": [],
            "error": None,
        }

        if not normalized_urls:
            return base_result

        if not self.provider:
            return base_result

        malicious_matches = []
        categories = set()

        for url in normalized_urls:
            cached = self._read_cache(url)
            if cached is not None:
                result = cached
            else:
                try:
                    result = self.provider.lookup(url)
                except Exception as err:
                    # Never block full email analysis when URL reputation fails.
                    return {
                        **base_result,
                        "provider": self.provider.provider_name,
                        "error": str(err),
                        "verdict": "provider_error",
                    }
                self._write_cache(url, result)

            if result.get("malicious"):
                malicious_matches.append({
                    "url": url,
                    "categories": result.get("categories", []),
                    "provider": result.get("provider", self.provider.provider_name),
                })
                categories.update(result.get("categories", []))

        return {
            "malicious": len(malicious_matches) > 0,
            "verdict": "listed" if malicious_matches else "not_listed",
            "confidence": "high" if malicious_matches else "low",
            "categories": sorted(categories),
            "provider": self.provider.provider_name,
            "matches": malicious_matches,
            "error": None,
        }
