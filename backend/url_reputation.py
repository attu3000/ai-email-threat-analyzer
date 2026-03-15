import os
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit
from urllib.request import urlopen

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None


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

    def _normalize(self, url: str) -> str:
        parsed = urlsplit((url or "").strip())
        if not parsed.scheme or not parsed.netloc:
            return ""

        netloc = parsed.netloc.lower()
        scheme = parsed.scheme.lower()
        path = parsed.path or "/"
        return urlunsplit((scheme, netloc, path, parsed.query, ""))

    def _request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        endpoint = "https://webrisk.googleapis.com/v1/uris:search"

        if httpx:
            with httpx.Client(timeout=self.timeout_s) as client:
                response = client.get(endpoint, params=params)
                response.raise_for_status()
                return response.json()

        # Fallback for environments without httpx installed.
        from urllib.parse import urlencode

        with urlopen(f"{endpoint}?{urlencode(params, doseq=True)}", timeout=self.timeout_s) as resp:  # nosec B310
            import json

            return json.loads(resp.read().decode("utf-8"))

    def lookup(self, url: str) -> Dict[str, Any]:
        normalized_url = self._normalize(url)
        if not normalized_url:
            return {
                "url": url,
                "normalized_url": "",
                "malicious": False,
                "verdict": "invalid_url",
                "confidence": "unknown",
                "categories": [],
                "provider": self.provider_name,
                "error": "Invalid URL format",
            }

        params = {
            "uri": normalized_url,
            "threatTypes": self.THREAT_TYPES,
            "key": self.api_key,
        }
        data = self._request(params)

        threat = data.get("threat") or {}
        threat_types = threat.get("threatTypes") or []
        malicious = bool(threat_types)

        # not_listed is neutral: URI absent from queried threat lists, not verified safe.
        return {
            "url": url,
            "normalized_url": normalized_url,
            "malicious": malicious,
            "verdict": "listed" if malicious else "not_listed",
            "confidence": "high" if malicious else "unknown",
            "categories": threat_types,
            "provider": self.provider_name,
            "error": None,
        }


class URLReputationService:
    def __init__(self, ttl_seconds: int = 600):
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}
        api_key = os.getenv("GOOGLE_WEB_RISK_API_KEY", "").strip()
        self.provider: Optional[URLReputationProvider] = (
            GoogleWebRiskProvider(api_key=api_key) if api_key else None
        )

    def _normalize_cache_key(self, url: str) -> str:
        try:
            parsed = urlsplit((url or "").strip())
        except Exception:
            return ""
        if not parsed.scheme or not parsed.netloc:
            return ""
        netloc = parsed.netloc.lower()
        scheme = parsed.scheme.lower()
        path = parsed.path or "/"
        return urlunsplit((scheme, netloc, path, parsed.query, ""))

    def _read_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        entry = self._cache.get(cache_key)
        if not entry:
            return None
        if time.time() - entry["ts"] > self.ttl_seconds:
            self._cache.pop(cache_key, None)
            return None
        return entry["result"]

    def _write_cache(self, cache_key: str, result: Dict[str, Any]) -> None:
        self._cache[cache_key] = {"ts": time.time(), "result": result}

    def lookup_urls(self, urls: List[str]) -> Dict[str, Any]:
        base_result = {
            "malicious": False,
            "verdict": "not_checked",
            "confidence": "unknown",
            "categories": [],
            "provider": self.provider.provider_name if self.provider else "disabled",
            "matches": [],
            "results": [],
            "errors": [],
        }

        candidate_urls = list(dict.fromkeys((urls or [])[:15]))
        if not candidate_urls:
            return base_result

        if not self.provider:
            base_result["results"] = [
                {
                    "url": url,
                    "normalized_url": self._normalize_cache_key(url),
                    "malicious": False,
                    "verdict": "not_checked",
                    "confidence": "unknown",
                    "categories": [],
                    "provider": "disabled",
                    "error": "provider_disabled",
                }
                for url in candidate_urls
            ]
            return base_result

        malicious_matches: List[Dict[str, Any]] = []
        categories = set()
        per_url_results: List[Dict[str, Any]] = []
        errors: List[str] = []

        for url in candidate_urls:
            cache_key = self._normalize_cache_key(url)
            if cache_key:
                cached = self._read_cache(cache_key)
                if cached is not None:
                    result = {**cached, "url": url}
                else:
                    try:
                        result = self.provider.lookup(url)
                    except Exception as err:
                        result = {
                            "url": url,
                            "normalized_url": cache_key,
                            "malicious": False,
                            "verdict": "provider_error",
                            "confidence": "unknown",
                            "categories": [],
                            "provider": self.provider.provider_name,
                            "error": str(err),
                        }
                        errors.append(f"{url}: {err}")
                    else:
                        self._write_cache(cache_key, result)
            else:
                result = {
                    "url": url,
                    "normalized_url": "",
                    "malicious": False,
                    "verdict": "invalid_url",
                    "confidence": "unknown",
                    "categories": [],
                    "provider": self.provider.provider_name,
                    "error": "Invalid URL format",
                }
                errors.append(f"{url}: invalid_url")

            per_url_results.append(result)
            if result.get("malicious"):
                malicious_matches.append(
                    {
                        "url": url,
                        "categories": result.get("categories", []),
                        "provider": result.get("provider", self.provider.provider_name),
                    }
                )
                categories.update(result.get("categories", []))

        return {
            "malicious": len(malicious_matches) > 0,
            "verdict": "listed" if malicious_matches else "not_listed",
            "confidence": "high" if malicious_matches else "unknown",
            "categories": sorted(categories),
            "provider": self.provider.provider_name,
            "matches": malicious_matches,
            "results": per_url_results,
            "errors": errors,
        }
