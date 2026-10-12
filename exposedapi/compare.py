from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlsplit, urlunsplit

from .har import STATIC_SUFFIXES
from .scanner import ScanConfig, UrllibClient, validate_target

BLOCKED_PATH_TERMS = ("/callback", "/logout", "/signout", "/token/redirect", "/smart-contracts")


def _load_har(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or not isinstance(document.get("log"), dict):
        raise ValueError("HAR must contain a log object")
    entries = document["log"].get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("HAR log.entries must be a list")
    return entries


def _cookie_for_request(request: dict) -> str | None:
    headers = request.get("headers", [])
    if not isinstance(headers, list):
        return None
    values = []
    for header in headers:
        if not isinstance(header, dict) or str(header.get("name", "")).lower() != "cookie":
            continue
        value = header.get("value")
        if not isinstance(value, str) or not value:
            continue
        if "\r" in value or "\n" in value:
            return None
        values.append(value)
    return "; ".join(values) if values else None


def _safe_targets(entries: list[dict], scope: list[str]) -> list[tuple[str, str, str, str]]:
    targets: dict[tuple[str, str], tuple[str, str, str, str]] = {}
    ambiguous: set[tuple[str, str]] = set()
    for entry in entries:
        request = entry.get("request", {}) if isinstance(entry, dict) else {}
        if not isinstance(request, dict):
            continue
        method = str(request.get("method", "")).upper()
        url = request.get("url")
        cookie = _cookie_for_request(request)
        if method != "GET" or not isinstance(url, str) or not cookie:
            continue
        try:
            validate_target(url, scope, require_https=True, reject_sensitive_query=True)
        except ValueError:
            continue
        parsed = urlsplit(url)
        path = parsed.path or "/"
        lowered = path.lower()
        if lowered.endswith(STATIC_SUFFIXES) or any(term in lowered for term in BLOCKED_PATH_TERMS):
            continue
        display_url = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        key = (method, display_url)
        if key in ambiguous:
            continue
        existing = targets.get(key)
        if existing and existing[3] != cookie:
            targets.pop(key)
            ambiguous.add(key)
            continue
        targets.setdefault(key, (method, url, display_url, cookie))
    return sorted(targets.values(), key=lambda item: (item[0], item[2]))


def _observe(client: UrllibClient, method: str, url: str, cookie: str, timeout: float) -> dict:
    try:
        response = client.get(url, headers={"Accept": "application/json, */*;q=0.8", "Cookie": cookie, "User-Agent": "ExposedAPI/0.5 authorized-security-research"}, timeout=timeout, allow_redirects=False)
        body = response.content or b""
        return {"status": response.status_code, "length": len(body), "sha256": hashlib.sha256(body).hexdigest(), "error": None}
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        return {"status": None, "length": None, "sha256": None, "error": exc.__class__.__name__}


def compare_hars(har_a: str, har_b: str, scope: list[str], timeout: float, rate_limit: float) -> dict:
    ScanConfig(timeout=timeout, rate_limit=rate_limit)
    if rate_limit > 2:
        raise ValueError("compare-har rate limit must be no more than 2")
    entries_a, entries_b = _load_har(har_a), _load_har(har_b)
    targets_a = {
        (method, display_url): (request_url, cookie)
        for method, request_url, display_url, cookie in _safe_targets(entries_a, scope)
    }
    targets_b = {
        (method, display_url): cookie
        for method, _request_url, display_url, cookie in _safe_targets(entries_b, scope)
    }
    matching_targets = sorted(targets_a.keys() & targets_b.keys())
    client = UrllibClient()
    results = []
    delay = 1.0 / rate_limit
    for index, (method, display_url) in enumerate(matching_targets):
        request_url, cookie_a = targets_a[(method, display_url)]
        cookie_b = targets_b[(method, display_url)]
        if index:
            time.sleep(delay)
        a = _observe(client, method, request_url, cookie_a, timeout)
        time.sleep(delay)
        b = _observe(client, method, request_url, cookie_b, timeout)
        same = bool(a["sha256"] and a["sha256"] == b["sha256"] and a["status"] == b["status"])
        if a["status"] is None or b["status"] is None:
            classification = "inconclusive request error"
        elif same and a["status"] == 200:
            classification = "same-response review candidate"
        elif same:
            classification = "same non-200 response"
        else:
            classification = "different-response review candidate"
        results.append({"method": method, "endpoint": display_url, "account_a": a, "account_b": b, "classification": classification})
    return {"tool": "ExposedAPI", "version": "0.5.0", "generated_at": datetime.now(timezone.utc).isoformat(), "methodology": "authorized two-session GET comparison; redirects disabled", "scope": scope, "results": results}


def write_comparison(report: dict, output: str) -> None:
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
