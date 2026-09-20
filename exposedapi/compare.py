from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from .har import STATIC_SUFFIXES
from .scanner import SENSITIVE_QUERY_NAMES, UrllibClient, validate_target

BLOCKED_PATH_TERMS = ("/callback", "/logout", "/signout", "/token/redirect", "/smart-contracts")
SENSITIVE_QUERY_NAMES = {"access_token", "code", "id_token", "state", "statetoken", "token"}


def _load_har(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        entries = json.load(handle).get("log", {}).get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("HAR log.entries must be a list")
    return entries


def _cookies_by_host(entries: list[dict]) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for entry in entries:
        request = entry.get("request", {})
        url = request.get("url", "")
        host = (urlsplit(url).hostname or "").lower()
        for header in request.get("headers", []):
            if str(header.get("name", "")).lower() == "cookie" and header.get("value"):
                cookies[host] = str(header["value"])
    return cookies


def _safe_targets(entries: list[dict], scope: list[str]) -> list[tuple[str, str, str]]:
    targets: dict[tuple[str, str], tuple[str, str, str]] = {}
    for entry in entries:
        request = entry.get("request", {})
        method = str(request.get("method", "")).upper()
        url = request.get("url")
        if method != "GET" or not isinstance(url, str):
            continue
        try:
            validate_target(url, scope, require_https=True)
        except ValueError:
            continue
        parsed = urlsplit(url)
        path = parsed.path or "/"
        lowered = path.lower()
        if lowered.endswith(STATIC_SUFFIXES) or any(term in lowered for term in BLOCKED_PATH_TERMS):
            continue
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if any(name.lower() in SENSITIVE_QUERY_NAMES for name, _ in query):
            continue
        display_url = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        targets[(method, display_url)] = (method, url, display_url)
    return list(targets.values())


def _observe(client: UrllibClient, method: str, url: str, cookie: str, timeout: float) -> dict:
    try:
        response = client.get(url, headers={"Accept": "application/json, */*;q=0.8", "Cookie": cookie, "User-Agent": "ExposedAPI/0.5 authorized-security-research"}, timeout=timeout, allow_redirects=False)
        body = response.content or b""
        return {"status": response.status_code, "length": len(body), "sha256": hashlib.sha256(body).hexdigest(), "error": None}
    except (URLError, TimeoutError, OSError) as exc:
        return {"status": None, "length": None, "sha256": None, "error": exc.__class__.__name__}


def compare_hars(har_a: str, har_b: str, scope: list[str], timeout: float, rate_limit: float) -> dict:
    entries_a, entries_b = _load_har(har_a), _load_har(har_b)
    cookies_a, cookies_b = _cookies_by_host(entries_a), _cookies_by_host(entries_b)
    targets = _safe_targets(entries_a, scope)
    client = UrllibClient()
    results = []
    delay = 1.0 / rate_limit
    for index, (method, request_url, display_url) in enumerate(targets):
        host = (urlsplit(request_url).hostname or "").lower()
        if host not in cookies_a or host not in cookies_b:
            continue
        if index:
            time.sleep(delay)
        a = _observe(client, method, request_url, cookies_a[host], timeout)
        time.sleep(delay)
        b = _observe(client, method, request_url, cookies_b[host], timeout)
        same = bool(a["sha256"] and a["sha256"] == b["sha256"] and a["status"] == b["status"])
        classification = "same-response review candidate" if same and a["status"] == 200 else "different or access-controlled"
        results.append({"method": method, "endpoint": display_url, "account_a": a, "account_b": b, "classification": classification})
    return {"tool": "ExposedAPI", "version": "0.5.0", "generated_at": datetime.now(timezone.utc).isoformat(), "methodology": "authorized two-session GET comparison; redirects disabled", "scope": scope, "results": results}


def write_comparison(report: dict, output: str) -> None:
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
