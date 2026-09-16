from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from .scanner import validate_target


STATIC_SUFFIXES = (".css", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".map", ".png", ".svg", ".webp", ".woff", ".woff2")
INTERESTING_TERMS = {"account", "admin", "api-key", "apikey", "auth", "developer", "key", "member", "organization", "payment", "permission", "role", "session", "transaction", "transfer", "user", "wallet"}


def _candidate_score(method: str, path: str, query_names: list[str]) -> tuple[int, list[str]]:
    lowered = path.lower()
    reasons: list[str] = []
    score = 0
    if method in {"GET", "HEAD"}:
        score += 1
        reasons.append("safe read method")
    if "/api/" in lowered or lowered.startswith("/api") or "/v1/" in lowered or "/v2/" in lowered:
        score += 2
        reasons.append("API-like path")
    matched = sorted(term for term in INTERESTING_TERMS if term in lowered)
    if matched:
        score += min(3, len(matched))
        reasons.append("security-relevant resource: " + ", ".join(matched))
    segments = [segment for segment in path.split("/") if segment]
    if any(len(segment) >= 16 for segment in segments):
        score += 2
        reasons.append("possible object identifier")
    if query_names:
        score += 1
        reasons.append("query parameters present")
    return score, reasons


def import_har(har_path: str, scope_patterns: list[str]) -> dict:
    with open(har_path, encoding="utf-8") as handle:
        document = json.load(handle)
    entries = document.get("log", {}).get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("HAR log.entries must be a list")

    inventory: dict[tuple[str, str], dict] = {}
    skipped = {"out_of_scope": 0, "static": 0, "unsafe_method": 0, "invalid": 0}
    for entry in entries:
        request = entry.get("request", {}) if isinstance(entry, dict) else {}
        method = str(request.get("method", "")).upper()
        raw_url = request.get("url")
        if not isinstance(raw_url, str) or not raw_url:
            skipped["invalid"] += 1
            continue
        if method not in {"GET", "HEAD"}:
            skipped["unsafe_method"] += 1
            continue
        try:
            validate_target(raw_url, scope_patterns)
        except ValueError as exc:
            skipped["out_of_scope" if "outside" in str(exc) else "invalid"] += 1
            continue

        parsed = urlsplit(raw_url)
        if parsed.path.lower().endswith(STATIC_SUFFIXES):
            skipped["static"] += 1
            continue
        clean_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
        query_names = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})
        key = (method, clean_url)
        if key not in inventory:
            score, reasons = _candidate_score(method, parsed.path or "/", query_names)
            inventory[key] = {"method": method, "url": clean_url, "query_parameter_names": query_names, "observed_statuses": [], "occurrences": 0, "priority_score": score, "reasons": reasons}
        item = inventory[key]
        item["occurrences"] += 1
        status = entry.get("response", {}).get("status") if isinstance(entry, dict) else None
        if isinstance(status, int) and status not in item["observed_statuses"]:
            item["observed_statuses"].append(status)

    endpoints = sorted(inventory.values(), key=lambda item: (-item["priority_score"], item["url"]))
    return {
        "tool": "ExposedAPI", "version": "0.3.0", "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": Path(har_path).name, "scope": scope_patterns,
        "security": "Request headers, cookies, bodies, response bodies, and query values were not retained.",
        "summary": {"har_entries": len(entries), "unique_safe_endpoints": len(endpoints), "skipped": skipped},
        "endpoints": endpoints,
    }


def write_inventory(inventory: dict, output_path: str) -> None:
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
