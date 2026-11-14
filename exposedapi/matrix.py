"""Explicit expected-access checks for authorized test-account resources."""
from __future__ import annotations

import os
import re
from urllib.parse import unquote, urlsplit, urlunsplit

from .compare import BLOCKED_PATH_TERMS
from .scanner import ScanConfig, UrllibClient, _RateLimiter, scan_endpoint, validate_target


def prepare_matrix(document: dict, scope: list[str] | None) -> tuple[dict[str, dict[str, str]], list[dict]]:
    if not isinstance(document, dict):
        raise ValueError("matrix must be an object")
    accounts = document.get("accounts")
    resources = document.get("resources")
    if not isinstance(accounts, dict) or not accounts or "anonymous" in accounts:
        raise ValueError("accounts must be a nonempty object; anonymous is reserved")
    if not isinstance(resources, list) or not resources:
        raise ValueError("resources must be a nonempty list")
    sessions = {}
    for name, config in accounts.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
            raise ValueError("account names must use 1-64 letters, digits, underscores or hyphens")
        mapping = config.get("headers_env") if isinstance(config, dict) else None
        if not isinstance(mapping, dict) or not mapping:
            raise ValueError(f"account {name} requires headers_env")
        headers = {}
        for header, variable in mapping.items():
            if not isinstance(header, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", header):
                raise ValueError("invalid header name")
            if header.lower() not in {"authorization", "cookie", "x-api-key", "api-key"}:
                raise ValueError("account headers must be Authorization, Cookie, X-API-Key or API-Key")
            if header.lower() in {key.lower() for key in headers}:
                raise ValueError("duplicate account header")
            if not isinstance(variable, str) or not variable:
                raise ValueError("header environment variable name is required")
            value = os.environ.get(variable)
            if not value or any(char in value for char in "\r\n"):
                raise ValueError(f"account {name} has a missing, empty or invalid credential environment variable")
            headers[header] = value
        sessions[name] = headers
    sessions["anonymous"] = {}
    checked = []
    for resource in resources:
        if not isinstance(resource, dict) or not isinstance(resource.get("url"), str):
            raise ValueError("each resource requires a URL")
        url = resource["url"]
        validate_target(url, scope, require_https=True, reject_sensitive_query=True)
        path = unquote(urlsplit(url).path).lower()
        if any(term in path for term in BLOCKED_PATH_TERMS):
            raise ValueError("matrix resource contains a blocked replay path")
        allowed = resource.get("allowed_accounts")
        if (not isinstance(allowed, list) or not allowed or
                any(not isinstance(name, str) or name not in sessions for name in allowed) or
                len(set(allowed)) != len(allowed)):
            raise ValueError("each resource requires a nonempty allowed_accounts list of unique known accounts")
        checked.append({"url": url, "allowed_accounts": allowed})
    return sessions, checked


def run_matrix(document: dict, scope: list[str] | None, timeout: float = 10, rate_limit: float = 0.5) -> dict:
    config = ScanConfig(timeout=timeout, rate_limit=rate_limit)
    if rate_limit > 2:
        raise ValueError("account-matrix rate limit must be no more than 2")
    sessions, resources = prepare_matrix(document, scope)
    limiter = _RateLimiter(config.rate_limit)
    client = UrllibClient()
    results = []
    for resource_index, resource in enumerate(resources):
        observations = {}
        for name, headers in sessions.items():
            limiter.wait()
            observation = scan_endpoint(resource["url"], scope, headers, config.timeout, client)
            observations[name] = observation
        baseline = next((observations[name] for name in resource["allowed_accounts"]
                         if observations[name].status is not None and 200 <= observations[name].status < 300), None)
        parsed = urlsplit(resource["url"])
        endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        for name, observation in observations.items():
            expected = name in resource["allowed_accounts"]
            status = observation.status
            success = status is not None and 200 <= status < 300
            same = bool(baseline and success and observation.body_sha256 == baseline.body_sha256)
            if status is None:
                classification = "inconclusive request error"
            elif expected:
                classification = "expected access observed" if success else "expected access not observed"
            elif status in {401, 403, 404}:
                classification = "expected denial observed"
            elif success and baseline:
                classification = "unexpected access review candidate"
            else:
                classification = "inconclusive access result"
            results.append({"resource_index": resource_index, "endpoint": endpoint,
                            "account": name, "expected_access": expected, "status": status,
                            "length": observation.content_length, "sha256": observation.body_sha256,
                            "matches_allowed_baseline": same, "classification": classification})
    return {"tool": "ExposedAPI", "methodology": "explicit account access matrix; GET only; redirects disabled",
            "notes": ["Successful HTTP responses do not prove access to protected data. Review response semantics manually.",
                      "A matching allowed baseline is supporting evidence, not proof of an authorization vulnerability."],
            "scope": scope, "results": results}
