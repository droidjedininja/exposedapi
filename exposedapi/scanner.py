from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass
from fnmatch import fnmatch
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


RESEARCH_ORIGIN = "https://security-research.invalid"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    content: bytes
    headers: object


class UrllibClient:
    def __init__(self) -> None:
        self.opener = build_opener(_NoRedirect)

    def get(self, url: str, headers: dict[str, str], timeout: float, allow_redirects: bool = False) -> HttpResponse:
        if allow_redirects:
            raise ValueError("ExposedAPI does not follow redirects")
        request = Request(url, headers=headers, method="GET")
        try:
            with self.opener.open(request, timeout=timeout) as response:
                return HttpResponse(response.status, response.read(), response.headers)
        except HTTPError as response:
            return HttpResponse(response.code, response.read(), response.headers)


@dataclass(frozen=True)
class Observation:
    endpoint: str
    status: int | None
    content_type: str | None
    content_length: int | None
    body_sha256: str | None
    location: str | None
    cors_origin: str | None
    cors_credentials: str | None
    classification: str
    confidence: str
    notes: list[str]
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def load_lines(path: str) -> list[str]:
    with open(path, encoding="utf-8") as handle:
        return [
            line.strip()
            for line in handle
            if line.strip() and not line.lstrip().startswith("#")
        ]


def host_in_scope(hostname: str, scope_patterns: Iterable[str]) -> bool:
    host = hostname.rstrip(".").lower()
    for raw_pattern in scope_patterns:
        pattern = raw_pattern.strip().rstrip(".").lower()
        if not pattern:
            continue
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if host.endswith(suffix) and host != suffix.lstrip("."):
                return True
        elif fnmatch(host, pattern):
            return True
    return False


def validate_target(url: str, scope_patterns: Iterable[str]) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("only http and https targets are supported")
    if not parsed.hostname:
        raise ValueError("target has no hostname")
    if parsed.username or parsed.password:
        raise ValueError("credentials must not be embedded in target URLs")
    if not host_in_scope(parsed.hostname, scope_patterns):
        raise ValueError(f"host is outside the supplied scope: {parsed.hostname}")
    return parsed.hostname.lower()


def _fingerprint(response: HttpResponse) -> tuple[int, str]:
    body = response.content or b""
    return len(body), hashlib.sha256(body).hexdigest()


def scan_endpoint(
    url: str,
    scope_patterns: Iterable[str],
    headers: dict[str, str],
    timeout: float,
    session: object | None = None,
) -> Observation:
    validate_target(url, scope_patterns)
    client = session or UrllibClient()
    request_headers = {
        "Accept": "application/json, */*;q=0.8",
        "Origin": RESEARCH_ORIGIN,
        "User-Agent": "ExposedAPI/0.2 authorized-security-research",
        **headers,
    }

    try:
        response = client.get(
            url,
            headers=request_headers,
            timeout=timeout,
            allow_redirects=False,
        )
        body_length, body_hash = _fingerprint(response)
        allowed_origin = response.headers.get("Access-Control-Allow-Origin")
        credentials = response.headers.get("Access-Control-Allow-Credentials")
        notes: list[str] = []
        classification = "endpoint observation"
        confidence = "informational"

        if allowed_origin == RESEARCH_ORIGIN:
            classification = "CORS origin-reflection review candidate"
            confidence = "medium" if credentials and credentials.lower() == "true" else "low"
            notes.append("The supplied untrusted Origin was reflected in the response.")
            if credentials and credentials.lower() == "true":
                notes.append("Credentials were allowed; browser and cookie behavior still require manual verification.")
        elif allowed_origin == "*":
            classification = "wildcard CORS review candidate"
            confidence = "low"
            notes.append("Wildcard CORS alone does not demonstrate exposure of authenticated data.")

        if 300 <= response.status_code < 400:
            notes.append("Redirect was recorded but not followed, preventing an accidental out-of-scope request.")

        return Observation(
            endpoint=url,
            status=response.status_code,
            content_type=response.headers.get("Content-Type"),
            content_length=body_length,
            body_sha256=body_hash,
            location=response.headers.get("Location"),
            cors_origin=allowed_origin,
            cors_credentials=credentials,
            classification=classification,
            confidence=confidence,
            notes=notes,
        )
    except (URLError, TimeoutError, OSError) as exc:
        return Observation(
            endpoint=url,
            status=None,
            content_type=None,
            content_length=None,
            body_sha256=None,
            location=None,
            cors_origin=None,
            cors_credentials=None,
            classification="request error",
            confidence="informational",
            notes=[],
            error=f"{exc.__class__.__name__}: {exc}",
        )


def scan_targets(
    targets: Iterable[str],
    scope_patterns: Iterable[str],
    headers: dict[str, str],
    timeout: float,
    rate_limit: float,
) -> list[Observation]:
    target_list = list(targets)
    scope_list = list(scope_patterns)
    for target in target_list:
        validate_target(target, scope_list)

    delay = 1.0 / rate_limit
    results: list[Observation] = []
    session = UrllibClient()
    for index, target in enumerate(target_list):
        if index:
            time.sleep(delay)
        results.append(scan_endpoint(target, scope_list, headers, timeout, session))
    return results
