from __future__ import annotations

import argparse
import json
import os
import sys

from .har import import_har, write_inventory
from .compare import compare_hars, write_comparison
from .reporting import build_report, write_html, write_json
from .scanner import load_lines, scan_targets, validate_target


def parse_header(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise argparse.ArgumentTypeError("header must use 'Name: Value' format")
    name, content = value.split(":", 1)
    if not name.strip() or not content.strip():
        raise argparse.ArgumentTypeError("header name and value are required")
    if "\n" in value or "\r" in value:
        raise argparse.ArgumentTypeError("header cannot contain newlines")
    return name.strip(), content.strip()


def parse_header_env(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("environment header must use 'Header-Name=ENV_VAR' format")
    name, env_name = (part.strip() for part in value.split("=", 1))
    if not name or not env_name:
        raise argparse.ArgumentTypeError("header name and environment variable are required")
    if any(character in value for character in "\r\n"):
        raise argparse.ArgumentTypeError("environment header cannot contain newlines")
    return name, env_name


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scope-enforced API security triage for authorized testing")
    parser.add_argument("--targets", required=True, help="File containing exact HTTP(S) endpoint URLs")
    parser.add_argument("--scope", required=True, help="File containing authorized hostnames or wildcards")
    parser.add_argument("--header", action="append", default=[], type=parse_header, help="Non-secret additional header; repeatable")
    parser.add_argument("--header-env", action="append", default=[], type=parse_header_env, help="Secret header as Header-Name=ENV_VAR; repeatable")
    parser.add_argument("--researcher", help="Value for X-HackerOne-Research when the program permits it")
    parser.add_argument("--auth-env", help="Environment variable containing a test-account token")
    parser.add_argument("--auth-scheme", default="Bearer", help="Authorization scheme used with --auth-env")
    parser.add_argument("--rate-limit", type=float, default=1.0, help="Maximum requests per second (default: 1)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds")
    parser.add_argument("--format", choices=["json", "html"], default="json")
    parser.add_argument("--output", "-o", default="output/scan.json")
    parser.add_argument("--dry-run", action="store_true", help="Validate targets and scope without network traffic")
    parser.add_argument("--acknowledge-authorization", action="store_true", help="Confirm that every target is authorized")
    return parser


def build_import_har_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Import and safely inventory an authorized browser HAR")
    parser.add_argument("import-har", help=argparse.SUPPRESS)
    parser.add_argument("--har", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--output", "-o", required=True)
    return parser


def build_compare_har_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safely compare two authorized HAR sessions")
    parser.add_argument("compare-har", help=argparse.SUPPRESS)
    parser.add_argument("--har-a", required=True)
    parser.add_argument("--har-b", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--rate-limit", type=float, default=0.5)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--output", "-o", required=True)
    parser.add_argument("--acknowledge-authorization", action="store_true")
    return parser


def _environment_headers(items: list[tuple[str, str]], parser: argparse.ArgumentParser) -> dict[str, str]:
    headers: dict[str, str] = {}
    for name, env_name in items:
        value = os.environ.get(env_name)
        if not value:
            parser.error(f"environment variable is empty or missing: {env_name}")
        if "\r" in value or "\n" in value:
            parser.error(f"environment variable contains an invalid newline: {env_name}")
        headers[name] = value
    return headers


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "compare-har":
        parser = build_compare_har_parser(); args = parser.parse_args(argv)
        if not args.acknowledge_authorization: parser.error("--acknowledge-authorization is required")
        if args.rate_limit <= 0 or args.rate_limit > 2: parser.error("--rate-limit must be greater than 0 and no more than 2")
        scope = load_lines(args.scope)
        try:
            report = compare_hars(args.har_a, args.har_b, scope, args.timeout, args.rate_limit)
            write_comparison(report, args.output)
        except (OSError, json.JSONDecodeError, ValueError) as exc: parser.error(str(exc))
        print(f"Saved {len(report['results'])} two-session comparison(s) to {args.output}"); return 0
    if argv and argv[0] == "import-har":
        parser = build_import_har_parser(); args = parser.parse_args(argv); scope = load_lines(args.scope)
        if not scope: parser.error("scope file is empty")
        try:
            inventory = import_har(args.har, scope); write_inventory(inventory, args.output)
        except (OSError, json.JSONDecodeError, ValueError) as exc: parser.error(str(exc))
        print(f"Saved {inventory['summary']['unique_safe_endpoints']} redacted, in-scope GET/HEAD endpoint(s) to {args.output}"); return 0
    parser = build_parser(); args = parser.parse_args(argv)
    if not args.acknowledge_authorization: parser.error("--acknowledge-authorization is required")
    if args.rate_limit <= 0 or args.rate_limit > 10: parser.error("--rate-limit must be greater than 0 and no more than 10")
    if args.timeout <= 0 or args.timeout > 60: parser.error("--timeout must be greater than 0 and no more than 60")
    targets, scope = load_lines(args.targets), load_lines(args.scope)
    if not targets: parser.error("target file is empty")
    if not scope: parser.error("scope file is empty")
    try:
        for target in targets: validate_target(target, scope)
    except ValueError as exc: parser.error(str(exc))
    if args.dry_run:
        print(f"Authorized scope validation passed for {len(targets)} target(s). No requests were sent."); return 0
    headers = dict(args.header)
    headers.update(_environment_headers(args.header_env, parser))
    if args.researcher: headers["X-HackerOne-Research"] = args.researcher
    if args.auth_env:
        token = os.environ.get(args.auth_env)
        if not token: parser.error(f"environment variable is empty or missing: {args.auth_env}")
        if "\r" in token or "\n" in token: parser.error(f"environment variable contains an invalid newline: {args.auth_env}")
        headers["Authorization"] = f"{args.auth_scheme} {token}".strip()
    try:
        results = scan_targets(targets, scope, headers, args.timeout, args.rate_limit)
    except ValueError as exc: parser.error(str(exc))
    report = build_report(results, scope)
    if args.format == "html":
        output = args.output if args.output.endswith(".html") else f"{args.output}.html"; write_html(report, output)
    else:
        output = args.output; write_json(report, output)
    print(f"Saved {len(results)} endpoint observation(s) to {output}"); return 0


if __name__ == "__main__":
    sys.exit(main())
