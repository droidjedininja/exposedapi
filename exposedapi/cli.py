from __future__ import annotations

import argparse
import os
import sys

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scope-enforced API security triage for authorized testing")
    parser.add_argument("--targets", required=True, help="File containing exact HTTP(S) endpoint URLs")
    parser.add_argument("--scope", required=True, help="File containing authorized hostnames or wildcards")
    parser.add_argument("--header", action="append", default=[], type=parse_header, help="Additional header; repeatable")
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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.acknowledge_authorization:
        parser.error("--acknowledge-authorization is required")
    if args.rate_limit <= 0 or args.rate_limit > 10:
        parser.error("--rate-limit must be greater than 0 and no more than 10")
    if args.timeout <= 0 or args.timeout > 60:
        parser.error("--timeout must be greater than 0 and no more than 60")

    targets = load_lines(args.targets)
    scope = load_lines(args.scope)
    if not targets:
        parser.error("target file is empty")
    if not scope:
        parser.error("scope file is empty")

    try:
        for target in targets:
            validate_target(target, scope)
    except ValueError as exc:
        parser.error(str(exc))

    if args.dry_run:
        print(f"Authorized scope validation passed for {len(targets)} target(s). No requests were sent.")
        return 0

    headers = dict(args.header)
    if args.researcher:
        headers["X-HackerOne-Research"] = args.researcher
    if args.auth_env:
        token = os.environ.get(args.auth_env)
        if not token:
            parser.error(f"environment variable is empty or missing: {args.auth_env}")
        headers["Authorization"] = f"{args.auth_scheme} {token}".strip()

    results = scan_targets(targets, scope, headers, args.timeout, args.rate_limit)
    report = build_report(results, scope)
    if args.format == "html":
        output = args.output if args.output.endswith(".html") else f"{args.output}.html"
        write_html(report, output)
    else:
        output = args.output
        write_json(report, output)
    print(f"Saved {len(results)} endpoint observation(s) to {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

