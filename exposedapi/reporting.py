from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone

from .scanner import Observation


def build_report(results: list[Observation], scope: list[str] | None) -> dict:
    return {
        "tool": "ExposedAPI",
        "version": "0.5.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "authorized read-only GET triage",
        "scope": scope,
        "results": [item.to_dict() for item in results],
    }


def write_json(report: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")


def write_html(report: dict, path: str) -> None:
    rows = []
    for item in report["results"]:
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(item['endpoint'])}</code></td>"
            f"<td>{html.escape(str(item['status']))}</td>"
            f"<td>{html.escape(item['classification'])}</td>"
            f"<td>{html.escape(item['confidence'])}</td>"
            f"<td>{html.escape(item.get('error') or '')}</td>"
            "</tr>"
        )
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ExposedAPI authorized triage report</title>
<style>body{{font:16px system-ui;margin:2rem;background:#07100f;color:#eef7f3}}table{{width:100%;border-collapse:collapse}}th,td{{padding:.75rem;border-bottom:1px solid #27423a;text-align:left;vertical-align:top}}code{{color:#65f5b3}}small{{color:#9ab0aa}}</style></head>
<body><h1>ExposedAPI authorized triage report</h1><small>{html.escape(report['generated_at'])} · Results are review candidates, not verified vulnerabilities.</small>
<table><thead><tr><th>Endpoint</th><th>Status</th><th>Classification</th><th>Confidence</th><th>Error</th></tr></thead><tbody>{''.join(rows)}</tbody></table></body></html>"""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(document)

