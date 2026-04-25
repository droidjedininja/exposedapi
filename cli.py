import argparse
import json
from .scanner import scan

def generate_html(results, output_file):
    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>ExposedAPI Report</title>
<style>
body {{ font-family: Arial; background:#0f1724; color:#fff; padding:20px; }}
table {{ width:100%; border-collapse: collapse; }}
th, td {{ padding:10px; border-bottom:1px solid #333; }}
th {{ background:#111; }}
.high {{ color:#ff4d4d; font-weight:bold; }}
.medium {{ color:#ffcc00; font-weight:bold; }}
.low {{ color:#4da6ff; font-weight:bold; }}
</style>
</head>
<body>

<h1>ExposedAPI Report</h1>
<p>Total Findings: {len(results)}</p>

<table>
<tr>
<th>Endpoint</th>
<th>Issue</th>
<th>Severity</th>
</tr>
"""

    for r in results:
        sev = r["severity"].lower()
        html += f"""
<tr>
<td>{r['endpoint']}</td>
<td>{r['issue']}</td>
<td class="{sev}">{r['severity']}</td>
</tr>
"""

    html += """
</table>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)


def main():
    parser = argparse.ArgumentParser(description="ExposedAPI Scanner")
    parser.add_argument("--targets", required=True, help="File with URLs")
    parser.add_argument("--auth", help="Auth header")
    parser.add_argument("--output", default="report.json")
    parser.add_argument("--format", choices=["json", "html"], default="json")

    args = parser.parse_args()

    with open(args.targets) as f:
        urls = [x.strip() for x in f if x.strip()]

    results = []

    for url in urls:
        findings = scan(url, args.auth)
        for issue, severity in findings:
            results.append({
                "endpoint": url,
                "issue": issue,
                "severity": severity,
                "details": ""
            })

    if args.format == "json":
        with open(args.output, "w") as f:
            json.dump({"results": results}, f, indent=2)
        print("JSON report saved:", args.output)

    elif args.format == "html":
        if not args.output.endswith(".html"):
            args.output = "report.html"
        generate_html(results, args.output)
        print("HTML report saved:", args.output)


if __name__ == "__main__":
    main()
