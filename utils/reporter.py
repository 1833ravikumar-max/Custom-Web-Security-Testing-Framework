"""
reporter.py
------------
Generates a professional scan report in JSON and/or HTML format.

Report structure includes:
  - Target URL
  - Scan Date
  - Modules Executed
  - Vulnerabilities Found (with severity, evidence, remediation)
  - Overall Risk Rating
"""

import json
import os
from datetime import datetime

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def _overall_risk_rating(findings):
    if not findings:
        return "Low"
    top = max(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 0))
    return top["severity"]


def build_report_data(target: str, modules_executed: list, findings: list):
    return {
        "target": target,
        "scan_date": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "modules_executed": modules_executed,
        "vulnerabilities_found": findings,
        "total_findings": len(findings),
        "overall_risk_rating": _overall_risk_rating(findings),
    }


def save_json_report(report_data: dict, output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    return output_path


def save_html_report(report_data: dict, output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    severity_colors = {
        "Critical": "#7f1d1d",
        "High": "#b91c1c",
        "Medium": "#b45309",
        "Low": "#0369a1",
        "Info": "#374151",
    }

    rows = ""
    for f in report_data["vulnerabilities_found"]:
        color = severity_colors.get(f["severity"], "#374151")
        rows += f"""
        <tr>
          <td>{f.get('vulnerability_type', 'XSS')}</td>
          <td>{f.get('parameter', '')}</td>
          <td>{f.get('method', '')}</td>
          <td><span class="badge" style="background:{color}">{f['severity']}</span></td>
          <td><code>{_escape(f.get('evidence', ''))}</code></td>
          <td>{f.get('remediation', '')}</td>
        </tr>"""

    if not rows:
        rows = '<tr><td colspan="6" style="text-align:center;color:#6b7280">No vulnerabilities found</td></tr>'

    overall_color = severity_colors.get(report_data["overall_risk_rating"], "#374151")

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Web Security Test Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:#f8fafc; color:#1f2937; margin:0; padding:2rem; }}
  .container {{ max-width: 1000px; margin: 0 auto; background:#fff; border-radius:12px; box-shadow:0 1px 4px rgba(0,0,0,.08); padding:2rem; }}
  h1 {{ margin-top:0; }}
  .meta {{ display:flex; gap:2rem; flex-wrap:wrap; margin-bottom:1.5rem; color:#4b5563; font-size:.95rem; }}
  .meta div strong {{ display:block; color:#111827; font-size:1rem; }}
  table {{ width:100%; border-collapse: collapse; margin-top:1rem; }}
  th, td {{ text-align:left; padding:.6rem .75rem; border-bottom:1px solid #e5e7eb; font-size:.9rem; vertical-align:top; }}
  th {{ background:#f1f5f9; }}
  code {{ background:#f3f4f6; padding:.15rem .4rem; border-radius:4px; font-size:.8rem; word-break:break-all; }}
  .badge {{ color:#fff; padding:.15rem .55rem; border-radius:999px; font-size:.75rem; font-weight:600; }}
  .risk {{ display:inline-block; padding:.3rem .8rem; border-radius:8px; color:#fff; font-weight:700; background:{overall_color}; }}
</style>
</head>
<body>
  <div class="container">
    <h1>Web Security Testing Report</h1>
    <div class="meta">
      <div><strong>{report_data['target']}</strong>Target URL</div>
      <div><strong>{report_data['scan_date']}</strong>Scan Date</div>
      <div><strong>{', '.join(report_data['modules_executed'])}</strong>Modules Executed</div>
      <div><strong>{report_data['total_findings']}</strong>Vulnerabilities Found</div>
      <div><span class="risk">{report_data['overall_risk_rating']}</span><div style="margin-top:.3rem">Overall Risk Rating</div></div>
    </div>
    <table>
      <thead>
        <tr><th>Type</th><th>Parameter</th><th>Method</th><th>Severity</th><th>Evidence</th><th>Remediation</th></tr>
      </thead>
      <tbody>{rows}
      </tbody>
    </table>
  </div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return output_path


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
