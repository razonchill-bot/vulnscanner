"""
Renders a scan into a self-contained HTML report - works standalone
(open in any browser) and doubles as the template the web UI reuses.
"""
from __future__ import annotations
import html
from datetime import datetime, timezone
from core.plugin_base import Severity
from risk.scoring import RiskSummary

SEVERITY_COLORS = {
    Severity.CRITICAL: "#7f1d1d",
    Severity.HIGH: "#b91c1c",
    Severity.MEDIUM: "#b45309",
    Severity.LOW: "#1d4ed8",
    Severity.INFO: "#4b5563",
}

RATING_COLORS = {
    "CRITICAL": "#7f1d1d", "HIGH": "#b91c1c", "MEDIUM": "#b45309",
    "LOW": "#1d4ed8", "INFO": "#4b5563",
}


def render_html_report(scan_report, risk_summary: RiskSummary, owasp_map: dict) -> str:
    target = scan_report.target
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    findings_html = "\n".join(_render_finding(f) for f in risk_summary.all_findings)
    if not findings_html:
        findings_html = "<p class='muted'>No findings - either the target is well-hardened, " \
                         "or checks were blocked (e.g. by a WAF). Review the module errors below.</p>"

    errors_html = "\n".join(
        f"<li><strong>{html.escape(name)}</strong>: {html.escape(result.error)}</li>"
        for name, result in scan_report.module_results.items() if result.error
    )
    errors_section = f"<h2>Module Errors</h2><ul>{errors_html}</ul>" if errors_html else ""

    owasp_html = "\n".join(_render_owasp_row(cat, data) for cat, data in owasp_map.items())

    counts = risk_summary.counts
    rating_color = RATING_COLORS.get(risk_summary.overall_rating, "#4b5563")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vulnerability Scan Report - {html.escape(target.host)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background: #0b0f19; color: #e5e7eb; margin: 0; padding: 40px; }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ font-size: 28px; margin-bottom: 4px; }}
  .subtitle {{ color: #9ca3af; margin-bottom: 32px; }}
  .rating-badge {{ display: inline-block; padding: 6px 16px; border-radius: 6px; font-weight: 700;
                   background: {rating_color}; color: white; font-size: 14px; letter-spacing: 0.5px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 24px 0 32px; }}
  .summary-cell {{ background: #111827; border-radius: 8px; padding: 16px; text-align: center; border: 1px solid #1f2937; }}
  .summary-cell .count {{ font-size: 24px; font-weight: 700; }}
  .summary-cell .label {{ font-size: 12px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.5px; }}
  .finding {{ background: #111827; border-left: 4px solid #4b5563; border-radius: 6px; padding: 16px 20px; margin-bottom: 14px; }}
  .finding .sev {{ display: inline-block; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px; color: white; margin-bottom: 8px; }}
  .finding h3 {{ margin: 4px 0; font-size: 16px; }}
  .finding .desc {{ color: #d1d5db; font-size: 14px; margin: 6px 0; }}
  .finding .meta {{ font-size: 12px; color: #9ca3af; margin-top: 8px; }}
  .finding .remediation {{ font-size: 13px; color: #86efac; margin-top: 8px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0 32px; }}
  th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #1f2937; font-size: 14px; }}
  th {{ color: #9ca3af; font-weight: 600; font-size: 12px; text-transform: uppercase; }}
  .tested-yes {{ color: #86efac; }}
  .tested-no {{ color: #6b7280; }}
  .muted {{ color: #9ca3af; }}
  code {{ background: #1f2937; padding: 2px 6px; border-radius: 4px; font-size: 13px; }}
</style>
</head>
<body>
<div class="container">
  <h1>Vulnerability Scan Report</h1>
  <div class="subtitle">Target: <code>{html.escape(target.url)}</code> &middot; Generated {generated_at} &middot; {scan_report.request_count} requests in {scan_report.duration_seconds:.1f}s</div>

  <span class="rating-badge">OVERALL RISK: {risk_summary.overall_rating}</span>

  <div class="summary-grid">
    {"".join(_summary_cell(sev, counts.get(sev, 0)) for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO])}
  </div>

  <h2>Findings</h2>
  {findings_html}

  {errors_section}

  <h2>OWASP Top 10 (2021) Coverage</h2>
  <table>
    <tr><th>Category</th><th>Tested</th><th>Findings</th></tr>
    {owasp_html}
  </table>
</div>
</body>
</html>"""


def _summary_cell(severity: Severity, count: int) -> str:
    color = SEVERITY_COLORS[severity]
    return f"""<div class="summary-cell" style="border-top: 3px solid {color};">
        <div class="count">{count}</div><div class="label">{severity.value}</div></div>"""


def _render_finding(finding) -> str:
    color = SEVERITY_COLORS[finding.severity]
    evidence = f"<div class='meta'>Evidence: <code>{html.escape(finding.evidence)}</code></div>" if finding.evidence else ""
    remediation = f"<div class='remediation'>Fix: {html.escape(finding.remediation)}</div>" if finding.remediation else ""
    return f"""<div class="finding" style="border-left-color: {color};">
        <span class="sev" style="background:{color};">{finding.severity.value}</span>
        <h3>{html.escape(finding.check)}</h3>
        <div class="desc">{html.escape(finding.description)}</div>
        {evidence}
        <div class="meta">{html.escape(finding.owasp_category)}</div>
        {remediation}
    </div>"""


def _render_owasp_row(category: str, data: dict) -> str:
    tested_html = "<span class='tested-yes'>&#10003; Tested</span>" if data["tested"] else "<span class='tested-no'>Manual review needed</span>"
    return f"<tr><td>{html.escape(category)}</td><td>{tested_html}</td><td>{data['finding_count']}</td></tr>"
