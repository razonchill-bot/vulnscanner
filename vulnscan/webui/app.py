"""
FastAPI web UI. Run with:
    uvicorn webui.app:app --reload --port 8000
"""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # allow `core.*`, `modules.*` imports

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uuid

from core.engine import run_scan
from core.target import InvalidTargetError
from risk.scoring import calculate_risk
from risk.owasp_mapping import map_owasp
from report.html_report import render_html_report
from report.history import save_scan, get_history

app = FastAPI(title="VulnScan")

REPORTS_DIR = Path(__file__).parent / "generated_reports"
REPORTS_DIR.mkdir(exist_ok=True)

TEMPLATES_DIR = Path(__file__).parent / "templates"


class ScanRequest(BaseModel):
    url: str
    allow_private: bool = False


@app.get("/", response_class=HTMLResponse)
def index():
    return (TEMPLATES_DIR / "index.html").read_text(encoding="utf-8")


@app.post("/api/scan")
def api_scan(req: ScanRequest):
    try:
        scan_report = run_scan(req.url, allow_private_ips=req.allow_private)
    except InvalidTargetError as e:
        raise HTTPException(status_code=400, detail=str(e))

    risk_summary = calculate_risk(scan_report.module_results)
    owasp_map = map_owasp(risk_summary)
    save_scan(scan_report.target.url, risk_summary)

    report_id = uuid.uuid4().hex[:12]
    html_report = render_html_report(scan_report, risk_summary, owasp_map)
    (REPORTS_DIR / f"{report_id}.html").write_text(html_report, encoding="utf-8")

    return {
        "target_url": scan_report.target.url,
        "duration_seconds": round(scan_report.duration_seconds, 2),
        "request_count": scan_report.request_count,
        "overall_rating": risk_summary.overall_rating,
        "risk_score": risk_summary.score,
        "counts": {sev.value: count for sev, count in risk_summary.counts.items()},
        "modules": [
            {
                "name": name,
                "error": result.error,
                "findings": [_finding_to_dict(f) for f in result.findings],
            }
            for name, result in scan_report.module_results.items()
        ],
        "owasp": {
            category: {
                "tested": data["tested"],
                "finding_count": data["finding_count"],
            }
            for category, data in owasp_map.items()
        },
        "report_id": report_id,
    }


@app.get("/api/report/{report_id}")
def get_report(report_id: str):
    path = REPORTS_DIR / f"{report_id}.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path, media_type="text/html")


@app.get("/api/history")
def api_history(url: str | None = None):
    return get_history(url=url)


def _finding_to_dict(finding) -> dict:
    return {
        "check": finding.check,
        "severity": finding.severity.value,
        "description": finding.description,
        "evidence": finding.evidence,
        "owasp_category": finding.owasp_category,
        "remediation": finding.remediation,
    }
