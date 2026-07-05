"""
Turns raw findings across all modules into:
  - a single overall risk rating
  - counts per severity
  - a numeric score (useful for the chart / trend-over-time in history)

This is the ONE place severity roll-up logic lives - engine/report code
should never reimplement this.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from core.plugin_base import Severity, Finding

SEVERITY_WEIGHTS = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 7,
    Severity.CRITICAL: 12,
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


@dataclass
class RiskSummary:
    counts: dict[Severity, int] = field(default_factory=dict)
    score: int = 0
    overall_rating: str = "LOW"
    all_findings: list[Finding] = field(default_factory=list)


def calculate_risk(module_results: dict) -> RiskSummary:
    counts = {s: 0 for s in Severity}
    all_findings: list[Finding] = []

    for result in module_results.values():
        if result.error:
            continue
        for finding in result.findings:
            counts[finding.severity] += 1
            all_findings.append(finding)

    score = sum(SEVERITY_WEIGHTS[s] * n for s, n in counts.items())

    if counts[Severity.CRITICAL] > 0:
        overall = "CRITICAL"
    elif counts[Severity.HIGH] > 0:
        overall = "HIGH"
    elif counts[Severity.MEDIUM] > 0:
        overall = "MEDIUM"
    elif counts[Severity.LOW] > 0:
        overall = "LOW"
    else:
        overall = "INFO"

    # Sort findings worst-first for the report.
    all_findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))

    return RiskSummary(counts=counts, score=score, overall_rating=overall, all_findings=all_findings)
