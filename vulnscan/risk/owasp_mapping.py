"""
Groups findings by OWASP Top 10 (2021) category for the report's
"OWASP Coverage" section - this is the section that makes a competition
judge go "oh, they actually understand the standard, not just buzzwords."
"""
from __future__ import annotations
from collections import defaultdict
from risk.scoring import RiskSummary

ALL_CATEGORIES = [
    "A01:2021 - Broken Access Control",
    "A02:2021 - Cryptographic Failures",
    "A03:2021 - Injection",
    "A04:2021 - Insecure Design",
    "A05:2021 - Security Misconfiguration",
    "A06:2021 - Vulnerable and Outdated Components",
    "A07:2021 - Identification and Authentication Failures",
    "A08:2021 - Software and Data Integrity Failures",
    "A09:2021 - Security Logging and Monitoring Failures",
    "A10:2021 - Server-Side Request Forgery (SSRF)",
]


def map_owasp(risk_summary: RiskSummary) -> dict:
    by_category = defaultdict(list)
    for finding in risk_summary.all_findings:
        category = finding.owasp_category or "Uncategorized"
        by_category[category].append(finding)

    return {
        category: {
            "finding_count": len(by_category.get(category, [])),
            "findings": by_category.get(category, []),
            "tested": category in _TESTED_CATEGORIES,
        }
        for category in ALL_CATEGORIES
    }


# Categories this scanner actually has modules for, vs. ones that need
# manual review (e.g. A09 logging failures generally can't be assessed
# from outside the application).
_TESTED_CATEGORIES = {
    "A01:2021 - Broken Access Control",
    "A02:2021 - Cryptographic Failures",
    "A03:2021 - Injection",
    "A05:2021 - Security Misconfiguration",
    "A06:2021 - Vulnerable and Outdated Components",
}
