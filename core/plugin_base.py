"""
Base class every detector module implements.

Standardizing the interface means the engine can discover, run, and
error-isolate modules generically instead of hardcoding each one - and
it's what makes "add a new vulnerability check" a 10-minute job instead
of a rewrite.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    check: str                 # e.g. "Missing HSTS Header"
    severity: Severity
    description: str
    evidence: str = ""          # short snippet proving the finding (header value, response fragment)
    owasp_category: str = ""    # e.g. "A05:2021 - Security Misconfiguration"
    remediation: str = ""


@dataclass
class ModuleResult:
    module_name: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None     # set if the module failed to run at all
    raw: dict[str, Any] = field(default_factory=dict)  # raw data for the report appendix


class ScannerModule:
    """
    Subclass this and implement `run`. Keep `run` free of try/except for
    the "did the whole thing blow up" case - the engine handles that so
    one module's bug can't kill the scan.
    """
    name: str = "unnamed-module"

    def __init__(self, target, http_client):
        self.target = target
        self.http = http_client

    def run(self) -> ModuleResult:
        raise NotImplementedError
