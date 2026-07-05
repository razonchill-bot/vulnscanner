import re
from core.plugin_base import ScannerModule, ModuleResult, Finding, Severity


class ClickjackingModule(ScannerModule):
    name = "Clickjacking Protection"

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        resp = self.http.get(self.target.url)

        xfo = resp.headers.get("X-Frame-Options", "")
        csp = resp.headers.get("Content-Security-Policy", "")
        has_frame_ancestors = bool(re.search(r"frame-ancestors", csp, re.IGNORECASE))

        result.raw = {"x_frame_options": xfo, "csp_frame_ancestors": has_frame_ancestors}

        if not xfo and not has_frame_ancestors:
            result.findings.append(Finding(
                check="No Clickjacking Protection",
                severity=Severity.MEDIUM,
                description="Neither X-Frame-Options nor a CSP frame-ancestors directive is set, "
                            "so the page can be embedded in an iframe on an attacker-controlled site.",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation="Add 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
            ))

        return result
