from core.plugin_base import ScannerModule, ModuleResult, Finding, Severity

# (header name, severity if missing, description, remediation)
EXPECTED_HEADERS = [
    ("Strict-Transport-Security", Severity.HIGH,
     "HSTS is missing, so browsers won't force HTTPS on future visits.",
     "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("X-Content-Type-Options", Severity.MEDIUM,
     "Missing X-Content-Type-Options allows MIME-sniffing attacks.",
     "Add: X-Content-Type-Options: nosniff"),
    ("X-Frame-Options", Severity.MEDIUM,
     "Missing X-Frame-Options increases clickjacking risk (also checked separately via CSP frame-ancestors).",
     "Add: X-Frame-Options: DENY  (or CSP frame-ancestors 'none')"),
    ("Content-Security-Policy", Severity.HIGH,
     "No CSP means the browser has no defense-in-depth against injected scripts.",
     "Define a Content-Security-Policy restricting script/style/img sources."),
    ("Referrer-Policy", Severity.LOW,
     "Missing Referrer-Policy may leak full URLs (including sensitive query params) to third parties via the Referer header.",
     "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    ("Permissions-Policy", Severity.LOW,
     "Missing Permissions-Policy leaves browser feature access (camera, mic, geolocation) unrestricted by default.",
     "Add a Permissions-Policy restricting unused browser features."),
]


class SecurityHeadersModule(ScannerModule):
    name = "Security Headers"

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        resp = self.http.get(self.target.url)
        headers = resp.headers

        result.raw = {"headers_seen": dict(headers)}

        for header_name, severity, description, remediation in EXPECTED_HEADERS:
            if header_name not in headers:
                result.findings.append(Finding(
                    check=f"Missing {header_name}",
                    severity=severity,
                    description=description,
                    owasp_category="A05:2021 - Security Misconfiguration",
                    remediation=remediation,
                ))

        return result
