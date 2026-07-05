from core.plugin_base import ScannerModule, ModuleResult, Finding, Severity


class SiteInfoModule(ScannerModule):
    name = "Site Information"

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        resp = self.http.get(self.target.url)

        result.raw = {
            "final_url": resp.url,
            "status_code": resp.status_code,
            "server_header": resp.headers.get("Server", "not disclosed"),
            "content_type": resp.headers.get("Content-Type", "unknown"),
            "redirected": resp.url != self.target.url,
        }

        if resp.url != self.target.url and resp.url.startswith("http://"):
            result.findings.append(Finding(
                check="HTTPS Not Enforced",
                severity=Severity.MEDIUM,
                description="The site did not redirect to HTTPS.",
                evidence=f"Final URL after redirects: {resp.url}",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation="Enforce HTTPS with a redirect from HTTP and set HSTS.",
            ))

        server = resp.headers.get("Server")
        if server:
            result.findings.append(Finding(
                check="Server Header Disclosure",
                severity=Severity.LOW,
                description="The Server header discloses software/version information useful for targeted attacks.",
                evidence=f"Server: {server}",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation="Suppress or genericize the Server header at the web server/proxy level.",
            ))

        return result
