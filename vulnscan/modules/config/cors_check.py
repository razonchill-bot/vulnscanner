from core.plugin_base import ScannerModule, ModuleResult, Finding, Severity

PROBE_ORIGIN = "https://vulnscan-cors-probe.example.invalid"


class CorsMisconfigModule(ScannerModule):
    name = "CORS Misconfiguration"

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name)

        resp = self.http.get(self.target.url, headers={"Origin": PROBE_ORIGIN})
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials")

        result.raw = {"acao": acao, "acac": acac}

        if acao == "*" and acac == "true":
            # This combination is actually invalid per spec (browsers reject it),
            # but some misconfigured servers still send it - worth flagging.
            result.findings.append(Finding(
                check="Invalid/Dangerous CORS Combination",
                severity=Severity.HIGH,
                description="Server sent 'Access-Control-Allow-Origin: *' together with "
                            "'Access-Control-Allow-Credentials: true', which is contradictory "
                            "and indicates a misconfigured CORS policy.",
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation="Reflect a specific allow-list of trusted origins instead of '*' when credentials are allowed.",
            ))
        elif acao == PROBE_ORIGIN:
            result.findings.append(Finding(
                check="Origin Reflection in CORS Policy",
                severity=Severity.HIGH,
                description="The server reflects any arbitrary Origin header back in "
                            "Access-Control-Allow-Origin, meaning any website can make "
                            "authenticated cross-origin requests to this API.",
                evidence=f"Sent Origin: {PROBE_ORIGIN} -> reflected in ACAO",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation="Validate Origin against an explicit allow-list server-side rather than reflecting it.",
            ))
        elif acao == "*":
            result.findings.append(Finding(
                check="Wildcard CORS Policy",
                severity=Severity.LOW,
                description="Access-Control-Allow-Origin is '*'. Fine for public read-only APIs; "
                            "risky if the endpoint returns sensitive or user-specific data.",
                evidence="ACAO: *",
                owasp_category="A05:2021 - Security Misconfiguration",
                remediation="Restrict to specific origins if the response contains non-public data.",
            ))

        return result
