import uuid
import re
from urllib.parse import urlencode, urlparse, parse_qs
from core.plugin_base import ScannerModule, ModuleResult, Finding, Severity

# Common parameter names worth probing when none are present in the URL itself.
COMMON_PARAMS = ["q", "search", "query", "id", "name", "redirect", "url", "page"]


class ReflectedXssModule(ScannerModule):
    """
    Detection-only reflected-XSS check: injects a unique, harmless marker
    string and checks whether it comes back UNESCAPED in the HTML response.
    This proves the injection point exists without ever delivering a real
    payload (no <script>alert()</script> execution attempt, no cookie theft,
    nothing that touches a browser). That's sufficient to flag the finding;
    weaponizing it further is out of scope for a detection tool.
    """
    name = "Reflected XSS (Detection)"

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        parsed = urlparse(self.target.url)
        existing_params = parse_qs(parsed.query)

        params_to_test = list(existing_params.keys()) or COMMON_PARAMS
        tested = 0
        findings_raw = []

        for param in params_to_test:
            marker = f"vs{uuid.uuid4().hex[:8]}xz"
            probe_value = f'"><{marker}>'  # breaks out of an attribute AND a tag context
            query_params = {**{k: v[0] for k, v in existing_params.items()}, param: probe_value}
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(query_params)}"

            try:
                resp = self.http.get(test_url)
            except Exception:
                continue
            tested += 1

            if probe_value in resp.text:
                findings_raw.append(param)
                result.findings.append(Finding(
                    check=f"Reflected XSS Indicator: parameter '{param}'",
                    severity=Severity.HIGH,
                    description=f"Parameter '{param}' reflects attacker-controlled input "
                                f"back into the HTML response without encoding/escaping, "
                                f"which typically allows script injection.",
                    evidence=f"Marker '{marker}' reflected unescaped in response",
                    owasp_category="A03:2021 - Injection",
                    remediation="Context-appropriately HTML-encode all user input before rendering it into HTML, "
                                "and add a Content-Security-Policy as defense-in-depth.",
                ))
            elif re.search(re.escape(marker), resp.text):
                # Marker present but the dangerous characters were stripped/encoded - good sign,
                # not a finding, but useful to know for the report appendix.
                pass

        result.raw = {"params_tested": tested, "vulnerable_params": findings_raw}
        return result
