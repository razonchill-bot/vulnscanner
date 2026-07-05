from bs4 import BeautifulSoup
from core.plugin_base import ScannerModule, ModuleResult, Finding, Severity

CSRF_TOKEN_HINTS = ("csrf", "token", "authenticity_token", "_token", "nonce")


class CsrfCheckModule(ScannerModule):
    """
    Heuristic CSRF check: looks for <form> elements with state-changing
    methods (POST/PUT/DELETE) that lack any hidden input resembling a CSRF
    token. This is a heuristic, not proof - some apps use header-based
    tokens (e.g. via JS) that this static check can't see, so findings here
    should be manually verified.
    """
    name = "CSRF Protection"

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        resp = self.http.get(self.target.url)
        soup = BeautifulSoup(resp.text, "html.parser")

        forms = soup.find_all("form")
        result.raw = {"forms_found": len(forms)}

        for i, form in enumerate(forms):
            method = (form.get("method") or "get").lower()
            if method not in ("post", "put", "delete"):
                continue

            hidden_inputs = form.find_all("input", {"type": "hidden"})
            has_token = any(
                any(hint in (inp.get("name") or "").lower() for hint in CSRF_TOKEN_HINTS)
                for inp in hidden_inputs
            )

            if not has_token:
                action = form.get("action") or "(same page)"
                result.findings.append(Finding(
                    check=f"Form Without CSRF Token (form #{i + 1})",
                    severity=Severity.MEDIUM,
                    description=f"A {method.upper()} form (action: {action}) has no hidden field "
                                f"resembling a CSRF token. This is heuristic - confirm manually, "
                                f"since some apps protect via headers/JS instead.",
                    owasp_category="A01:2021 - Broken Access Control",
                    remediation="Include a per-session CSRF token in all state-changing forms and "
                                "validate it server-side (e.g. Double Submit Cookie or synchronizer token pattern).",
                ))

        return result
