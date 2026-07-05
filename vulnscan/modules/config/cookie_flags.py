from core.plugin_base import ScannerModule, ModuleResult, Finding, Severity


class CookieFlagsModule(ScannerModule):
    name = "Cookie Security Flags"

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        resp = self.http.get(self.target.url)

        set_cookie_headers = resp.raw.headers.get_all("Set-Cookie") if resp.raw and hasattr(resp.raw.headers, "get_all") else None
        if not set_cookie_headers:
            # Fallback for environments where raw header list isn't accessible
            single = resp.headers.get("Set-Cookie")
            set_cookie_headers = [single] if single else []

        result.raw = {"cookies_seen": len(set_cookie_headers)}

        for cookie_str in set_cookie_headers:
            name = cookie_str.split("=")[0].strip()
            lower = cookie_str.lower()
            issues = []
            if "secure" not in lower and self.target.scheme == "https":
                issues.append("missing Secure flag")
            if "httponly" not in lower:
                issues.append("missing HttpOnly flag")
            if "samesite" not in lower:
                issues.append("missing SameSite attribute")

            if issues:
                looks_sensitive = any(k in name.lower() for k in ("sess", "auth", "token", "id"))
                severity = Severity.HIGH if looks_sensitive else Severity.LOW
                result.findings.append(Finding(
                    check=f"Weak Cookie Flags: {name}",
                    severity=severity,
                    description=f"Cookie '{name}' is {', '.join(issues)}.",
                    evidence=cookie_str.split(";")[0],
                    owasp_category="A02:2021 - Cryptographic Failures",
                    remediation="Set Secure, HttpOnly, and SameSite=Strict/Lax on session and auth cookies.",
                ))

        return result
