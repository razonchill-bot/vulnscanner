import re
from core.plugin_base import ScannerModule, ModuleResult, Finding, Severity

# Small signature set. Extend this dict as you add more fingerprints -
# each entry is (regex_pattern, where_to_look).
SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r'name="generator" content="WordPress'],
    "Joomla": [r"/media/jui/", r'name="generator" content="Joomla'],
    "Drupal": [r"/sites/default/files", r'Drupal\.settings'],
    "Laravel": [r"laravel_session"],
    "Django": [r"csrftoken", r"__admin__"],
    "Express/Node": [r"X-Powered-By: Express"],
    "React": [r"__NEXT_DATA__|data-reactroot|react-dom"],
}

# Illustrative only - a real deployment should pull from an updated CVE feed
# (e.g. NVD API) rather than a hardcoded list like this.
KNOWN_VULNERABLE_HINTS = {
    "WordPress": "If a version string is visible, cross-check it against the WPScan vulnerability database.",
    "Drupal": "Cross-check any exposed version against Drupal Security Advisories (esp. old Drupalgeddon-class issues).",
}


class TechFingerprintModule(ScannerModule):
    name = "Technology Fingerprint"

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        resp = self.http.get(self.target.url)
        body = resp.text
        headers_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())

        detected = []
        for tech, patterns in SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE) or re.search(pattern, headers_blob, re.IGNORECASE):
                    detected.append(tech)
                    break

        result.raw = {"detected_technologies": detected}

        for tech in detected:
            hint = KNOWN_VULNERABLE_HINTS.get(tech)
            result.findings.append(Finding(
                check=f"Technology Detected: {tech}",
                severity=Severity.INFO,
                description=f"Fingerprint matched {tech}." + (f" {hint}" if hint else ""),
                owasp_category="A06:2021 - Vulnerable and Outdated Components",
                remediation="Ensure this component is on the latest patched version.",
            ))

        return result
