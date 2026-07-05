import concurrent.futures
from core.plugin_base import ScannerModule, ModuleResult, Finding, Severity

# Extend this list freely - it's the highest-value place to add breadth
# for a competition (each entry is basically a free extra "check").
CANDIDATE_PATHS = [
    (".git/config", Severity.CRITICAL, "Exposed .git directory can leak full source code history."),
    (".env", Severity.CRITICAL, "Exposed .env file often contains database credentials/API keys."),
    ("wp-config.php.bak", Severity.CRITICAL, "Backup of WordPress config may contain DB credentials."),
    ("config.php.bak", Severity.HIGH, "Backup config file may expose secrets."),
    ("backup.zip", Severity.HIGH, "Exposed backup archive may contain full site/database dump."),
    (".DS_Store", Severity.LOW, "Reveals directory structure/filenames."),
    ("phpinfo.php", Severity.MEDIUM, "Exposes detailed server/PHP configuration."),
    ("admin/", Severity.INFO, "Admin panel reachable - ensure it's properly access-controlled."),
    (".well-known/security.txt", Severity.INFO, "Present - good practice (not a vulnerability)."),
    ("server-status", Severity.MEDIUM, "Apache mod_status may leak internal request/traffic data."),
    ("swagger.json", Severity.LOW, "Exposed API schema reveals full endpoint surface to attackers."),
    ("api/v1/users", Severity.INFO, "Common API path present - check auth on it separately."),
]


class SensitivePathsModule(ScannerModule):
    name = "Sensitive Paths"

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        found = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futures = {
                pool.submit(self._check_path, path): (path, severity, desc)
                for path, severity, desc in CANDIDATE_PATHS
            }
            for future in concurrent.futures.as_completed(futures):
                path, severity, desc = futures[future]
                status = future.result()
                if status is not None and status < 400:
                    found.append(path)
                    result.findings.append(Finding(
                        check=f"Exposed Path: /{path}",
                        severity=severity,
                        description=desc,
                        evidence=f"HTTP {status}",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        remediation=f"Remove public access to /{path} or block it at the web server/proxy level.",
                    ))

        result.raw = {"paths_found": found, "paths_checked": len(CANDIDATE_PATHS)}
        return result

    def _check_path(self, path: str):
        try:
            resp = self.http.get(f"{self.target.base_url}/{path}", allow_redirects=False)
            return resp.status_code
        except Exception:
            return None
