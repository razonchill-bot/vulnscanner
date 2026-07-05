import re
from urllib.parse import urlencode, urlparse, parse_qs
from core.plugin_base import ScannerModule, ModuleResult, Finding, Severity

# Regexes that match common DB error messages leaking through to the response.
# This list is intentionally small and illustrative - extend with more
# DBMS-specific signatures (Oracle, MSSQL, SQLite, etc.) as needed.
SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",         # MySQL
    r"warning: mysql_",                                # MySQL/PHP
    r"unclosed quotation mark after the character",     # MSSQL
    r"quoted string not properly terminated",           # Oracle
    r"pg_query\(\)",                                     # PostgreSQL/PHP
    r"sqlite3\.OperationalError",                        # SQLite
    r"ORA-\d{5}",                                        # Oracle error codes
]

COMMON_PARAMS = ["id", "q", "search", "category", "user", "page"]


class SqliDetectModule(ScannerModule):
    """
    Detection-only SQLi check using two non-destructive techniques:

    1. Error-based: send a lone single-quote and look for DB error strings
       leaking into the response. Proves the input reaches a query
       unsanitized without ever attempting to read/modify data.
    2. Boolean-based: compare response to a "always true" vs "always false"
       condition appended to the parameter. A meaningfully different
       response (e.g. content length/status) between the two indicates the
       input influences query logic.

    Neither technique attempts UNION-based extraction, stacked queries, or
    anything that reads/writes actual data - it only confirms the
    vulnerability class exists.
    """
    name = "SQL Injection (Detection)"

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name)
        parsed = urlparse(self.target.url)
        existing_params = parse_qs(parsed.query)
        params_to_test = list(existing_params.keys()) or COMMON_PARAMS

        tested = 0
        flagged = []

        for param in params_to_test:
            base_params = {k: v[0] for k, v in existing_params.items()}

            # --- Technique 1: error-based ---
            probe_params = {**base_params, param: base_params.get(param, "1") + "'"}
            probe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(probe_params)}"
            try:
                resp = self.http.get(probe_url)
                tested += 1
            except Exception:
                continue

            error_hit = next((pat for pat in SQL_ERROR_SIGNATURES if re.search(pat, resp.text, re.IGNORECASE)), None)
            if error_hit:
                flagged.append(param)
                result.findings.append(Finding(
                    check=f"SQL Injection Indicator (error-based): parameter '{param}'",
                    severity=Severity.CRITICAL,
                    description=f"Injecting a single quote into '{param}' caused a database "
                                f"error message to leak into the response, indicating the "
                                f"input reaches a SQL query without proper sanitization.",
                    evidence=f"Matched pattern: {error_hit}",
                    owasp_category="A03:2021 - Injection",
                    remediation="Use parameterized queries / prepared statements exclusively; "
                                "never concatenate user input into SQL strings. Disable verbose DB errors in production.",
                ))
                continue  # no need for boolean test if error-based already confirmed it

            # --- Technique 2: boolean-based ---
            true_params = {**base_params, param: str(base_params.get(param, "1")) + " AND 1=1"}
            false_params = {**base_params, param: str(base_params.get(param, "1")) + " AND 1=2"}
            true_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(true_params)}"
            false_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(false_params)}"

            try:
                true_resp = self.http.get(true_url)
                false_resp = self.http.get(false_url)
            except Exception:
                continue

            if (true_resp.status_code == 200 and false_resp.status_code == 200
                    and abs(len(true_resp.text) - len(false_resp.text)) > 50):
                flagged.append(param)
                result.findings.append(Finding(
                    check=f"SQL Injection Indicator (boolean-based): parameter '{param}'",
                    severity=Severity.HIGH,
                    description=f"Appending an always-true vs. always-false condition to '{param}' "
                                f"produced meaningfully different responses (length delta "
                                f"{abs(len(true_resp.text) - len(false_resp.text))} chars), suggesting "
                                f"the input influences query logic.",
                    owasp_category="A03:2021 - Injection",
                    remediation="Use parameterized queries / prepared statements exclusively.",
                ))

        result.raw = {"params_tested": tested, "flagged_params": flagged}
        return result
