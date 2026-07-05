"""
Run with: python3 -m tests.test_modules   (from the vulnscan/ root)
Or:        python3 -m unittest discover tests

These tests prove each detector's LOGIC is correct using scripted fake
responses - they don't require network access, and they pin down exactly
what should and shouldn't trigger a finding.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.fakes import FakeResponse, FakeHttpClient, FakeTarget
from modules.transport.headers_scan import SecurityHeadersModule
from modules.config.clickjacking import ClickjackingModule
from modules.config.cors_check import CorsMisconfigModule, PROBE_ORIGIN
from modules.config.cookie_flags import CookieFlagsModule
from modules.injection.xss_detect import ReflectedXssModule
from modules.injection.sqli_detect import SqliDetectModule
from modules.access_control.csrf_check import CsrfCheckModule
from core.plugin_base import Severity
from risk.scoring import calculate_risk
from risk.owasp_mapping import map_owasp


class TestSecurityHeaders(unittest.TestCase):
    def test_flags_all_missing_headers(self):
        target = FakeTarget("https://good.example")
        http = FakeHttpClient(lambda m, u, **kw: FakeResponse(200, headers={}, url=u))
        result = SecurityHeadersModule(target, http).run()
        checks = {f.check for f in result.findings}
        self.assertIn("Missing Strict-Transport-Security", checks)
        self.assertIn("Missing Content-Security-Policy", checks)
        self.assertEqual(len(result.findings), 6)

    def test_no_findings_when_all_headers_present(self):
        target = FakeTarget("https://good.example")
        good_headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        http = FakeHttpClient(lambda m, u, **kw: FakeResponse(200, headers=good_headers, url=u))
        result = SecurityHeadersModule(target, http).run()
        self.assertEqual(len(result.findings), 0)


class TestClickjacking(unittest.TestCase):
    def test_flags_when_no_protection(self):
        target = FakeTarget("https://good.example")
        http = FakeHttpClient(lambda m, u, **kw: FakeResponse(200, headers={}, url=u))
        result = ClickjackingModule(target, http).run()
        self.assertEqual(len(result.findings), 1)

    def test_no_finding_with_csp_frame_ancestors(self):
        target = FakeTarget("https://good.example")
        headers = {"Content-Security-Policy": "frame-ancestors 'none'"}
        http = FakeHttpClient(lambda m, u, **kw: FakeResponse(200, headers=headers, url=u))
        result = ClickjackingModule(target, http).run()
        self.assertEqual(len(result.findings), 0)


class TestCors(unittest.TestCase):
    def test_flags_origin_reflection(self):
        target = FakeTarget("https://api.example")
        def responder(m, u, **kw):
            sent_origin = kw.get("headers", {}).get("Origin")
            return FakeResponse(200, headers={"Access-Control-Allow-Origin": sent_origin}, url=u)
        http = FakeHttpClient(responder)
        result = CorsMisconfigModule(target, http).run()
        self.assertEqual(len(result.findings), 1)
        self.assertIn("Reflection", result.findings[0].check)

    def test_no_finding_when_no_cors_headers(self):
        target = FakeTarget("https://api.example")
        http = FakeHttpClient(lambda m, u, **kw: FakeResponse(200, headers={}, url=u))
        result = CorsMisconfigModule(target, http).run()
        self.assertEqual(len(result.findings), 0)


class TestCookieFlags(unittest.TestCase):
    def test_flags_session_cookie_missing_all_flags(self):
        target = FakeTarget("https://good.example")
        headers = {"Set-Cookie": "sessionid=abc123; Path=/"}
        http = FakeHttpClient(lambda m, u, **kw: FakeResponse(200, headers=headers, url=u, raw=None))
        result = CookieFlagsModule(target, http).run()
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, Severity.HIGH)  # "sess" in name -> sensitive

    def test_no_finding_when_flags_present(self):
        target = FakeTarget("https://good.example")
        headers = {"Set-Cookie": "sessionid=abc123; Secure; HttpOnly; SameSite=Strict"}
        http = FakeHttpClient(lambda m, u, **kw: FakeResponse(200, headers=headers, url=u, raw=None))
        result = CookieFlagsModule(target, http).run()
        self.assertEqual(len(result.findings), 0)


class TestReflectedXss(unittest.TestCase):
    def test_flags_unescaped_reflection(self):
        target = FakeTarget("https://good.example/search?q=test")
        def responder(m, u, **kw):
            # Simulate a vulnerable app: whatever's in the query string gets
            # reflected straight into the HTML, unescaped.
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(u).query).get("q", [""])[0]
            return FakeResponse(200, headers={}, text=f"<html>Results for {q}</html>", url=u)
        http = FakeHttpClient(responder)
        result = ReflectedXssModule(target, http).run()
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, Severity.HIGH)

    def test_no_finding_when_input_is_escaped(self):
        target = FakeTarget("https://good.example/search?q=test")
        def responder(m, u, **kw):
            return FakeResponse(200, headers={}, text="<html>Results for [sanitized]</html>", url=u)
        http = FakeHttpClient(responder)
        result = ReflectedXssModule(target, http).run()
        self.assertEqual(len(result.findings), 0)


class TestSqliDetect(unittest.TestCase):
    def test_flags_error_based_leak(self):
        target = FakeTarget("https://good.example/products?id=1")
        def responder(m, u, **kw):
            if "'" in u or "%27" in u:
                return FakeResponse(200, text="You have an error in your SQL syntax near ''", url=u)
            return FakeResponse(200, text="<html>Product list</html>", url=u)
        http = FakeHttpClient(responder)
        result = SqliDetectModule(target, http).run()
        self.assertEqual(len(result.findings), 1)
        self.assertIn("error-based", result.findings[0].check)
        self.assertEqual(result.findings[0].severity, Severity.CRITICAL)

    def test_no_finding_on_clean_app(self):
        target = FakeTarget("https://good.example/products?id=1")
        http = FakeHttpClient(lambda m, u, **kw: FakeResponse(200, text="<html>Product list</html>", url=u))
        result = SqliDetectModule(target, http).run()
        self.assertEqual(len(result.findings), 0)


class TestCsrf(unittest.TestCase):
    def test_flags_post_form_without_token(self):
        target = FakeTarget("https://good.example/account")
        html = '<form method="POST" action="/update"><input name="email"><button>Save</button></form>'
        http = FakeHttpClient(lambda m, u, **kw: FakeResponse(200, text=html, url=u))
        result = CsrfCheckModule(target, http).run()
        self.assertEqual(len(result.findings), 1)

    def test_no_finding_with_csrf_token(self):
        target = FakeTarget("https://good.example/account")
        html = ('<form method="POST" action="/update">'
                '<input type="hidden" name="csrf_token" value="xyz">'
                '<input name="email"><button>Save</button></form>')
        http = FakeHttpClient(lambda m, u, **kw: FakeResponse(200, text=html, url=u))
        result = CsrfCheckModule(target, http).run()
        self.assertEqual(len(result.findings), 0)


class TestRiskScoringAndOwasp(unittest.TestCase):
    def test_overall_rating_escalates_to_critical(self):
        target = FakeTarget("https://good.example/products?id=1")
        http = FakeHttpClient(lambda m, u, **kw: FakeResponse(
            200, text="You have an error in your SQL syntax", url=u))
        sqli_result = SqliDetectModule(target, http).run()
        risk = calculate_risk({"sqli": sqli_result})
        self.assertEqual(risk.overall_rating, "CRITICAL")
        self.assertGreater(risk.score, 0)

        owasp = map_owasp(risk)
        injection_cat = "A03:2021 - Injection"
        self.assertEqual(owasp[injection_cat]["finding_count"], 1)
        self.assertTrue(owasp[injection_cat]["tested"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
