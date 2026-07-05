"""
The scan engine: runs every registered module against a target, isolates
failures so one broken module doesn't kill the whole scan, and hands the
results off to risk scoring / OWASP mapping / reporting.
"""
from __future__ import annotations
import concurrent.futures
import time
from dataclasses import dataclass, field

from core.target import Target, normalize_target
from core.http_client import ScanHttpClient
from core.plugin_base import ModuleResult

# --- Module registry -------------------------------------------------------
# Import modules here as you add them. Keeping this list explicit (rather
# than magic auto-discovery) makes it obvious what a given scan run actually
# includes - important when you're explaining your tool to judges.

from modules.recon.site_info import SiteInfoModule
from modules.recon.tech_fingerprint import TechFingerprintModule
from modules.transport.headers_scan import SecurityHeadersModule
from modules.transport.tls_scan import TlsScanModule
from modules.config.cors_check import CorsMisconfigModule
from modules.config.clickjacking import ClickjackingModule
from modules.config.cookie_flags import CookieFlagsModule
from modules.config.sensitive_paths import SensitivePathsModule
from modules.injection.xss_detect import ReflectedXssModule
from modules.injection.sqli_detect import SqliDetectModule
from modules.access_control.csrf_check import CsrfCheckModule

MODULE_CLASSES = [
    SiteInfoModule,
    TechFingerprintModule,
    SecurityHeadersModule,
    TlsScanModule,
    CookieFlagsModule,
    CorsMisconfigModule,
    ClickjackingModule,
    SensitivePathsModule,
    CsrfCheckModule,
    ReflectedXssModule,
    SqliDetectModule,
]


@dataclass
class ScanReport:
    target: Target
    module_results: dict[str, ModuleResult] = field(default_factory=dict)
    duration_seconds: float = 0.0
    request_count: int = 0


def run_scan(
    url: str,
    *,
    allow_private_ips: bool = False,
    max_workers: int = 4,
    max_requests: int = 500,
) -> ScanReport:
    target = normalize_target(url, allow_private_ips=allow_private_ips)
    http = ScanHttpClient(max_requests=max_requests)

    start = time.monotonic()
    results: dict[str, ModuleResult] = {}

    # Modules run concurrently (I/O bound - waiting on network), but the
    # http client's internal throttle still caps overall request rate.
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_cls = {
            pool.submit(_run_module_safely, cls, target, http): cls
            for cls in MODULE_CLASSES
        }
        for future in concurrent.futures.as_completed(future_to_cls):
            result = future.result()
            results[result.module_name] = result

    return ScanReport(
        target=target,
        module_results=results,
        duration_seconds=time.monotonic() - start,
        request_count=len(http.log),
    )


def _run_module_safely(module_cls, target: Target, http: ScanHttpClient) -> ModuleResult:
    """
    Never let a single module's exception take down the whole scan.
    A failed module shows up in the report as an error, not a stack trace
    on the user's terminal.
    """
    instance = module_cls(target, http)
    try:
        return instance.run()
    except Exception as e:  # noqa: BLE001 - intentional: isolate any module failure
        return ModuleResult(module_name=instance.name, error=f"{type(e).__name__}: {e}")
