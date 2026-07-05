"""
Shared HTTP client for every scanner module.

Centralizing this means:
  - one place to set timeouts/retries/rate limits
  - one place to enforce "don't hammer the target" behavior
  - one place to record every request made, for the audit trail in the report
"""
from __future__ import annotations
import time
import threading
from dataclasses import dataclass, field
from typing import Optional
import requests

DEFAULT_TIMEOUT = 8
DEFAULT_USER_AGENT = "VulnScanCTF/1.0 (+authorized-security-testing)"


@dataclass
class RequestLogEntry:
    method: str
    url: str
    status_code: Optional[int]
    elapsed_ms: float
    error: Optional[str] = None


class ScanHttpClient:
    """
    Wraps requests.Session with:
      - a minimum delay between requests (politeness / avoids tripping WAFs
        into blocking the rest of the scan)
      - a hard cap on total requests per scan, so a bug in a module can't
        turn into an accidental DoS
      - full request logging for the report's "what we actually sent" section
    """

    def __init__(
        self,
        min_delay_seconds: float = 0.15,
        max_requests: int = 500,
        timeout: int = DEFAULT_TIMEOUT,
        verify_tls: bool = True,
    ):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
        self.min_delay = min_delay_seconds
        self.max_requests = max_requests
        self.timeout = timeout
        self.verify_tls = verify_tls
        self._lock = threading.Lock()
        self._last_request_time = 0.0
        self._request_count = 0
        self.log: list[RequestLogEntry] = []

    def _throttle(self):
        with self._lock:
            if self._request_count >= self.max_requests:
                raise RuntimeError(
                    f"Scan exceeded the safety cap of {self.max_requests} requests. "
                    f"Aborting to avoid hammering the target."
                )
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < self.min_delay:
                time.sleep(self.min_delay - elapsed)
            self._last_request_time = time.monotonic()
            self._request_count += 1

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        self._throttle()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_tls)
        kwargs.setdefault("allow_redirects", True)
        start = time.monotonic()
        try:
            resp = self.session.request(method, url, **kwargs)
            self.log.append(RequestLogEntry(
                method=method, url=url, status_code=resp.status_code,
                elapsed_ms=(time.monotonic() - start) * 1000,
            ))
            return resp
        except requests.RequestException as e:
            self.log.append(RequestLogEntry(
                method=method, url=url, status_code=None,
                elapsed_ms=(time.monotonic() - start) * 1000, error=str(e),
            ))
            raise

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        return self.request("HEAD", url, **kwargs)
