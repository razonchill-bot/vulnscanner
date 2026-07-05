"""
Fake HTTP layer for unit tests. This lets us verify detection LOGIC
deterministically, without depending on any real network target being
reachable (or behaving consistently) at test time - the right way to
test a scanner's decision-making, independent of live network conditions.
"""
from urllib.parse import urlparse, parse_qs


class FakeResponse:
    def __init__(self, status_code=200, headers=None, text="", url="", raw=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.url = url
        self.raw = raw


class FakeTarget:
    def __init__(self, url):
        self.url = url
        parsed = urlparse(url)
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.base_url = f"{parsed.scheme}://{parsed.hostname}"


class FakeHttpClient:
    """
    responder: callable(method, url, **kwargs) -> FakeResponse
    Lets each test define exactly how the "server" behaves.
    """
    def __init__(self, responder):
        self.responder = responder
        self.timeout = 8
        self.log = []

    def get(self, url, **kwargs):
        return self.responder("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.responder("POST", url, **kwargs)

    def head(self, url, **kwargs):
        return self.responder("HEAD", url, **kwargs)
