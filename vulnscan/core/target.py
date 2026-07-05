"""
Target normalization and validation.

Every module receives a normalized Target object instead of a raw string,
so URL-handling bugs only need to be fixed in one place.
"""
from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse
import ipaddress
import socket


class InvalidTargetError(Exception):
    pass


@dataclass
class Target:
    raw_input: str
    url: str
    scheme: str
    host: str
    port: int
    path: str

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}" if self._explicit_port else f"{self.scheme}://{self.host}"

    @property
    def _explicit_port(self) -> bool:
        default = 443 if self.scheme == "https" else 80
        return self.port != default


def normalize_target(user_input: str, *, allow_private_ips: bool = False) -> Target:
    """
    Turn whatever the user typed into a validated Target.

    Rules:
      - Add https:// if no scheme given (falls back to http if https fails later).
      - Reject empty / malformed input early instead of letting it explode
        somewhere deep in a scanner module.
      - Optionally block scans against private/loopback IP ranges to avoid
        the tool being pointed at internal infrastructure by mistake.
    """
    raw = user_input.strip()
    if not raw:
        raise InvalidTargetError("Empty target.")

    if "://" not in raw:
        raw = "https://" + raw

    parsed = urlparse(raw)

    if parsed.scheme not in ("http", "https"):
        raise InvalidTargetError(f"Unsupported scheme: {parsed.scheme}")

    if not parsed.hostname:
        raise InvalidTargetError("Could not parse a hostname from input.")

    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if not allow_private_ips:
        _reject_private_targets(host)

    return Target(
        raw_input=user_input,
        url=urlunparse(parsed),
        scheme=parsed.scheme,
        host=host,
        port=port,
        path=parsed.path or "/",
    )


def _reject_private_targets(host: str) -> None:
    """
    Best-effort guard against accidentally scanning private/loopback/link-local
    addresses (e.g. a misconfigured input pointing at 127.0.0.1 or 10.x.x.x).
    For CTF setups that run challenges on private ranges, pass
    allow_private_ips=True explicitly.
    """
    try:
        resolved = socket.gethostbyname(host)
        ip = ipaddress.ip_address(resolved)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise InvalidTargetError(
                f"Target resolves to a private/loopback address ({resolved}). "
                f"Pass allow_private_ips=True if this is intentional (e.g. a local CTF box)."
            )
    except socket.gaierror:
        # DNS resolution failure - let downstream HTTP calls surface the real error.
        pass
