import ssl
import socket
import datetime
from core.plugin_base import ScannerModule, ModuleResult, Finding, Severity

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


class TlsScanModule(ScannerModule):
    name = "TLS / Certificate Analysis"

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name)

        if self.target.scheme != "https":
            result.findings.append(Finding(
                check="No TLS in Use",
                severity=Severity.HIGH,
                description="The target is being served over plain HTTP - no transport encryption at all.",
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation="Deploy TLS (HTTPS) with a valid certificate and redirect all HTTP traffic to it.",
            ))
            return result

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.target.host, self.target.port), timeout=self.http.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target.host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    protocol = tls_sock.version()
                    cipher = tls_sock.cipher()

            result.raw = {"protocol": protocol, "cipher": cipher, "cert": cert}

            if protocol in WEAK_PROTOCOLS:
                result.findings.append(Finding(
                    check="Outdated TLS Protocol",
                    severity=Severity.HIGH,
                    description=f"Server negotiated {protocol}, which is deprecated and has known weaknesses.",
                    evidence=protocol,
                    owasp_category="A02:2021 - Cryptographic Failures",
                    remediation="Disable protocols below TLS 1.2; prefer TLS 1.3 only where compatible.",
                ))

            not_after = cert.get("notAfter")
            if not_after:
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.utcnow()).days
                if days_left < 0:
                    result.findings.append(Finding(
                        check="Expired Certificate",
                        severity=Severity.CRITICAL,
                        description="The TLS certificate has already expired.",
                        evidence=f"Expired on {not_after}",
                        owasp_category="A02:2021 - Cryptographic Failures",
                        remediation="Renew the certificate immediately.",
                    ))
                elif days_left < 14:
                    result.findings.append(Finding(
                        check="Certificate Expiring Soon",
                        severity=Severity.MEDIUM,
                        description=f"The TLS certificate expires in {days_left} day(s).",
                        evidence=f"Expires on {not_after}",
                        owasp_category="A02:2021 - Cryptographic Failures",
                        remediation="Renew the certificate before expiry; consider automating renewal (e.g. ACME/Let's Encrypt).",
                    ))

        except ssl.SSLCertVerificationError as e:
            result.findings.append(Finding(
                check="Certificate Validation Failed",
                severity=Severity.HIGH,
                description="The certificate could not be validated (self-signed, expired, or hostname mismatch).",
                evidence=str(e),
                owasp_category="A02:2021 - Cryptographic Failures",
                remediation="Use a certificate issued by a trusted CA that matches the hostname.",
            ))
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result.error = f"Could not establish TLS connection: {e}"

        return result
