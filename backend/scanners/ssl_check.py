# scanners/ssl_check.py
import ssl
import socket
from urllib.parse import urlparse

def _extract_hostname(url):
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None

def check_ssl(url):
    """
    Returns certificate details or error. Uses a 10s timeout and SNI.
    """
    try:
        hostname = _extract_hostname(url)
        if not hostname:
            return {"error": "Invalid hostname"}

        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = {}
                subject = {}
                for part in cert.get("issuer", []):
                    for k, v in part:
                        issuer[k] = v
                for part in cert.get("subject", []):
                    for k, v in part:
                        subject[k] = v
                return {
                    "issuer": issuer,
                    "subject": subject,
                    "valid_from": cert.get("notBefore"),
                    "valid_to": cert.get("notAfter")
                }
    except Exception as e:
        return {"error": str(e)}
