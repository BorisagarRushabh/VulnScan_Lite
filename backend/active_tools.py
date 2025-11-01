# active_tools.py
"""
Helper utilities for active scanning (safe / read-only / low-impact).

Drop this file into your backend folder so `active_scan.py` can import it.

Functions:
- lookup_cves_for_version(banner)
- detect_waf(resp)
- check_cors(target)
- probe_common_paths(active_jobs, job_id, target)
- discover_params_and_test_redirect(active_jobs, job_id, target)
- tcp_port_probe(host)
- extract_version_from_headers(resp)
- safe_log(active_jobs, job_id, message)

Notes:
- All network operations are conservative and time-limited.
- No active exploitation is performed. Redirect tests use a benign redirect target (https://example.com)
- CVE lookup is a lightweight heuristic stub — replace / extend with OSV/NVD integration where you have API access.
"""

import re
import time
import socket
import requests
from urllib.parse import urlparse, urljoin, parse_qs

# short timeout for probes
DEFAULT_TIMEOUT = 5


def safe_log(active_jobs, job_id, message):
    """Append message to active_jobs[job_id]['logs'] if present, and print for server logs."""
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {message}"
    try:
        if active_jobs is not None and job_id in active_jobs:
            active_jobs[job_id].setdefault("logs", []).append(line)
    except Exception:
        pass
    try:
        print(line)
    except Exception:
        pass


def extract_version_from_headers(resp):
    """
    Returns a banner string if detected in headers (e.g. "Apache/2.4.49" or "nginx/1.18.0"),
    or None if not found.
    """
    if resp is None:
        return None
    try:
        headers = resp.headers
    except Exception:
        return None

    header_candidates = []
    for h in ("server", "x-powered-by", "via"):
        v = headers.get(h)
        if v:
            header_candidates.append(v)

    if not header_candidates:
        return None

    # simple heuristic: look for product/version tokens like name/x.y.z or name x.y.z
    token_re = re.compile(r"([A-Za-z0-9_\-\.]+)/\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)")
    for candidate in header_candidates:
        m = token_re.search(candidate)
        if m:
            # return first sensible token
            prod = m.group(0)
            return prod
    # fallback: return the full server header if nothing parsed
    return header_candidates[0]


def lookup_cves_for_version(banner):
    """
    Lightweight heuristic CVE lookup.
    This deliberately does NOT perform heavy queries or require keys.
    It attempts to parse well-known banner patterns and returns a list of dicts
    representing matched CVEs (empty list by default).

    Extend this to call OSV/NVD APIs when you have API access.

    Example:
        banner = "Apache/2.4.49"
        -> returns example CVE list for 2.4.49 (demo only)
    """
    if not banner:
        return []

    banner = banner.strip()
    # naive parse
    m = re.search(r"([A-Za-z\-]+)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", banner)
    if not m:
        return []

    prod = m.group(1).lower()
    ver = m.group(2)

    # small demo mapping (NOT comprehensive). Replace with OSV/NVD integration.
    demo_db = {
        ("apache", "2.4.49"): [
            {
                "id": "CVE-2021-41773",
                "summary": "Path traversal and remote code execution in Apache HTTP Server 2.4.49",
                "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
            }
        ],
    }

    key = (prod, ver)
    return demo_db.get(key, [])


def detect_waf(resp):
    """
    Basic WAF fingerprinting using headers and common blocking phrases.
    Returns dict: { name: <string> or None, evidence: <list of strings> }.
    Non-intrusive: only examines response content/headers.
    """
    out = {"name": None, "evidence": []}
    if resp is None:
        return out
    try:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text or ""
    except Exception:
        return out

    # Header-based hints
    if "server" in headers and "cloudflare" in headers["server"].lower():
        out["name"] = "Cloudflare"
        out["evidence"].append("Server header contains Cloudflare")
    if "cf-ray" in headers:
        out["name"] = out["name"] or "Cloudflare"
        out["evidence"].append("cf-ray header present")
    if "x-amzn-trace-id" in headers or "x-amz-cf-id" in headers:
        out["name"] = out["name"] or "AWS/Akamai"
        out["evidence"].append("AWS/Akamai tracing header present")
    if "x-mod-security" in headers or "mod_security" in body.lower() or "mod_security" in str(headers):
        out["name"] = out["name"] or "ModSecurity"
        out["evidence"].append("ModSecurity signatures in headers/body")

    # Body-based signatures
    lower = body.lower()
    if "request has been blocked" in lower or "access denied" in lower and not out["name"]:
        out["evidence"].append("Blocking text in response body")
        out["name"] = out["name"] or "Unknown WAF"

    # If no clear evidence, return None name but maybe evidence list empty
    return out


def check_cors(target):
    """
    Safe CORS check: sends a GET with a cross-origin like header and inspects
    Access-Control-* headers. Does not send credentials.
    Returns a dict with the important headers and a quick assessment.
    """
    if not target:
        return {"ok": False, "error": "no target"}

    headers = {"Origin": "https://evil.example", "User-Agent": "VulnScanLite/1.0"}
    try:
        r = requests.get(target, headers=headers, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
    except Exception as e:
        return {"ok": False, "error": f"request failed: {e}"}

    acao = r.headers.get("Access-Control-Allow-Origin")
    acac = r.headers.get("Access-Control-Allow-Credentials")
    acah = r.headers.get("Access-Control-Allow-Headers")
    acam = r.headers.get("Access-Control-Allow-Methods")

    assessment = []
    if not acao:
        assessment.append("No Access-Control-Allow-Origin header")
    else:
        if acao == "*":
            assessment.append("Wildcard origin (Access-Control-Allow-Origin: *)")
        elif "evil.example" in acao:
            assessment.append("Reflected Origin allowed")
    if acac and acac.lower() == "true" and acao == "*":
        assessment.append("Credentials allowed with wildcard origin (unsafe)")

    return {
        "ok": True,
        "status_code": r.status_code,
        "headers": {
            "Access-Control-Allow-Origin": acao,
            "Access-Control-Allow-Credentials": acac,
            "Access-Control-Allow-Headers": acah,
            "Access-Control-Allow-Methods": acam,
        },
        "assessment": assessment,
    }


def probe_common_paths(active_jobs, job_id, target):
    """
    Minimal Nikto-like probes: checks a short curated list of paths.
    Returns list of found paths (dicts with path and status).
    """

    safe_log(active_jobs, job_id, "Starting small path probe")
    common_paths = ["/robots.txt", "/admin/", "/login", "/.git/", "/.env", "/backup.zip", "/server-status"]
    found = []
    for path in common_paths:
        url = target.rstrip("/") + path
        try:
            r = requests.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            if r.status_code < 400:
                found.append({"path": path, "status": r.status_code})
                safe_log(active_jobs, job_id, f"Found accessible path: {path} ({r.status_code})")
            # be polite (tiny pause)
            time.sleep(0.12)
        except Exception as e:
            safe_log(active_jobs, job_id, f"Probe failed {path}: {e}")
            continue
    safe_log(active_jobs, job_id, "Path probe finished")
    return found


def discover_params_and_test_redirect(active_jobs, job_id, target):
    """
    Find query-parameter bearing links and forms (basic), then test a benign redirect value
    for open-redirect vulnerabilities. Does NOT follow redirects.
    Returns list of {url, param, status, location, possible_open_redirect_bool}
    """
    results = []
    try:
        r = requests.get(target, timeout=DEFAULT_TIMEOUT, headers={"User-Agent": "VulnScanLite/1.0"})
        body = r.text or ""
    except Exception as e:
        safe_log(active_jobs, job_id, f"Failed to fetch target for redirect discovery: {e}")
        return results

    # find hrefs with query string
    hrefs = set(re.findall(r'href=["\']([^"\']+\?[^"\']+)["\']', body, flags=re.IGNORECASE))
    # also check forms action
    forms = set(re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', body, flags=re.IGNORECASE))

    candidates = list(hrefs | forms)
    safe_log(active_jobs, job_id, f"Found {len(candidates)} candidate URLs to test for redirect parameters")

    TEST_REDIRECT = "https://example.com/"

    for c in candidates[:30]:  # limit number to avoid noise
        try:
            parsed = urlparse(c)
            qs = parsed.query
            if not qs:
                continue
            params = parse_qs(qs)
            # test each parameter by replacing it with TEST_REDIRECT, send request but do not follow
            for p in list(params.keys())[:3]:  # test up to first 3 params
                test_qs = "&".join(f"{k}={TEST_REDIRECT}" if k == p else f"{k}=" + ",".join(vals) for k, vals in params.items())
                test_url = urljoin(target, parsed.path) + "?" + test_qs
                try:
                    rt = requests.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                    location = rt.headers.get("Location") or rt.headers.get("location")
                    possible = False
                    if location and TEST_REDIRECT in location:
                        possible = True
                        safe_log(active_jobs, job_id, f"Possible open-redirect via {c} param {p} -> {location}")
                    results.append({
                        "candidate": c,
                        "param": p,
                        "status": rt.status_code,
                        "location": location,
                        "possible_open_redirect": possible
                    })
                except Exception as e:
                    safe_log(active_jobs, job_id, f"Redirect test failed for {c}: {e}")
                time.sleep(0.08)
        except Exception:
            continue

    return results


def tcp_port_probe(host, ports=None, timeout=0.6):
    """
    Lightweight TCP connect probe for common ports.
    Returns list of open ports (port numbers).
    Non-intrusive and short timeout.
    """
    if not host:
        return []

    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 6379, 8080, 8443]

    open_ports = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, p))
            open_ports.append(p)
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
    return open_ports
