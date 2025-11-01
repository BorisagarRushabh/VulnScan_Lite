# scanners/headers.py
import requests

REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

def check_security_headers(response=None, url=None):
    """
    Accepts a requests.Response object (preferred) or a url string.
    Always returns a dict; never throws.
    """
    try:
        if response is None and url:
            response = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        if response is None:
            return {"error": "No response available"}

        headers = {k: v for k, v in response.headers.items()}
        missing = [h for h in REQUIRED_HEADERS if h not in headers]
        return {"present": list(headers.keys()), "missing": missing}
    except Exception as e:
        return {"error": str(e)}
