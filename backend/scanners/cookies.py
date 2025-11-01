# scanners/cookies.py
def check_cookie_flags(response):
    """
    Returns list of cookies with attributes. If response is None -> empty list.
    Note: requests can only see cookies set via HTTP headers (not JS).
    """
    try:
        if response is None:
            return []
        cookies = response.cookies
        results = []
        for cookie in cookies:
            results.append({
                "name": getattr(cookie, "name", ""),
                "value": getattr(cookie, "value", ""),
                "secure": getattr(cookie, "secure", False),
                "httponly": getattr(cookie, "httponly", False)
            })
        # Fallback: inspect Set-Cookie header if no cookies object entries
        if not results:
            set_cookie = response.headers.get("Set-Cookie")
            if set_cookie:
                parts = [p.strip() for p in set_cookie.split(',') if p.strip()]
                for p in parts:
                    results.append({"raw": p})
        return results
    except Exception as e:
        return {"error": str(e)}
