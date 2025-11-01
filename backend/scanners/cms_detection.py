# scanners/cms_detection.py
from bs4 import BeautifulSoup
from urllib.parse import urlparse

COMMON_CMS_PATHS = {
    "WordPress": ["wp-content", "wp-includes", "xmlrpc.php"],
    "Joomla": ["Joomla!", "index.php?option=com_"],
    "Drupal": ["sites/default", "Drupal.settings"]
}

def detect_cms(html, url=None):
    try:
        if not html:
            return {"cms": "Unknown", "reason": "No HTML retrieved"}

        soup = BeautifulSoup(html, "html.parser")
        meta = soup.find("meta", {"name": "generator"})
        if meta and meta.get("content"):
            return {"cms": meta["content"], "evidence": "meta generator"}

        text = (html or "").lower()
        for cms, patterns in COMMON_CMS_PATHS.items():
            for p in patterns:
                if p.lower() in text:
                    return {"cms": cms, "evidence": p}

        if url:
            parsed = urlparse(url)
            if "wp-" in (parsed.path or "").lower():
                return {"cms": "WordPress", "evidence": parsed.path}

        return {"cms": "Unknown"}
    except Exception as e:
        return {"error": str(e)}
