# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from threading import Thread
import uuid
import requests
import time
from urllib.parse import urlparse

# Passive scanning modules
from scanners.headers import check_security_headers
from scanners.ssl_check import check_ssl
from scanners.cookies import check_cookie_flags
from scanners.cms_detection import detect_cms

# Active scanning blueprint
from active_scan import active_scan_bp  # correct import

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Register active scan blueprint under /active prefix
app.register_blueprint(active_scan_bp, url_prefix="/active")

# Passive scan jobs
jobs = {}

# ----------------------- Error Handlers -----------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"ok": False, "error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"ok": False, "error": "Internal Server Error"}), 500

# ----------------------- Utilities -----------------------
def safe_parse_url(raw_url):
    """Normalize URL, add https:// if missing"""
    if not raw_url:
        return None
    parsed = urlparse(raw_url)
    if not parsed.scheme:
        raw_url = "https://" + raw_url
        parsed = urlparse(raw_url)
    if not parsed.hostname:
        return None
    return parsed.geturl()

def log_job(job_id, message):
    ts = time.strftime('%H:%M:%S')
    if job_id in jobs:
        jobs[job_id]["logs"].append(f"[{ts}] {message}")
    print(f"[{ts}] job={job_id} {message}")

# ----------------------- Passive Scan Routes -----------------------
@app.route("/scan", methods=["POST"])
def start_scan():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"ok": False, "error": "Missing URL"}), 400

    raw_url = data["url"]
    url = safe_parse_url(raw_url)
    if not url:
        return jsonify({"ok": False, "error": "Invalid URL"}), 400

    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "queued", "result": None, "error": None, "logs": []}

    def run():
        try:
            jobs[job_id]["status"] = "running"
            log_job(job_id, f"Scan started for {url}")

            # Fetch target HTML
            try:
                resp = requests.get(
                    url,
                    timeout=15,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 VulnScanLite/1.0"}
                )
                html = resp.text or ""
                log_job(job_id, f"Fetched {url} (status {resp.status_code})")
            except Exception as e:
                resp = None
                html = ""
                log_job(job_id, f"Warning: fetch failed: {e}")

            # Headers
            try:
                log_job(job_id, "Running header checks...")
                headers_result = check_security_headers(resp, url)
            except Exception as e:
                headers_result = {"error": str(e)}
                log_job(job_id, f"Header check error: {e}")

            # SSL
            try:
                log_job(job_id, "Checking SSL/TLS...")
                if url.lower().startswith("https://"):
                    ssl_result = check_ssl(url)
                else:
                    ssl_result = {"info": "Not HTTPS — SSL check skipped"}
            except Exception as e:
                ssl_result = {"error": str(e)}
                log_job(job_id, f"SSL check error: {e}")

            # Cookies
            try:
                log_job(job_id, "Inspecting cookies...")
                cookies_result = check_cookie_flags(resp)
            except Exception as e:
                cookies_result = {"error": str(e)}
                log_job(job_id, f"Cookie check error: {e}")

            # CMS
            try:
                log_job(job_id, "Detecting CMS...")
                cms_result = detect_cms(html, url)
            except Exception as e:
                cms_result = {"error": str(e)}
                log_job(job_id, f"CMS detection error: {e}")

            result = {
                "headers": headers_result,
                "ssl": ssl_result,
                "cookies": cookies_result,
                "cms": cms_result
            }

            jobs[job_id]["result"] = result
            jobs[job_id]["status"] = "finished"
            log_job(job_id, "Scan finished — results ready.")
        except Exception as e:
            jobs[job_id]["status"] = "failed"
            jobs[job_id]["error"] = str(e)
            log_job(job_id, f"Scan failed: {e}")

    Thread(target=run, daemon=True).start()
    return jsonify({"ok": True, "job_id": job_id}), 200

@app.route("/job/<job_id>", methods=["GET"])
def get_job(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"ok": False, "error": "Job not found"}), 404
    return jsonify({"ok": True, "job": job}), 200

# ----------------------- Health Check -----------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"ok": True, "message": "VulnScan Lite backend is live"}), 200

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"ok": True, "status": "running"}), 200

# ----------------------- Run App -----------------------
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=True)
