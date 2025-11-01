import threading
import subprocess
import uuid
import time
import requests
import shutil
import socket
from urllib.parse import urlparse, urljoin
from flask import Blueprint, request, jsonify, current_app

from active_tools import (
    lookup_cves_for_version,
    detect_waf,
    check_cors,
    probe_common_paths,
    discover_params_and_test_redirect,
    tcp_port_probe,
    extract_version_from_headers,
    safe_log
)

active_scan_bp = Blueprint("active_scan", __name__)
active_jobs = {}

ALLOWED_MODULES = {"nmap", "nikto-like", "safe-sqli-xss"}


# ---------- Utility ----------
def log(job_id, message):
    ts = time.strftime('%H:%M:%S')
    line = f"[{ts}] {message}"
    if job_id in active_jobs:
        active_jobs[job_id]["logs"].append(line)
    try:
        current_app.logger.info(f"[{ts}] job={job_id} {message}")
    except RuntimeError:
        pass


def is_tool_installed(name):
    return shutil.which(name) is not None


def normalize_target(raw_url):
    """Ensure valid scheme and fallback to http:// if https fails"""
    if not raw_url:
        return None
    raw_url = raw_url.strip()
    if not raw_url:
        return None

    parsed = urlparse(raw_url)
    if not parsed.scheme:
        raw_url = "http://" + raw_url
        parsed = urlparse(raw_url)

    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.hostname:
        return None

    if parsed.hostname in ("127.0.0.1", "localhost") and parsed.scheme == "https":
        raw_url = raw_url.replace("https://", "http://")

    return raw_url.rstrip("/")


# ---------- Module Runners ----------
def run_nmap_scan(job_id, target):
    log(job_id, f"Starting Nmap scan for {target}")
    if not is_tool_installed("nmap"):
        active_jobs[job_id]["result"]["nmap"] = "skipped: nmap not installed"
        log(job_id, "Nmap not installed — skipping.")
        return

    try:
        result = subprocess.run(
            ["nmap", "-sV", "--top-ports", "50", target],
            capture_output=True,
            text=True,
            timeout=120
        )
        output = result.stdout or result.stderr or "No output"
        active_jobs[job_id]["result"]["nmap"] = output
        log(job_id, "Nmap scan finished.")
    except subprocess.TimeoutExpired:
        active_jobs[job_id]["result"]["nmap"] = "timeout"
        log(job_id, "Nmap scan timed out.")
    except Exception as e:
        active_jobs[job_id]["result"]["nmap"] = f"error: {e}"
        log(job_id, f"Nmap scan error: {e}")


def run_nikto_like_scan(job_id, target):
    log(job_id, f"Starting Nikto-like scan for {target}")
    common_paths = ["/robots.txt", "/admin/", "/.git/", "/.env", "/backup.zip", "/login"]
    found = []
    for path in common_paths:
        url = urljoin(target, path)
        try:
            r = requests.get(url, timeout=6, allow_redirects=True)
            if r.status_code < 400:
                found.append({"path": path, "status": r.status_code})
                log(job_id, f"Accessible path found: {path} ({r.status_code})")
        except Exception as e:
            log(job_id, f"Failed to probe {path}: {e}")
    active_jobs[job_id]["result"]["nikto-like"] = found
    log(job_id, "Nikto-like scan finished.")


def run_safe_sqli_xss(job_id, target):
    log(job_id, "Starting safe SQLi/XSS tests")
    results = {}
    payloads = {
        "sqli": {"param": "id", "payload": "' OR '1'='1"},
        "xss": {"param": "q", "payload": "<script>alert(1)</script>"}
    }

    for key, data in payloads.items():
        try:
            r = requests.get(target, params={data["param"]: data["payload"]}, timeout=6)
            if data["payload"] in r.text:
                results[key] = f"Reflected {key.upper()} payload"
                log(job_id, f"Potential {key.upper()} reflection detected.")
            else:
                results[key] = f"No reflection detected for {key.upper()}"
        except Exception as e:
            results[key] = f"Error: {e}"
            log(job_id, f"{key.upper()} check failed: {e}")

    active_jobs[job_id]["result"]["safe-sqli-xss"] = results
    log(job_id, "SQLi/XSS checks finished.")


# ---------- Worker ----------
def active_scan_worker(job_id, target, modules):
    try:
        active_jobs[job_id]["status"] = "running"
        log(job_id, f"Active scan started for {target}")

        if "nmap" in modules:
            run_nmap_scan(job_id, target)
        if "nikto-like" in modules:
            run_nikto_like_scan(job_id, target)
        if "safe-sqli-xss" in modules:
            run_safe_sqli_xss(job_id, target)

        # Passive/fingerprint checks
        try:
            resp = requests.get(target, timeout=8, headers={"User-Agent": "VulnScanLite/1.0"})
        except Exception:
            resp = None

        active_jobs[job_id]["result"]["waf"] = detect_waf(resp)
        active_jobs[job_id]["result"]["cors"] = check_cors(target)
        active_jobs[job_id]["result"]["dirs"] = probe_common_paths(active_jobs, job_id, target)
        active_jobs[job_id]["result"]["redirects"] = discover_params_and_test_redirect(active_jobs, job_id, target)
        active_jobs[job_id]["result"]["server_banner"] = extract_version_from_headers(resp)

        banner = active_jobs[job_id]["result"].get("server_banner")
        if banner:
            active_jobs[job_id]["result"]["cve_matches"] = lookup_cves_for_version(banner)

        host = urlparse(target).hostname
        if host:
            active_jobs[job_id]["result"]["open_ports"] = tcp_port_probe(host)

        log(job_id, "All selected modules completed.")
        active_jobs[job_id]["status"] = "finished"

    except Exception as e:
        log(job_id, f"Worker crashed: {e}")
        active_jobs[job_id]["status"] = "failed"
        active_jobs[job_id]["result"]["error"] = str(e)


# ---------- Routes ----------
@active_scan_bp.route("/scan", methods=["POST"])
def start_active_scan():
    try:
        data = request.get_json(silent=True) or {}
        url = data.get("url", "").strip()
        modules = data.get("modules", [])
        consent = data.get("consent", False)

        if not consent:
            return jsonify({"ok": False, "error": "Consent required"}), 400

        normalized = normalize_target(url)
        if not normalized:
            return jsonify({"ok": False, "error": "Invalid or unsupported URL"}), 400

        modules = [m for m in modules if m in ALLOWED_MODULES]
        if not modules:
            modules = ["nikto-like", "safe-sqli-xss"]

        job_id = str(uuid.uuid4())
        active_jobs[job_id] = {
            "status": "queued",
            "logs": [],
            "result": {},
            "modules": modules,
            "target": normalized
        }

        t = threading.Thread(target=active_scan_worker, args=(job_id, normalized, modules), daemon=True)
        t.start()

        log(job_id, f"Scan thread started for {normalized} with modules: {modules}")
        return jsonify({"ok": True, "job_id": job_id}), 200

    except Exception as e:
        safe_log(f"/active/scan failed: {e}")
        return jsonify({"ok": False, "error": f"Scan failed: {e}"}), 500


@active_scan_bp.route("/job/<job_id>", methods=["GET"])
def get_active_job(job_id):
    job = active_jobs.get(job_id)
    if not job:
        return jsonify({"ok": False, "error": "Job not found"}), 404
    return jsonify({"ok": True, "job": job}), 200


@active_scan_bp.route("/tools", methods=["GET"])
def get_tools():
    tools = {
        "nmap": is_tool_installed("nmap"),
    }
    return jsonify({"ok": True, "tools": tools}), 200
