import logging
import os
import glob
import io
import re
import subprocess
import threading
import xml.etree.ElementTree as ET
from flask import Flask, request, send_file, jsonify

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ─── Configuration ────────────────────────────────────────────────────────────
# Edit this value before deploying to the sensor machine.

# Shared secret — must match SECRET_TOKEN in the backend .env file.
SECRET_TOKEN = os.environ.get("SECRET_TOKEN", "change_me_internal_token")
# ──────────────────────────────────────────────────────────────────────────────

PCAP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generated_pcaps")
os.makedirs(PCAP_DIR, exist_ok=True)

@app.before_request
def check_auth():
    token = request.headers.get("X-Internal-Token")
    if token != SECRET_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

@app.route("/get-pcap", methods=["GET"])
def get_pcap():
    start_time = request.args.get("start_time")
    end_time = request.args.get("end_time")
    headers_only = request.args.get("headers_only", "false").lower() == "true"
    
    pcap_files = glob.glob(f"{PCAP_DIR}/continuous*.pcap")
    if not pcap_files:
        return jsonify({"error": "No PCAPs found on sensor"}), 404

    if not start_time or not end_time:
        latest_pcap = max(pcap_files, key=os.path.getctime)
        return send_file(latest_pcap, as_attachment=True, download_name="latest_full.pcap")

    from datetime import datetime
    start_dt = datetime.utcfromtimestamp(float(start_time)).strftime('%Y-%m-%d %H:%M:%S')
    end_dt = datetime.utcfromtimestamp(float(end_time)).strftime('%Y-%m-%d %H:%M:%S')
    
    out_filename = f"slice_{int(float(start_time))}.pcap"
    merged_filename = f"merged_{int(float(start_time))}.pcap"
    
    try:
        merge_cmd = ["mergecap", "-w", merged_filename] + pcap_files
        subprocess.run(merge_cmd, check=True, capture_output=True, timeout=30)

        cmd = ["editcap", "-A", start_dt, "-B", end_dt]
        if headers_only:
            cmd.extend(["-s", "96"])

        cmd.extend([merged_filename, out_filename])
        subprocess.run(cmd, check=True, capture_output=True, timeout=30)

        with open(out_filename, 'rb') as f:
            return_data = io.BytesIO(f.read())

        return send_file(return_data, as_attachment=True, download_name=out_filename)

    except subprocess.TimeoutExpired:
        logger.warning("PCAP slice timed out for start=%s end=%s", start_time, end_time)
        return jsonify({"error": "PCAP slicing timed out"}), 500
    except subprocess.CalledProcessError:
        logger.exception("PCAP slice failed")
        return jsonify({"error": "Slicing failed"}), 500
    except Exception:
        logger.exception("Unexpected error in get_pcap")
        return jsonify({"error": "Internal server error"}), 500
        
    finally:
        if os.path.exists(merged_filename):
            os.remove(merged_filename)
        if os.path.exists(out_filename):
            os.remove(out_filename)

# ── Active probing (Nmap) — matches docs/Deliverable/api_profiling_probing.html ──

_SAFE_TARGET = re.compile(r'^[a-zA-Z0-9.\-/]+$')
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+")

# "fast": Fast Scan (-F)
# "deep": version detection across all open ports (default)
# "vuln": version detection + Vulners NSE script across 10,000 ports
_SCAN_PROFILES = {
    "fast": ["-F"],
    "deep": ["-sV"],
    "vuln": ["-sV", "--script", "vulners", "-p", "1-10000"],
}

_SCAN_TIMEOUT = 1200  # 20 min — vuln scans can take up to ~15 min per the docs

_scan_lock = threading.Lock()
_scan_result = {"status": "idle", "message": "No scan has been dispatched yet.", "results": []}


def _parse_nmap_xml(xml_text):
    results = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return results

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = status_el.get("state") if status_el is not None else "unknown"

        addr_el = host_el.find("address")
        host_ip = addr_el.get("addr") if addr_el is not None else None
        if not host_ip:
            continue

        hostname = None
        hostname_el = host_el.find("hostnames/hostname")
        if hostname_el is not None:
            hostname = hostname_el.get("name")

        ports = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_state_el = port_el.find("state")
                port_state = port_state_el.get("state") if port_state_el is not None else "unknown"
                if port_state != "open":
                    continue

                service_el = port_el.find("service")
                service_name = service_el.get("name", "") if service_el is not None else ""
                product = service_el.get("product", "") if service_el is not None else ""
                version_str = service_el.get("version", "") if service_el is not None else ""
                version = " ".join(v for v in [product, version_str] if v).strip()

                cves = set()
                for script_el in port_el.findall("script"):
                    cves.update(_CVE_PATTERN.findall(script_el.get("output", "")))

                ports.append({
                    "port": int(port_el.get("portid")),
                    "protocol": port_el.get("protocol"),
                    "state": port_state,
                    "service": service_name,
                    "version": version,
                    "cves": sorted(cves),
                })

        results.append({
            "host": host_ip,
            "hostname": hostname,
            "state": state,
            "ports": ports,
        })

    return results


def _run_nmap(target_list, profile):
    global _scan_result
    try:
        cmd = ["nmap", "-oX", "-"] + _SCAN_PROFILES[profile] + target_list
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_SCAN_TIMEOUT)
        results = _parse_nmap_xml(proc.stdout)
        with _scan_lock:
            _scan_result = {"status": "completed", "message": "Scan completed successfully.", "results": results}
    except subprocess.TimeoutExpired:
        with _scan_lock:
            _scan_result = {"status": "error", "message": "Scan timed out.", "results": []}
    except Exception as e:
        with _scan_lock:
            _scan_result = {"status": "error", "message": str(e), "results": []}


@app.route("/run-nmap-async", methods=["POST"])
def run_nmap_async():
    data = request.get_json(silent=True) or {}
    target = data.get("target")
    targets = data.get("targets")
    profile = data.get("profile", "deep")

    if bool(target) == bool(targets):  # exactly one of target/targets must be present
        return jsonify({"status": "error", "message": "Exactly one of 'target' or 'targets' must be present."}), 400

    target_list = [target] if target else targets
    if not isinstance(target_list, list) or not target_list:
        return jsonify({"status": "error", "message": "'targets' must be a non-empty array."}), 400
    for t in target_list:
        if not isinstance(t, str) or not _SAFE_TARGET.match(t):
            return jsonify({"status": "error", "message": f"Invalid target: {t!r}"}), 400

    if profile not in _SCAN_PROFILES:
        return jsonify({"status": "error", "message": f"Invalid profile: {profile!r}"}), 400

    with _scan_lock:
        _scan_result["status"] = "running"
        _scan_result["message"] = "Scan in progress."
        _scan_result["results"] = []

    thread = threading.Thread(target=_run_nmap, args=(target_list, profile), daemon=True)
    thread.start()
    return jsonify({"status": "accepted", "message": "Nmap scan started."}), 202


@app.route("/get-nmap-results", methods=["GET"])
def get_nmap_results():
    with _scan_lock:
        result = dict(_scan_result)
    return jsonify(result), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5005")))
