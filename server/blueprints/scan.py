"""Nmap scans, run by the sensor."""
import ipaddress
import json
import logging
import re

import requests
from flasgger import swag_from
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

import settings
from extensions import limiter
from settings import doc

logger = logging.getLogger(__name__)

bp = Blueprint("scan", __name__)


def _is_safe_scan_param(value: str) -> bool:
    """Returns True only if value is a valid IP, CIDR, or simple hostname.
    Rejects shell metacharacters to prevent command injection."""
    if not isinstance(value, str) or not value:
        return False
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass
    # Allow plain hostnames / simple alphanumeric values; reject shell metacharacters
    return bool(re.match(r"^[a-zA-Z0-9_.\-/]+$", value))


@bp.route("/v1/scan/start", methods=["POST"])
@jwt_required()
@limiter.limit("5 per minute")
@swag_from(doc("start_scan.yml"))
def start_scan():
    data = request.get_json() or {}

    # Validate all string values to block shell metacharacters before they
    # reach the Nmap command constructor on the VM.
    for key, value in data.items():
        if isinstance(value, str) and not _is_safe_scan_param(value):
            logger.warning("start_scan: rejected unsafe param %s=%r", key, value)
            return jsonify({"error": f"Invalid value for parameter '{key}'"}), 400

    try:
        response = requests.post(
            settings.sensor_url("/run-nmap-async"),
            json=data,
            headers=settings.sensor_headers(**{"Content-Type": "application/json"}),
            timeout=10,
        )
        return jsonify(response.json()), response.status_code
    except Exception:
        logger.exception("start_scan: failed to reach VM")
        return jsonify({"error": "Failed to reach VM"}), 500


@bp.route("/v1/scan/results", methods=["GET"])
@jwt_required()
@swag_from(doc("get_scan_results.yml"))
def get_scan_results():
    try:
        response = requests.get(
            settings.sensor_url("/get-nmap-results"), headers=settings.sensor_headers(), timeout=10
        )
        _emit_scan_notice(response)
        return jsonify(response.json()), response.status_code
    except Exception:
        logger.exception("get_scan_results: failed to reach VM")
        return jsonify({"error": "Failed to reach VM"}), 500


def _emit_scan_notice(response):
    """WP5: emit one Notice::Info per completed nmap scan (dedup by results hash).

    This endpoint is polled by the frontend, so the notice is keyed on a
    hash of the scan results — the same finished scan only alerts once.
    Matches the documented /v1/scan/results shape: {status, message, results:
    [{host, hostname, state, ports: [{port, protocol, state, service,
    version, cves}]}]}.
    """
    try:
        result = response.json()
        if result.get("status") != "completed":
            return
        from hashlib import sha256
        from wp5_notices import emit_notice

        hosts = result.get("results") or []
        open_ports = [
            f"{host.get('host')}:{port.get('port')}/{port.get('protocol')} {port.get('service', '')}".strip()
            for host in hosts
            for port in host.get("ports", [])
        ]
        if not open_ports:
            return
        summary = json.dumps(hosts, sort_keys=True)
        emit_notice(
            note="PENM::Service_Scan_Report",
            msg=(
                f"Nmap service inspection completed: {len(open_ports)} open "
                f"port(s) across {len(hosts)} host(s)"
            ),
            sub="; ".join(open_ports[:10]) or None,
            n=len(open_ports),
            identifier=f"nmap-scan:{sha256(summary.encode()).hexdigest()[:16]}",
        )
    except Exception:
        logger.exception("WP5 notice emission failed in get_scan_results")
