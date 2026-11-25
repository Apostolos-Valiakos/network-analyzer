"""Continuous monitoring: Zeek ingest, statistics, exports and sensor pcaps."""
import csv
import glob
import io
import json
import logging
import os
import time
from datetime import timezone

import requests
from flasgger import swag_from
from flask import Blueprint, Response, jsonify, request
from flask_jwt_extended import jwt_required
from psycopg2.extras import execute_values

import live_roles
import settings
from extensions import limiter, socketio
from models import db, FlowStatistic, RoleSnapshot, utc_from_timestamp, utc_now
from Preprocess import run_ip_role_pipeline
from settings import RESULTS_OUTPUT_DIR, doc

logger = logging.getLogger(__name__)

bp = Blueprint("monitoring", __name__)


def generate_csv_response(data_list, filename):
    """Converts a list of dicts to a CSV Flask response."""
    if not data_list:
        return "No data available", 200, {"Content-Type": "text/plain"}

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=data_list[0].keys())
    writer.writeheader()
    writer.writerows(data_list)

    return (
        output.getvalue(),
        200,
        {
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "text/csv",
        },
    )


ABNORMAL_BYTES_THRESHOLD = 5_000_000  # 5 MB in a single flow


ABNORMAL_PKTS_THRESHOLD = 5_000  # packets in a single flow


def flow_alert(src_ip, dst_ip, orig_bytes, orig_pkts, conn_state):
    """The network_alert payload for one Zeek flow, or None. First match wins."""
    if orig_bytes > ABNORMAL_BYTES_THRESHOLD:
        return {
            "level": "error",
            "title": "Massive Data Transfer",
            "message": f"IP {src_ip} sent {(orig_bytes/1024/1024):.2f} MB to {dst_ip}.",
        }
    if orig_pkts > ABNORMAL_PKTS_THRESHOLD:
        return {
            "level": "warning",
            "title": "Packet Flood Detected",
            "message": f"IP {src_ip} sent {orig_pkts} packets to {dst_ip}.",
        }
    if conn_state == "REJ":
        return {
            "level": "warning",
            "title": "Connection Rejected",
            "message": f"{src_ip} attempted to connect to a closed port on {dst_ip}.",
        }
    return None


def flow_to_zeek(row):
    """A flow_statistics row with Zeek's dotted field names."""
    return {
        # Stored as naive UTC (see ingest_zeek); mark it UTC so .timestamp()
        # gives the real epoch instead of reading it as server-local time.
        "ts": row.ts.replace(tzinfo=timezone.utc).timestamp(),  # float for ECharts
        "id.orig_h": row.id_orig_h,
        "id.resp_h": row.id_resp_h,
        "proto": row.proto,
        "conn_state": row.conn_state,
        "orig_bytes": row.orig_bytes,
        "resp_bytes": row.resp_bytes,
        "orig_pkts": row.orig_pkts,
        "resp_pkts": row.resp_pkts,
    }


def proxy_sensor_pcap(params, download_name):
    """Streams a pcap from the sensor's /get-pcap with the usual error mapping.

    download_name may be a callable; it is evaluated only after the sensor
    answers 200, matching the original routes' order of evaluation.
    """
    try:
        vm_response = requests.get(
            settings.sensor_url("/get-pcap"),
            params=params,
            headers=settings.sensor_headers(),
            stream=True,
            timeout=10,
        )
        if vm_response.status_code != 200:
            return jsonify({"error": "Failed to retrieve PCAP from sensor"}), 502
        name = download_name() if callable(download_name) else download_name
        return Response(
            vm_response.iter_content(chunk_size=1024),
            content_type="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": f"attachment; filename={name}"},
        )
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Sensor is unreachable"}), 503
    except requests.exceptions.Timeout:
        return jsonify({"error": "Sensor request timed out"}), 504


@bp.route("/v1/ingest/zeek", methods=["POST"])
@limiter.exempt
@swag_from(doc("ingest_zeek.yml"))
def ingest_zeek():
    """Receives JSON flow batches from the VM Zeek Agent."""
    if not settings.token_matches(request.headers.get("X-Internal-Token")):
        return jsonify({"error": "Unauthorized"}), 401

    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("flows", []), list):
        return jsonify({"error": 'Expected a JSON object with a "flows" list'}), 400
    flows = body.get("flows", [])
    if not flows:
        return jsonify({"status": "empty"}), 200

    conn = None
    try:
        conn = db.engine.raw_connection()
        cursor = conn.cursor()
        batch = []

        for data in flows:
            raw_ts = data.get("ts")
            # Standardize to UTC for DB storage
            dt_ts = utc_from_timestamp(raw_ts) if raw_ts else utc_now()

            orig_bytes = data.get("orig_bytes", 0)
            orig_pkts = data.get("orig_pkts", 0)
            src_ip = data.get("id.orig_h")
            dst_ip = data.get("id.resp_h")
            conn_state = data.get("conn_state")

            alert = flow_alert(src_ip, dst_ip, orig_bytes, orig_pkts, conn_state)
            if alert:
                socketio.emit("network_alert", alert)

            batch.append(
                (
                    dt_ts,
                    data.get("uid"),
                    src_ip,  # Reusing extracted variable
                    dst_ip,  # Reusing extracted variable
                    data.get("proto"),
                    conn_state,  # Reusing extracted variable
                    orig_bytes,  # Reusing extracted variable
                    data.get("resp_bytes", 0),
                    orig_pkts,  # Reusing extracted variable
                    data.get("resp_pkts", 0),
                )
            )

        insert_query = """
            INSERT INTO flow_statistics 
            (ts, uid, id_orig_h, id_resp_h, proto, conn_state, orig_bytes, resp_bytes, orig_pkts, resp_pkts) 
            VALUES %s ON CONFLICT DO NOTHING;
        """
        # FIXED: Removed duplicate execute_values call
        execute_values(cursor, insert_query, batch)
        conn.commit()

        socketio.emit("new_network_data", flows)

        return jsonify({"status": "success", "inserted": len(batch)}), 200
    except Exception as e:
        logger.exception("ingest_zeek failed")
        if conn:
            conn.rollback()
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if conn:
            conn.close()


@bp.route("/v1/ingest/dpi", methods=["POST"])
@limiter.exempt
@swag_from(doc("ingest_dpi.yml"))
def ingest_dpi():
    """Receives one window of role evidence from the sensor's dpi_agent."""
    if not settings.token_matches(request.headers.get("X-Internal-Token")):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        result = live_roles.ingest(request.get_json(silent=True))
    except live_roles.BadWindow as exc:
        db.session.rollback()
        return jsonify({"error": str(exc)}), 400
    except Exception:
        db.session.rollback()
        logger.exception("ingest_dpi failed")
        return jsonify({"error": "Internal server error"}), 500
    return jsonify(result), 200


_BAD_TIME_PARAMS = (
    "start_time and end_time must be Unix timestamps in seconds, and limit an integer"
)


@bp.route("/v1/network/statistics", methods=["GET"])
@jwt_required()
@swag_from(doc("get_network_statistics.yml"))
def get_network_statistics():
    """Endpoint 1: Get Network Statistics (Grafana/Zeek Aligned)"""
    try:
        raw_start = float(request.args.get("start_time", 0))
        # time.time() is the real epoch; utcnow().timestamp() reads the naive UTC
        # value as local time and lands hours in the past on non-UTC hosts.
        raw_end = float(request.args.get("end_time", time.time()))
        limit = int(request.args.get("limit", 1000))
        start_dt = utc_from_timestamp(raw_start)
        end_dt = utc_from_timestamp(raw_end)
    except (ValueError, OverflowError, OSError):
        return jsonify({"error": _BAD_TIME_PARAMS}), 400
    resp_format = request.args.get("format", "csv").lower()
    if not (1 <= limit <= 10000):
        return jsonify({"error": "limit must be between 1 and 10000"}), 400

    try:
        query = (
            FlowStatistic.query.filter(
                FlowStatistic.ts >= start_dt, FlowStatistic.ts <= end_dt
            )
            .order_by(FlowStatistic.ts.desc())
            .limit(limit)
            .all()
        )

        results = [flow_to_zeek(row) for row in query]

        if resp_format == "json":
            return jsonify(results), 200
        return generate_csv_response(results, "network_statistics.csv")

    except Exception:
        logger.exception("get_network_statistics failed")
        return jsonify({"error": "Internal server error"}), 500


@bp.route("/v1/network/roles/latest", methods=["GET"])
@jwt_required()
@swag_from(doc("get_latest_roles.yml"))
def get_latest_roles():
    """Endpoint 2: Get Latest Role Snapshot"""
    try:
        limit = int(request.args.get("limit", 1000))
    except ValueError:
        return jsonify({"error": "limit must be an integer between 1 and 10000"}), 400
    resp_format = request.args.get("format", "csv").lower()
    if not (1 <= limit <= 10000):
        return jsonify({"error": "limit must be between 1 and 10000"}), 400
    source = request.args.get("source") or None
    if source is not None and source not in live_roles.SOURCES:
        return jsonify({"error": "source must be pcap or dpi"}), 400

    try:
        latest_ts, source = live_roles.latest_snapshot(source)

        if latest_ts is None:
            if resp_format == "json":
                return jsonify([]), 200
            return generate_csv_response([], "latest_roles.csv")

        query = (
            RoleSnapshot.query.filter_by(ts=latest_ts, source=source).limit(limit).all()
        )

        results = []
        for row in query:
            results.append(
                {
                    "ts": row.ts,
                    "id.orig_h": row.ip_address,
                    "role": row.role,
                    "confidence": row.confidence,
                    "reasoning": row.reasoning,
                    "source": row.source,
                }
            )


        if resp_format == "json":
            return jsonify(results), 200
        return generate_csv_response(results, "latest_roles.csv")

    except Exception as e:
        logger.exception("get_latest_roles failed")
        return jsonify({"error": "Internal server error"}), 500


@bp.route("/v1/network/pcap/headers", methods=["GET"])
@jwt_required()
@swag_from(doc("get_pcap_headers.yml"))
def get_pcap_headers_only():
    """Endpoint 3: Get Timeframe PCAP (Headers Only / No Payload)"""
    start_time = request.args.get("start_time")
    end_time = request.args.get("end_time")
    return proxy_sensor_pcap(
        {"start_time": start_time, "end_time": end_time, "headers_only": "true"},
        lambda: f"headers_{int(float(start_time))}.pcap",
    )


@bp.route("/v1/network/pcap/latest/full", methods=["GET"])
@jwt_required()
@swag_from(doc("get_latest_full_pcap.yml"))
def get_latest_full_pcap():
    """Endpoint 4: Get Full Payload PCAP (Latest Snapshot)"""
    return proxy_sensor_pcap(None, "latest_full.pcap")


@bp.route("/v1/network/export", methods=["GET"])
@jwt_required()
@swag_from(doc("export_network_statistics.yml"))
def export_network_statistics():
    """Endpoint 5: Export Analytics Data (CSV/JSON) with Zeek dot notation"""
    try:
        raw_start = float(request.args.get("start_time", 0))
        raw_end = float(request.args.get("end_time", time.time()))  # see get_network_statistics
        limit_arg = request.args.get("limit")
        limit = int(limit_arg) if limit_arg and limit_arg.strip() else None
        start_dt = utc_from_timestamp(raw_start)
        end_dt = utc_from_timestamp(raw_end)
    except (ValueError, OverflowError, OSError):
        return jsonify({"error": _BAD_TIME_PARAMS}), 400
    resp_format = request.args.get("format", "csv").lower()
    if limit is not None and not (1 <= limit <= 10000):
        return jsonify({"error": "limit must be between 1 and 10000"}), 400

    try:
        query = FlowStatistic.query.filter(
            FlowStatistic.ts >= start_dt, FlowStatistic.ts <= end_dt
        ).order_by(FlowStatistic.ts.desc())

        if limit:
            query = query.limit(limit)

        records = query.all()

        # 2. Map to strict Zeek field names, plus the concatenated IP pair
        results = [
            {**flow_to_zeek(row), "conversations": f"{row.id_orig_h} <-> {row.id_resp_h}"}
            for row in records
        ]

        filename = f"network_analytics_{int(raw_start)}_{int(raw_end)}"

        # 3. Return JSON Download
        if resp_format == "json":
            return Response(
                json.dumps(results, indent=2),
                mimetype="application/json",
                headers={
                    "Content-Disposition": f"attachment; filename={filename}.json"
                },
            )

        # 4. Return CSV Download (Dictionary keys automatically become dot-notation headers)
        return generate_csv_response(results, f"{filename}.csv")

    except Exception:
        logger.exception("export_network_statistics failed")
        return jsonify({"error": "Internal server error"}), 500


@bp.route("/v1/analyze_live", methods=["POST"])
@jwt_required()
@limiter.limit("5 per minute")
def analyze_live():
    """Analyses the latest live snapshot (latest_snapshot.pcap, refreshed by
    the snapshot scheduler every SNAPSHOT_INTERVAL_SECONDS)."""
    list_of_files = glob.glob(os.path.join(RESULTS_OUTPUT_DIR, "*.pcap"))
    if not list_of_files:
        return (
            jsonify(
                {
                    "message": "No live snapshot yet. The backend fetches one from the "
                    "sensor every few minutes; check that the sensor is reachable "
                    "(SENSOR_URL) and that SNAPSHOT_ENABLED is not false."
                }
            ),
            404,
        )

    latest_file = max(list_of_files, key=os.path.getctime)

    try:
        # Run pipeline with an empty list for selected_ips (analyzes all)
        model_name = os.path.splitext(os.path.basename(latest_file))[0]

        results = run_ip_role_pipeline(latest_file, model_name, selected_ips=None)

        # WP5: unidentified devices on the live network are worth an alert
        try:
            from wp5_notices import emit_notice

            for ip, role in (results.get("ip_roles") or {}).items():
                if role == "Unidentified":
                    emit_notice(
                        note="PENM::Unidentified_Device",
                        msg=f"Device {ip} is active on the network but matches no known 5G/O-RAN role",
                        sub=os.path.basename(latest_file),
                        src=ip,
                        identifier=f"unidentified-device:{ip}",
                    )
        except Exception:
            logger.exception("WP5 notice emission failed in analyze_live")

        # The snapshot stays: the scheduler replaces it on its next run.
        return jsonify(results), 200

    except Exception:
        logger.exception("analyze_live failed")
        return jsonify({"message": "Internal server error"}), 500
