"""Analysis steps shared by the upload and re-analyze routes."""
import logging
from datetime import datetime
from pathlib import Path

from flask import jsonify

from graph_builder import build_graph_json
from models import db, PcapFile
from packet_table import CACHE_SUFFIX as PACKET_CACHE_SUFFIX
from pcap_analysis import summarize_traffic
from Preprocess import run_ip_role_pipeline
from rrc_utils import FEATURE_CACHE_SUFFIX
from settings import PCAP_GEN_OUTPUT_DIR, UPLOAD_FOLDER

logger = logging.getLogger(__name__)


class AnalysisFailed(Exception):
    """Analysis step failed; the message is safe to show to the user."""


def mark_pcap_error(pcap_id) -> None:
    """Flags a pcap as ERROR after a failed analysis, keeping any earlier result."""
    if not pcap_id:
        return
    try:
        record = db.session.get(PcapFile, pcap_id)
        if record:
            record.status = "ERROR"
            db.session.commit()
    except Exception:
        logger.exception("Could not mark pcap %s as ERROR", pcap_id)
        db.session.rollback()


def run_core_analysis(pcap_path: str, model_name: str, pipeline_label: str) -> dict:
    """Traffic graph + role pipeline, shared by upload and re-analyze.

    Returns the result stored in pcap_files.analysis_result. Raises
    AnalysisFailed with a user-safe message when either step fails.
    """
    analysis_result, err = summarize_traffic(pcap_path)
    if err:
        raise AnalysisFailed(f"Analysis failed: {err}")
    report = run_ip_role_pipeline(pcap_path, model_name)
    if report.get("status") != "success":
        raise AnalysisFailed(f"{pipeline_label} failed: {report.get('message')}")
    return {
        "total_packets": analysis_result["total_packets"],
        "graph": build_graph_json(analysis_result["conversations"]),
        "roles": report.get("ip_roles", {}),
    }


def analysis_error_response(exc: Exception, pcap_id, generic_message: str, log_name: str):
    """Rolls back, marks the pcap ERROR, and returns the 500 response.

    AnalysisFailed messages are shown to the user; anything else is logged
    with its traceback and replaced by generic_message.
    """
    db.session.rollback()
    mark_pcap_error(pcap_id)
    if isinstance(exc, AnalysisFailed):
        logger.error("%s failed: %s", log_name, exc)
        return jsonify({"error": str(exc)}), 500
    logger.exception("%s failed", log_name)
    return jsonify({"error": generic_message}), 500


def cleanup_packet_caches(max_age_seconds: int = 3600) -> None:
    """Deletes stale tshark cache files (.packets.tsv, .features.tsv, legacy
    .packets.json) older than max_age_seconds."""
    now = datetime.now().timestamp()
    for directory in [PCAP_GEN_OUTPUT_DIR, UPLOAD_FOLDER]:
        caches = list(Path(directory).glob("*" + PACKET_CACHE_SUFFIX))
        caches += Path(directory).glob("*" + FEATURE_CACHE_SUFFIX)
        caches += Path(directory).glob("*.packets.json")
        for path in caches:
            try:
                if now - path.stat().st_mtime > max_age_seconds:
                    path.unlink()
                    logger.info("Removed stale tshark cache: %s", path.name)
            except OSError:
                pass
