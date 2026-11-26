"""
The IP role pipeline: runs the role engine on a capture in a child process
(so a hung tshark can be killed after 600 s) and writes the role summary that
/save_roles serves.
"""
import csv
import json
import logging
import multiprocessing as mp
import os
import subprocess
import time

import numpy as np

import packet_table
import settings
from db_setup import database_only_app
from role_engine import get_or_compute_roles, roles_as_strings

logger = logging.getLogger(__name__)


def _pipeline_worker(pcap_file_path, model_name, result_queue, selected_ips=None):
    """
    Worker process to run the analysis in the background without blocking Flask.
    """
    try:
        with database_only_app().app_context():
            start_time = time.time()

            # 1. Make sure tshark can read the capture. The role engine treats
            # an unreadable capture as "no evidence", which would look like a
            # successful run with no roles.
            try:
                packet_table.ensure(pcap_file_path)
            except (OSError, subprocess.SubprocessError, RuntimeError) as e:
                result_queue.put(
                    {"status": "failed", "message": f"Failed to load packets: {e}"}
                )
                return

            # 2. Roles from the evidence-based rule engine. `warnings` collects
            # user-safe messages when the capture could not be read completely.
            logger.info("Loading roles for %s", pcap_file_path)
            warnings = []
            assessments = get_or_compute_roles(pcap_file_path, warnings=warnings)
            ip_roles = roles_as_strings(assessments)

            # Filter if user selected specific IPs
            if selected_ips:
                ip_roles = {k: v for k, v in ip_roles.items() if k in selected_ips}

            # 3. Generate Summary Report
            summary = []
            u_roles, counts = np.unique(list(ip_roles.values()), return_counts=True)
            for r, c in zip(u_roles, counts):
                summary.append(
                    {
                        "class_name": r,
                        "count": int(c),
                        "ips": [ip for ip, role in ip_roles.items() if role == r],
                    }
                )

            # Save result for /save_roles (?type=json|csv), which reads
            # settings.RESULTS_OUTPUT_DIR
            results_dir = settings.RESULTS_OUTPUT_DIR
            os.makedirs(results_dir, exist_ok=True)
            base = os.path.splitext(os.path.basename(pcap_file_path))[0]
            with open(os.path.join(results_dir, f"{base}.json"), "w") as f:
                json.dump(summary, f, indent=4)
            with open(os.path.join(results_dir, f"{base}.csv"), "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["class_name", "count", "ips"])
                for row in summary:
                    writer.writerow([row["class_name"], row["count"], ";".join(row["ips"])])

            most_frequent_class = (
                max(summary, key=lambda x: x["count"])["class_name"]
                if summary
                else None
            )

            report = {
                "status": "success",
                "total_classified": len(ip_roles),
                "most_frequent_class": most_frequent_class,
                "processing_time": round(time.time() - start_time, 2),
                "rule_based_classification_summary": summary,
                "ip_roles": ip_roles,
                "ip_role_details": {
                    ip: {
                        "role": a.role,
                        "confidence": a.confidence,
                        "reasoning": a.reasoning,
                    }
                    for ip, a in assessments.items()
                    if ip in ip_roles
                },
            }
            # Only present when something went wrong, so normal reports keep
            # their exact shape.
            if warnings:
                report["warnings"] = warnings
            result_queue.put(report)
    except Exception as e:
        logger.exception("Role pipeline failed for %s", pcap_file_path)
        result_queue.put({"status": "failed", "message": str(e)})


def _run_pipeline_blocking(pcap_file_path, model_name, selected_ips=None):
    """Blocking subprocess wrapper — must be called from a real OS thread."""
    queue = mp.Queue()
    process = mp.Process(
        target=_pipeline_worker, args=(pcap_file_path, model_name, queue, selected_ips)
    )
    process.start()
    try:
        result = queue.get(timeout=600)
        process.join(timeout=5)
        return result
    except mp.queues.Empty:
        process.terminate()
        process.join(timeout=5)
        return {"status": "failed", "message": "Pipeline Timeout"}


def run_ip_role_pipeline(pcap_file_path, model_name, selected_ips=None):
    """
    Entry point for the routes. Socket.IO runs in threading mode, so blocking
    this request thread while the child process works affects no other request.

    `model_name` is accepted for API compatibility and ignored: roles come only
    from the rule engine (role_engine.py).
    """
    return _run_pipeline_blocking(pcap_file_path, model_name, selected_ips)
