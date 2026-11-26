"""
Periodic role snapshots of the live network.

Every SNAPSHOT_INTERVAL_SECONDS (default 300) a background thread:
  1. fetches the last interval of traffic from the sensor (/get-pcap slice),
  2. saves it as RESULTS_OUTPUT_DIR/latest_snapshot.pcap (atomically, trimmed),
     which POST /v1/analyze_live analyses on demand,
  3. runs the role engine on it and stores one RoleSnapshot row per IP,
     which GET /v1/network/roles/latest serves,
  4. deletes snapshot rows older than SNAPSHOT_RETENTION_HOURS (default 168).

SNAPSHOT_ENABLED=false turns it off. Production runs one gunicorn worker, so
there is exactly one scheduler; start_scheduler() is also safe to call twice.
"""
import logging
import os
import threading
import time

import requests

import settings
from models import db, RoleSnapshot
from pcap_repair import trim_incomplete_tail
from role_engine import assess_pcap

logger = logging.getLogger(__name__)

SNAPSHOT_NAME = "latest_snapshot.pcap"
_FETCH_TIMEOUT = 120

_started = False
_start_lock = threading.Lock()


def interval_seconds() -> int:
    return max(60, int(os.getenv("SNAPSHOT_INTERVAL_SECONDS", "300")))


def retention_seconds() -> int:
    return int(float(os.getenv("SNAPSHOT_RETENTION_HOURS", "168")) * 3600)


def enabled() -> bool:
    return os.getenv("SNAPSHOT_ENABLED", "true").strip().lower() not in ("0", "false", "no", "off")


def snapshot_path() -> str:
    return os.path.join(settings.RESULTS_OUTPUT_DIR, SNAPSHOT_NAME)


def fetch_snapshot(window_seconds: int) -> str:
    """Downloads the sensor's slice of the last `window_seconds` into
    latest_snapshot.pcap and returns its path. Raises on any failure."""
    end_time = time.time()
    start_time = end_time - window_seconds
    response = requests.get(
        settings.sensor_url("/get-pcap"),
        params={"start_time": start_time, "end_time": end_time},
        headers=settings.sensor_headers(),
        stream=True,
        timeout=_FETCH_TIMEOUT,
    )
    response.raise_for_status()

    os.makedirs(settings.RESULTS_OUTPUT_DIR, exist_ok=True)
    final = snapshot_path()
    partial = f"{final}.{os.getpid()}.part"
    try:
        with open(partial, "wb") as f:
            for chunk in response.iter_content(chunk_size=1 << 16):
                f.write(chunk)
        trim_incomplete_tail(partial)
        # Atomic, so /v1/analyze_live never reads a half-written file.
        os.replace(partial, final)
    finally:
        if os.path.exists(partial):
            os.remove(partial)
    return final


def store_roles(pcap_path: str, taken_at: float) -> int:
    """Runs the role engine on the snapshot and stores one RoleSnapshot row per
    IP. Returns the number of rows stored."""
    warnings = []
    assessments = assess_pcap(pcap_path, warnings=warnings)
    for message in warnings:
        logger.warning("Role snapshot: %s", message)
    db.session.bulk_save_objects([
        RoleSnapshot(
            ts=taken_at,
            ip_address=ip,
            role=a.role,
            confidence=a.confidence,
            reasoning=a.reasoning,
            source="pcap",
        )
        for ip, a in assessments.items()
    ])
    cutoff = taken_at - retention_seconds()
    RoleSnapshot.query.filter(RoleSnapshot.ts < cutoff).delete(synchronize_session=False)
    db.session.commit()
    return len(assessments)


def run_role_snapshot(app) -> None:
    """One scheduler tick. Never raises: a failed tick is logged and the next
    one tries again."""
    with app.app_context():
        taken_at = time.time()
        try:
            path = fetch_snapshot(interval_seconds())
        except requests.exceptions.RequestException as exc:
            logger.warning("Role snapshot: could not fetch a slice from the sensor: %s", exc)
            return
        except Exception:
            logger.exception("Role snapshot: saving the slice failed")
            return
        try:
            count = store_roles(path, taken_at)
            logger.info("Role snapshot: stored roles for %d IPs", count)
        except Exception:
            db.session.rollback()
            logger.exception("Role snapshot: role assessment failed")


def _loop(app, stop: threading.Event) -> None:
    while not stop.is_set():
        run_role_snapshot(app)
        stop.wait(interval_seconds())


def start_scheduler(app, stop: threading.Event = None):
    """Starts the snapshot thread once per process. Returns the thread, or
    None when disabled or already running."""
    global _started
    if not enabled():
        logger.info("Role snapshots disabled (SNAPSHOT_ENABLED=false)")
        return None
    with _start_lock:
        if _started:
            return None
        _started = True
    thread = threading.Thread(
        target=_loop, args=(app, stop or threading.Event()), name="role-snapshots", daemon=True
    )
    thread.start()
    logger.info("Role snapshots every %d s", interval_seconds())
    return thread
