"""
Live roles from the sensor's DPI windows (Host Files/dpi_agent.py).

The agent sends one window of stage-1 role evidence every DPI_WINDOW_SECONDS
(default 60) to POST /v1/ingest/dpi. For each window this module:
  1. stores it in dpi_evidence_windows (a re-sent window_id is ignored),
  2. remembers the identities IPs stated about themselves (NRF profile type,
     NG/E2 Setup names, PFCP Node ID) in dpi_identities. Setup messages are
     rare, so these count for LIVE_ROLE_IDENTITY_HOURS (default 24),
  3. merges the windows of the last LIVE_ROLE_WINDOW_MINUTES (default 15)
     plus those identities, runs the role engine's rules, and stores one
     RoleSnapshot row per IP with source "dpi" and ts = the window's end,
  4. deletes windows, identities and snapshots older than
     SNAPSHOT_RETENTION_HOURS (default 168, shared with the pcap snapshots).

GET /v1/network/roles/latest serves DPI snapshots while they are fresh
(DPI_FRESH_SECONDS, default 180) and the pcap scheduler's otherwise.
"""
import logging
import os
import time
from typing import Any, Dict, Optional, Tuple

from models import (
    DpiEvidenceWindow,
    DpiIdentity,
    RoleSnapshot,
    db,
    utc_from_timestamp,
    utc_now,
)
from role_engine import resolve_roles
from role_evidence import PcapObservations, _infer_cross_ip

logger = logging.getLogger(__name__)

SOURCE_DPI = "dpi"
SOURCE_PCAP = "pcap"
SOURCES = (SOURCE_PCAP, SOURCE_DPI)

# dpi_identities.kind -> IpEvidence set it fills.
IDENTITY_FIELDS = {
    "nrf_nf_type": "nrf_nf_types",
    "ran_node_name": "ran_node_names",
    "amf_name": "amf_names",
    "e2_node_id": "e2_node_ids",
    "pfcp_node_id": "pfcp_node_ids",
}
# Kinds that keep an IP in the live roles while it is quiet: a registered NF
# is still that NF when it sends nothing for a while. The others only add to
# the reasoning of IPs seen in the rolling window.
STANDALONE_KINDS = {"nrf_nf_type"}

_MAX_WINDOW_SECONDS = 3600
_MAX_VALUE = 160


class BadWindow(ValueError):
    """The request body is not a window the backend can use (HTTP 400)."""


def role_window_seconds() -> float:
    return float(os.getenv("LIVE_ROLE_WINDOW_MINUTES", "15")) * 60


def identity_seconds() -> float:
    return float(os.getenv("LIVE_ROLE_IDENTITY_HOURS", "24")) * 3600


def retention_seconds() -> float:
    return float(os.getenv("SNAPSHOT_RETENTION_HOURS", "168")) * 3600


def fresh_seconds() -> float:
    return float(os.getenv("DPI_FRESH_SECONDS", "180"))


def parse_window(body: Any) -> Tuple[str, float, float, PcapObservations]:
    """Checks a request body; returns (window_id, start, end, observations)."""
    if not isinstance(body, dict):
        raise BadWindow("Expected a JSON object")
    window_id = body.get("window_id")
    if not isinstance(window_id, str) or not 1 <= len(window_id) <= 64:
        raise BadWindow("window_id must be a string of 1-64 characters")
    start, end = body.get("window_start"), body.get("window_end")
    if not all(isinstance(t, (int, float)) and not isinstance(t, bool) for t in (start, end)):
        raise BadWindow("window_start and window_end must be Unix timestamps in seconds")
    if not 0 < end - start <= _MAX_WINDOW_SECONDS:
        raise BadWindow(f"window_end must be after window_start, by at most {_MAX_WINDOW_SECONDS} s")
    observations = body.get("observations")
    if not isinstance(observations, dict):
        raise BadWindow("observations must be a JSON object")
    try:
        obs = PcapObservations.from_dict(observations)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise BadWindow(f"observations are not valid role evidence: {exc}") from exc
    return window_id, float(start), float(end), obs


def ingest(body: Any) -> Dict[str, Any]:
    """Stores one window and the snapshot it completes. Raises BadWindow for
    a bad body; the caller commits nothing on any other exception."""
    window_id, start, end, obs = parse_window(body)
    if DpiEvidenceWindow.query.filter_by(window_id=window_id).first():
        return {"status": "duplicate"}

    for message in obs.warnings:
        logger.warning("DPI window %s: %s", window_id, message)
    end_dt = utc_from_timestamp(end)
    db.session.add(DpiEvidenceWindow(
        window_id=window_id,
        window_start=utc_from_timestamp(start),
        window_end=end_dt,
        received_at=utc_now(),
        payload=body["observations"],
    ))
    _record_identities(obs, end_dt)
    db.session.flush()
    count = _store_snapshot(end)
    _prune(time.time())
    db.session.commit()
    return {"status": "success", "roles": count}


def _record_identities(obs: PcapObservations, seen_at) -> None:
    for ip, evidence in obs.evidence.items():
        for kind, attr in IDENTITY_FIELDS.items():
            for value in getattr(evidence, attr):
                value = value[:_MAX_VALUE]
                row = db.session.get(DpiIdentity, (ip, kind, value))
                if row is None:
                    db.session.add(DpiIdentity(
                        ip=ip, kind=kind, value=value, first_seen=seen_at, last_seen=seen_at
                    ))
                else:
                    row.first_seen = min(row.first_seen, seen_at)
                    row.last_seen = max(row.last_seen, seen_at)


def merged_observations(end: float) -> PcapObservations:
    """The windows ending in (end - LIVE_ROLE_WINDOW_MINUTES, end], plus the
    identities seen in the LIVE_ROLE_IDENTITY_HOURS before end. Stage 2 has
    not run yet."""
    end_dt = utc_from_timestamp(end)
    window_from = utc_from_timestamp(end - role_window_seconds())
    merged = PcapObservations()
    windows = (
        DpiEvidenceWindow.query
        .filter(DpiEvidenceWindow.window_end > window_from, DpiEvidenceWindow.window_end <= end_dt)
        .order_by(DpiEvidenceWindow.window_end)
        .all()
    )
    for window in windows:
        merged.merge(PcapObservations.from_dict(window.payload))

    identity_from = utc_from_timestamp(end - identity_seconds())
    identities = DpiIdentity.query.filter(
        DpiIdentity.last_seen >= identity_from, DpiIdentity.first_seen <= end_dt
    ).all()
    for row in identities:
        attr = IDENTITY_FIELDS.get(row.kind)
        if attr and (row.ip in merged.evidence or row.kind in STANDALONE_KINDS):
            getattr(merged.ev(row.ip), attr).add(row.value)
    return merged


def _store_snapshot(end: float) -> int:
    obs = merged_observations(end)
    _infer_cross_ip(obs)
    assessments = resolve_roles(obs)
    db.session.bulk_save_objects([
        RoleSnapshot(
            ts=end,
            ip_address=ip,
            role=a.role,
            confidence=a.confidence,
            reasoning=a.reasoning,
            source=SOURCE_DPI,
        )
        for ip, a in assessments.items()
    ])
    return len(assessments)


def _prune(now: float) -> None:
    cutoff = now - retention_seconds()
    cutoff_dt = utc_from_timestamp(cutoff)
    DpiEvidenceWindow.query.filter(DpiEvidenceWindow.window_end < cutoff_dt).delete(
        synchronize_session=False
    )
    DpiIdentity.query.filter(DpiIdentity.last_seen < cutoff_dt).delete(synchronize_session=False)
    RoleSnapshot.query.filter(RoleSnapshot.ts < cutoff).delete(synchronize_session=False)


def latest_snapshot(source: Optional[str] = None) -> Tuple[Optional[float], Optional[str]]:
    """(ts, source) of the snapshot GET /v1/network/roles/latest serves.

    With a source, that source's newest snapshot. Without one, the newest DPI
    snapshot while it is fresh, else the newest pcap snapshot, else whatever
    DPI snapshot exists. Returns (None, None) when there is none."""
    def newest(src):
        return db.session.query(db.func.max(RoleSnapshot.ts)).filter(
            RoleSnapshot.source == src
        ).scalar()

    if source:
        ts = newest(source)
        return (ts, source) if ts is not None else (None, None)
    dpi_ts = newest(SOURCE_DPI)
    if dpi_ts is not None and dpi_ts >= time.time() - fresh_seconds():
        return dpi_ts, SOURCE_DPI
    pcap_ts = newest(SOURCE_PCAP)
    if pcap_ts is not None:
        return pcap_ts, SOURCE_PCAP
    if dpi_ts is not None:
        return dpi_ts, SOURCE_DPI
    return None, None
