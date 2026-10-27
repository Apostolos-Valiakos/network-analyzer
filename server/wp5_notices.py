"""
WP5 alert emitter — XTRUST-6G alert exchange format.

Writes alerts as Zeek Notice::Info-compatible JSON lines (one object per
line, flattened keys like "id.orig_h"), per the WP5 Alert Exchange Format
document. Zeek's own notice.log (produced by the sensor's Zeek process)
covers protocol-level detections; this module lets the analyzer emit its
own findings (anomalous clusters, scan results, unidentified devices) in
the same vocabulary so R13 / WP5 partners can consume one format.

Field mapping follows the WP5 summary:
  ts / note / msg / sub          core classification
  src / dst / p / n              endpoint & numeric context (aggregated alerts)
  uid / id.* / proto             connection context (only when flow-tied)
  peer_descr                     sensor identity, convention: <hostname>-<engine>
  identifier                     dedup key for conceptually-identical repeats

Alerts are appended to WP5_NOTICE_LOG (default: results/wp5_notices.log
next to this file; in the R13 container: /var/log/penm/wp5_notices.log).
Emission is best-effort: failures are logged, never raised.
"""

import json
import logging
import os
import socket
import threading
import time

logger = logging.getLogger(__name__)

_DEFAULT_LOG = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "results", "wp5_notices.log"
)

_lock = threading.Lock()
# Dedup memory: identifier -> last emit timestamp (per process).
_recent: dict = {}
_SUPPRESS_SECONDS = float(os.getenv("WP5_SUPPRESS_SECONDS", "3600"))


def _peer_descr() -> str:
    """Sensor identity per WP5 convention: <component>-<engine>."""
    explicit = os.getenv("WP5_PEER_DESCR")
    if explicit:
        return explicit
    host = os.getenv("NODE_HOSTNAME") or socket.gethostname()
    return f"{host}-penm"


def emit_notice(
    note: str,
    msg: str,
    sub: str = None,
    src: str = None,
    dst: str = None,
    p: int = None,
    n: int = None,
    proto: str = None,
    uid: str = None,
    orig_h: str = None,
    orig_p: int = None,
    resp_h: str = None,
    resp_p: int = None,
    identifier: str = None,
) -> bool:
    """
    Append one Notice::Info JSON line to the WP5 notice log.

    Only populated fields are serialized (WP5: "populate what you have;
    omit what you don't"). When `identifier` is given, repeated emissions
    within WP5_SUPPRESS_SECONDS are skipped (dedup of identical findings).
    Returns True when a line was written.
    """
    try:
        now = time.time()

        if identifier:
            with _lock:
                last = _recent.get(identifier)
                if last is not None and (now - last) < _SUPPRESS_SECONDS:
                    return False
                _recent[identifier] = now

        notice = {"ts": now, "note": note, "msg": msg}
        if sub:
            notice["sub"] = sub
        if uid:
            notice["uid"] = uid
        if orig_h:
            notice["id.orig_h"] = orig_h
        if orig_p is not None:
            notice["id.orig_p"] = int(orig_p)
        if resp_h:
            notice["id.resp_h"] = resp_h
        if resp_p is not None:
            notice["id.resp_p"] = int(resp_p)
        if proto:
            notice["proto"] = proto
        if src:
            notice["src"] = src
        if dst:
            notice["dst"] = dst
        if p is not None:
            notice["p"] = int(p)
        if n is not None:
            notice["n"] = int(n)
        if identifier:
            notice["identifier"] = identifier
        notice["peer_descr"] = _peer_descr()
        notice["actions"] = ["Notice::ACTION_LOG"]
        notice["suppress_for"] = 0.0

        path = os.getenv("WP5_NOTICE_LOG", _DEFAULT_LOG)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with _lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(notice) + "\n")
        return True
    except Exception:
        logger.exception("WP5 notice emission failed (note=%s)", note)
        return False
