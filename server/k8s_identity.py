"""
Which Kubernetes pod or Service owned an IP, and when.

The sensor's hubble_agent (Host Files/hubble_agent.py) reads flows from
Hubble Relay and sends a batch every HUBBLE_INTERVAL_SECONDS (default 60) to
POST /v1/ingest/hubble. This module stores them:
  - pod_ip_sightings: time spans during which one pod owned an IP (source
    "hubble", or "k8s-api" from k8s_api_agent's pod lists). A sighting
    of the same pod within SIGHTING_GAP_SECONDS (default 600) of the last one
    extends it; another pod on the IP (an IP reused after a restart) starts a
    new row.
  - service_ip_sightings: the same for Service (ClusterIP) addresses.
  - hubble_flows: flows counted per minute.
Everything older than HUBBLE_RETENTION_HOURS (default 168) is deleted.

at(ip, ts) and during(ip, t0, t1) answer "who was this IP" for role_fusion.
"""
import logging
import os
import time
from typing import Any, Dict, List, Optional

from models import (
    HubbleFlow,
    PodIpSighting,
    ServiceIpSighting,
    db,
    utc_from_timestamp,
)

logger = logging.getLogger(__name__)

_MAX_TEXT = 253
# Where a batch comes from: hubble_agent (flows) or k8s_api_agent (pod lists).
SOURCES = ("hubble", "k8s-api")
_MAX_ITEMS = 50000


class BadBatch(ValueError):
    """The request body is not a batch the backend can use (HTTP 400)."""


def gap_seconds() -> float:
    return float(os.getenv("SIGHTING_GAP_SECONDS", "600"))


def retention_seconds() -> float:
    return float(os.getenv("HUBBLE_RETENTION_HOURS", "168")) * 3600


def slack_seconds() -> float:
    """Sightings are refreshed once per agent interval, so last_seen can lag
    the truth by that much; lookups widen their window by this."""
    return float(os.getenv("SIGHTING_SLACK_SECONDS", "120"))


# ── Ingest ────────────────────────────────────────────────────────────────────


def _text(item: Dict[str, Any], key: str, required: bool = True) -> Optional[str]:
    value = item.get(key)
    if value is None or value == "":
        if required:
            raise BadBatch(f"{key} is required")
        return None
    if not isinstance(value, str):
        raise BadBatch(f"{key} must be a string")
    return value[:_MAX_TEXT]


def _time(item: Dict[str, Any], key: str) -> float:
    value = item.get(key)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise BadBatch(f"{key} must be a Unix timestamp in seconds")
    return float(value)


def _list(body: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    items = body.get(key, [])
    if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
        raise BadBatch(f"{key} must be a list of objects")
    if len(items) > _MAX_ITEMS:
        raise BadBatch(f"{key} has more than {_MAX_ITEMS} items")
    return items


def ingest(body: Any) -> Dict[str, Any]:
    """Stores one batch. Raises BadBatch for a bad body; commits only when
    everything was stored."""
    if not isinstance(body, dict):
        raise BadBatch("Expected a JSON object")
    source = body.get("source", "hubble")
    if source not in SOURCES:
        raise BadBatch(f"source must be one of {', '.join(SOURCES)}")
    pods = _parse_pods(_list(body, "sightings"), source)
    services = _parse_services(_list(body, "services"))
    flows = _parse_flows(_list(body, "flows"))

    for sighting in sorted(pods, key=lambda s: s["first_seen"]):
        _merge_pod(sighting)
    for sighting in sorted(services, key=lambda s: s["first_seen"]):
        _merge_service(sighting)
    for flow in flows:
        _add_flow(flow)
    _prune(time.time())
    db.session.commit()
    return {"status": "success", "sightings": len(pods), "services": len(services),
            "flows": len(flows)}


def _span(item):
    first, last = _time(item, "first_seen"), _time(item, "last_seen")
    if last < first:
        raise BadBatch("last_seen must not be before first_seen")
    return utc_from_timestamp(first), utc_from_timestamp(last)


def _parse_pods(items, source):
    out = []
    for item in items:
        first, last = _span(item)
        labels = item.get("labels") or {}
        if not isinstance(labels, dict):
            raise BadBatch("labels must be an object")
        identity = item.get("identity")
        if identity is not None and (not isinstance(identity, int) or isinstance(identity, bool)):
            raise BadBatch("identity must be an integer")
        out.append({
            "ip": _text(item, "ip"),
            "namespace": _text(item, "namespace"),
            "pod": _text(item, "pod"),
            "workload": _text(item, "workload", required=False),
            "workload_kind": (_text(item, "workload_kind", required=False) or None),
            "labels": {str(k)[:_MAX_TEXT]: str(v)[:_MAX_TEXT] for k, v in labels.items()},
            "identity": identity,
            "node": _text(item, "node", required=False),
            "source": source,
            "first_seen": first,
            "last_seen": last,
        })
    return out


def _parse_services(items):
    out = []
    for item in items:
        first, last = _span(item)
        out.append({
            "ip": _text(item, "ip"),
            "namespace": _text(item, "namespace"),
            "service": _text(item, "service"),
            "first_seen": first,
            "last_seen": last,
        })
    return out


def _parse_flows(items):
    out = []
    for item in items:
        port = item.get("dst_port") or 0
        count = item.get("count")
        if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
            raise BadBatch("dst_port must be an integer port")
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise BadBatch("count must be a positive integer")
        out.append({
            "minute": utc_from_timestamp(_time(item, "minute")),
            "src_ip": _text(item, "src_ip"),
            "dst_ip": _text(item, "dst_ip"),
            "dst_port": port,
            "protocol": (_text(item, "protocol", required=False) or "")[:16],
            "verdict": (_text(item, "verdict", required=False) or "")[:16],
            "src_pod": (item.get("src_pod") or "")[:507],
            "dst_pod": (item.get("dst_pod") or "")[:507],
            "count": count,
        })
    return out


def _latest(model, ip):
    return model.query.filter_by(ip=ip).order_by(model.last_seen.desc()).first()


def _merge_pod(s):
    row = _latest(PodIpSighting, s["ip"])
    same = row is not None and (row.namespace, row.pod) == (s["namespace"], s["pod"])
    if same and (s["first_seen"] - row.last_seen).total_seconds() <= gap_seconds():
        row.first_seen = min(row.first_seen, s["first_seen"])
        row.last_seen = max(row.last_seen, s["last_seen"])
        for key in ("workload", "workload_kind", "identity", "node"):
            if s[key] is not None:
                setattr(row, key, s[key])
        if s["labels"]:
            row.labels = s["labels"]
        return
    db.session.add(PodIpSighting(**s))
    db.session.flush()


def _merge_service(s):
    row = _latest(ServiceIpSighting, s["ip"])
    same = row is not None and (row.namespace, row.service) == (s["namespace"], s["service"])
    if same and (s["first_seen"] - row.last_seen).total_seconds() <= gap_seconds():
        row.first_seen = min(row.first_seen, s["first_seen"])
        row.last_seen = max(row.last_seen, s["last_seen"])
        return
    db.session.add(ServiceIpSighting(**s))
    db.session.flush()


def _add_flow(f):
    key = {k: f[k] for k in f if k != "count"}
    row = HubbleFlow.query.filter_by(**key).first()
    if row is None:
        db.session.add(HubbleFlow(**f))
        db.session.flush()
    else:
        row.count += f["count"]


def _prune(now: float) -> None:
    cutoff = utc_from_timestamp(now - retention_seconds())
    PodIpSighting.query.filter(PodIpSighting.last_seen < cutoff).delete(synchronize_session=False)
    ServiceIpSighting.query.filter(ServiceIpSighting.last_seen < cutoff).delete(
        synchronize_session=False
    )
    HubbleFlow.query.filter(HubbleFlow.minute < cutoff).delete(synchronize_session=False)


# ── Lookup ────────────────────────────────────────────────────────────────────


def _overlap(row, t0, t1) -> float:
    start = max(row.first_seen, t0)
    end = min(row.last_seen, t1)
    return (end - start).total_seconds()


def _best(model, ip, t0: float, t1: float):
    """Among the sightings within the slack of [t0, t1], the one overlapping
    [t0, t1] itself the most. A sighting outside it scores minus its
    distance, so for a point in time the span containing it wins over a
    neighbouring one."""
    slack = slack_seconds()
    lo, hi = utc_from_timestamp(t0 - slack), utc_from_timestamp(t1 + slack)
    rows = model.query.filter(
        model.ip == ip, model.first_seen <= hi, model.last_seen >= lo
    ).all()
    if not rows:
        return None
    start, end = utc_from_timestamp(t0), utc_from_timestamp(t1)
    return max(rows, key=lambda r: (_overlap(r, start, end), r.last_seen))


def has_data() -> bool:
    """True once any pod or Service sighting is stored. Without Hubble the
    role results are left exactly as they were."""
    return (
        db.session.query(PodIpSighting.id).first() is not None
        or db.session.query(ServiceIpSighting.id).first() is not None
    )


def during(ip: str, t0: float, t1: float) -> Optional[Dict[str, Any]]:
    """What Kubernetes knew about `ip` between t0 and t1 (epoch seconds): the
    pod that owned it for most of the span, and/or the Service it was the
    address of. None when neither is known."""
    info: Dict[str, Any] = {}
    pod = _best(PodIpSighting, ip, t0, t1)
    if pod is not None:
        info.update({
            "namespace": pod.namespace,
            "pod": pod.pod,
            "workload": pod.workload,
            "workload_kind": pod.workload_kind,
            "node": pod.node,
            "labels": pod.labels or {},
        })
    service = _best(ServiceIpSighting, ip, t0, t1)
    if service is not None:
        info["service"] = f"{service.namespace}/{service.service}"
        info.setdefault("namespace", service.namespace)
    return {k: v for k, v in info.items() if v not in (None, "")} or None


def at(ip: str, ts: float) -> Optional[Dict[str, Any]]:
    return during(ip, ts, ts)
