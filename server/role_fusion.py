"""
Adds Kubernetes identity (k8s_identity, from Hubble) to role results when
they are read. The traffic decides the role; the pod is only a hint:
  - the pod's hint agrees with the role: confidence + 0.10 (at most 0.99),
    and the reasoning names the pod;
  - it disagrees: the role stays, "k8s_mismatch": true, the reasoning names
    both;
  - the role is "Unidentified": it stays, and "suggested_role" carries the hint;
  - Service addresses and host-network IPs get their identity shown, never a hint.
Each result gets a "k8s" object only when something is known about its IP,
so results without Kubernetes data keep their exact shape.

Hints come from k8s_role_hints.json (pod labels and names -> role).
"""
import json
import logging
import os
import re
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

import k8s_identity

logger = logging.getLogger(__name__)

HINTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "k8s_role_hints.json")
AGREEMENT_BOOST = 0.10
MAX_CONFIDENCE = 0.99
_LABEL_KEYS = ("app.kubernetes.io/component", "app.kubernetes.io/name", "app")
_IDENTITY_KEYS = ("namespace", "pod", "workload", "workload_kind", "service", "node")


@lru_cache(maxsize=1)
def _hints() -> Tuple[Tuple[str, str, frozenset], ...]:
    with open(HINTS_FILE, encoding="utf-8") as f:
        table = json.load(f)["hints"]
    return tuple(
        (h["token"].lower(), h["role"], frozenset([h["role"], *h.get("also", [])]))
        for h in table
    )


def _tokens(text: str) -> List[str]:
    words = re.split(r"[^a-z0-9]+", text.lower())
    return [w.rstrip("0123456789") for w in words if w.rstrip("0123456789")]


def hint_for(info: Dict[str, Any]) -> Optional[Tuple[str, frozenset]]:
    """(role, roles that agree) for a pod, or None when nothing matches."""
    labels = info.get("labels") or {}
    candidates = [labels.get(k) for k in _LABEL_KEYS] + [info.get("workload"), info.get("pod")]
    for candidate in candidates:
        if not candidate:
            continue
        tokens = set(_tokens(candidate))
        for token, role, accepted in _hints():
            if token in tokens:
                return role, accepted
    return None


def annotate(
    entries: Dict[str, Dict[str, Any]],
    t0: float,
    t1: float,
    warnings: Optional[List[str]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Adds "k8s" (and adjusts confidence/reasoning) in place for every
    {ip: {"role", "confidence", "reasoning", ...}} entry, using what
    Kubernetes knew about the IP between t0 and t1 (epoch seconds)."""
    try:
        if not k8s_identity.has_data():
            return entries
    except Exception:
        logger.exception("Kubernetes identity lookup failed")
        if warnings is not None:
            warnings.append("Kubernetes pod information could not be read; roles are shown without it.")
        return entries
    for ip, entry in entries.items():
        try:
            info = k8s_identity.during(ip, t0, t1)
        except Exception:
            logger.exception("Kubernetes identity lookup failed")
            if warnings is not None:
                warnings.append("Kubernetes pod information could not be read; roles are shown without it.")
            return entries
        if info:
            _apply(entry, info)
    return entries


def _apply(entry: Dict[str, Any], info: Dict[str, Any]) -> None:
    k8s = {k: info[k] for k in _IDENTITY_KEYS if info.get(k)}
    hint = hint_for(info) if info.get("pod") else None
    if hint:
        hint_role, accepted = hint
        k8s["hint_role"] = hint_role
        role = entry.get("role")
        where = f"pod {info['namespace']}/{info['pod']}"
        reasoning = entry.get("reasoning") or ""
        if role in accepted:
            confidence = float(entry.get("confidence") or 0.0)
            if confidence > 0:
                entry["confidence"] = round(min(MAX_CONFIDENCE, confidence + AGREEMENT_BOOST), 4)
            entry["reasoning"] = f"{reasoning}; {where} agrees ({hint_role})"
        elif role in (None, "", "Unidentified"):
            k8s["suggested_role"] = hint_role
            entry["reasoning"] = f"{reasoning}; {where} suggests {hint_role}"
        else:
            k8s["k8s_mismatch"] = True
            entry["reasoning"] = f"{reasoning}; {where} suggests {hint_role}, the traffic says {role}"
    entry["k8s"] = k8s


def capture_span(pcap_path: str) -> Optional[Tuple[float, float]]:
    """(first, last) frame time of a capture, from its packet table."""
    import packet_table

    first = last = None
    for (value,) in packet_table.columns(pcap_path, ["frame.time_epoch"]):
        try:
            ts = float(value)
        except ValueError:
            continue
        first = ts if first is None else min(first, ts)
        last = ts if last is None else max(last, ts)
    return (first, last) if first is not None else None


def annotate_capture(
    entries: Dict[str, Dict[str, Any]], pcap_path: str, warnings: Optional[List[str]] = None
) -> Dict[str, Dict[str, Any]]:
    """annotate() over the capture's own time span."""
    try:
        if not k8s_identity.has_data():
            return entries
        span = capture_span(pcap_path)
    except Exception:
        logger.exception("Could not read the capture's time span for Kubernetes identities")
        if warnings is not None:
            warnings.append("Kubernetes pod information is not shown: the capture's time span could not be read.")
        return entries
    if span is None:
        return entries
    return annotate(entries, span[0], span[1], warnings)
