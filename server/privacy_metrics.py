import hashlib
import ipaddress
import secrets
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple


def _is_empty(value: Any) -> bool:
    return value is None or value == ""


def _to_str(value: Any) -> str:
    return "" if value is None else str(value)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _generalize_value(value: Any) -> Any:
    if _is_empty(value):
        return value

    sval = _to_str(value)
    if _is_ip(sval):
        addr = ipaddress.ip_address(sval)
        if addr.version == 4:
            parts = sval.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return str(addr.exploded[:19] + "::/64")

    if isinstance(value, (int, float)):
        low = int(value // 10) * 10
        high = low + 9
        return f"{low}-{high}"

    if len(sval) <= 3:
        return "*"
    return f"{sval[:3]}*"


def _generalize_ip(value: Any, prefix: int) -> Any:
    if _is_empty(value):
        return value
    sval = _to_str(value)
    if not _is_ip(sval):
        return _generalize_value(value)
    addr = ipaddress.ip_address(sval)
    if addr.version == 4:
        parts = sval.split(".")
        if prefix >= 24:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        if prefix >= 16:
            return f"{parts[0]}.{parts[1]}.0.0/16"
        return f"{parts[0]}.0.0.0/8"
    return str(addr.exploded[:19] + "::/64")


def _generalize_numeric(value: Any, bin_size: int) -> Any:
    if _is_empty(value):
        return value
    try:
        num = float(value)
        low = int(num // bin_size) * bin_size
        high = low + bin_size - 1
        return f"{low}-{high}"
    except (TypeError, ValueError):
        return _generalize_value(value)


def _generalize_text_prefix(value: Any, keep: int) -> Any:
    if _is_empty(value):
        return value
    sval = _to_str(value)
    if len(sval) <= keep:
        return "*" * max(1, len(sval))
    return f"{sval[:keep]}*"


def _generalize_protocol_family(value: Any) -> Any:
    if _is_empty(value):
        return value
    sval = _to_str(value).upper()
    if "SCTP" in sval:
        return "SCTP_FAMILY"
    if "TCP" in sval:
        return "TCP_FAMILY"
    if "UDP" in sval:
        return "UDP_FAMILY"
    if "DNS" in sval or "NTP" in sval:
        return "SERVICE_DISCOVERY"
    return "OTHER_PROTOCOL"


def _apply_generalization_profile(value: Any, profile: str) -> Any:
    if profile == "ip_mask_16":
        return _generalize_ip(value, 16)
    if profile == "ip_mask_24":
        return _generalize_ip(value, 24)
    if profile == "numeric_bins_5":
        return _generalize_numeric(value, 5)
    if profile == "numeric_bins_10":
        return _generalize_numeric(value, 10)
    if profile == "text_prefix_1":
        return _generalize_text_prefix(value, 1)
    if profile == "text_prefix_3":
        return _generalize_text_prefix(value, 3)
    if profile == "protocol_family":
        return _generalize_protocol_family(value)
    return _generalize_value(value)


def _pseudonymize_value(value: Any, salt: str) -> Any:
    if _is_empty(value):
        return value
    digest = hashlib.sha256(f"{salt}:{_to_str(value)}".encode("utf-8")).hexdigest()
    return f"ps_{digest[:12]}"


def apply_transformations(
    records: List[Dict[str, Any]],
    pseudonymize: List[str],
    generalize: List[str],
    suppress: List[str],
    pseudonymization_mode: str = "deterministic",
    generalize_profiles: Optional[Dict[str, str]] = None,
    suppress_thresholds: Optional[Dict[str, int]] = None,
    salt: str = "network-analyzer",
) -> List[Dict[str, Any]]:
    transformed: List[Dict[str, Any]] = []
    pseudo_map: Dict[Tuple[str, str], str] = {}
    generalize_profiles = generalize_profiles or {}
    suppress_thresholds = suppress_thresholds or {}
    run_salt = secrets.token_hex(8) if pseudonymization_mode == "per_run" else ""

    for row in records:
        new_row = dict(row)

        for col in pseudonymize:
            if col in new_row and not _is_empty(new_row[col]):
                pilot_val = _to_str(row.get("pilot")) if "pilot" in row else ""
                if pseudonymization_mode == "per_pilot":
                    key = (col, _to_str(new_row[col]), pilot_val)
                    row_salt = f"{salt}:pilot:{pilot_val}"
                elif pseudonymization_mode == "per_run":
                    key = (col, _to_str(new_row[col]), run_salt)
                    row_salt = f"{salt}:run:{run_salt}"
                else:
                    key = (col, _to_str(new_row[col]))
                    row_salt = salt
                if key not in pseudo_map:
                    pseudo_map[key] = _pseudonymize_value(new_row[col], row_salt)
                new_row[col] = pseudo_map[key]

        for col in generalize:
            if col in new_row:
                profile = generalize_profiles.get(col, "auto")
                new_row[col] = _apply_generalization_profile(new_row[col], profile)

        for col in suppress:
            if col in new_row:
                new_row[col] = "*"

        transformed.append(new_row)

    # Threshold-based suppression on rare values per selected column.
    for col, threshold in suppress_thresholds.items():
        if threshold <= 1:
            continue
        counts = Counter(_to_str(row.get(col)) for row in transformed)
        for row in transformed:
            key = _to_str(row.get(col))
            if counts.get(key, 0) < threshold:
                row[col] = "*"

    return transformed


def _equivalence_groups(
    records: List[Dict[str, Any]], identifiers: List[str]
) -> Dict[Tuple[Any, ...], List[Dict[str, Any]]]:
    groups: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = defaultdict(list)
    if not identifiers:
        groups[("__all__",)] = records
        return groups

    for row in records:
        key = tuple(row.get(attr) for attr in identifiers)
        groups[key].append(row)
    return groups


def _distribution(values: List[Any]) -> Dict[str, float]:
    if not values:
        return {}
    counts = Counter(_to_str(v) for v in values)
    total = sum(counts.values())
    return {k: v / total for k, v in counts.items()}


def _total_variation_distance(a: Dict[str, float], b: Dict[str, float]) -> float:
    keys = set(a.keys()) | set(b.keys())
    return 0.5 * sum(abs(a.get(k, 0.0) - b.get(k, 0.0)) for k in keys)


def compute_privacy_metrics(
    records: List[Dict[str, Any]],
    identifiers: List[str],
    sensitive_attribute: Optional[str],
) -> Dict[str, Any]:
    if not records:
        return {
            "k_anonymity": 0,
            "l_diversity": 0,
            "t_closeness": 0.0,
            "equivalence_classes": 0,
            "records": 0,
        }

    groups = _equivalence_groups(records, identifiers)
    group_sizes = [len(group) for group in groups.values()]
    k_anonymity = min(group_sizes) if group_sizes else 0

    l_diversity = 0
    t_closeness = 0.0
    if sensitive_attribute:
        global_dist = _distribution([row.get(sensitive_attribute) for row in records])
        l_scores = []
        t_scores = []
        for group in groups.values():
            values = [row.get(sensitive_attribute) for row in group]
            non_empty_values = [v for v in values if not _is_empty(v)]
            l_scores.append(len(set(_to_str(v) for v in non_empty_values)))
            class_dist = _distribution(values)
            t_scores.append(_total_variation_distance(global_dist, class_dist))
        l_diversity = min(l_scores) if l_scores else 0
        t_closeness = max(t_scores) if t_scores else 0.0

    return {
        "k_anonymity": int(k_anonymity),
        "l_diversity": int(l_diversity),
        "t_closeness": round(float(t_closeness), 4),
        "equivalence_classes": len(groups),
        "records": len(records),
    }


def build_privacy_suggestions(
    metrics: Dict[str, Any], identifiers: List[str], sensitive_attribute: Optional[str]
) -> List[str]:
    suggestions: List[str] = []
    k_val = metrics.get("k_anonymity", 0)
    l_val = metrics.get("l_diversity", 0)
    t_val = metrics.get("t_closeness", 1.0)

    if "ip" in identifiers:
        suggestions.append(
            "Do not use raw 'ip' as an identifier; prefer pseudonymization and coarse network buckets."
        )
    if k_val < 2:
        suggestions.append(
            "k-anonymity is low. Remove high-cardinality identifiers and apply stronger generalization profiles."
        )
    if l_val < 2 and sensitive_attribute:
        suggestions.append(
            f"l-diversity is low for '{sensitive_attribute}'. Increase group size with fewer identifiers or stronger suppression."
        )
    if t_val > 0.5:
        suggestions.append(
            "t-closeness is high. Use threshold-based suppression for rare values and coarser categorical groupings."
        )
    if not suggestions:
        suggestions.append(
            "Metrics are in a healthier range. Validate utility before finalizing transformations."
        )
    return suggestions
