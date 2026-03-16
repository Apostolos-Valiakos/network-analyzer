import hashlib
import ipaddress
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
    salt: str = "network-analyzer",
) -> List[Dict[str, Any]]:
    transformed: List[Dict[str, Any]] = []
    pseudo_map: Dict[Tuple[str, str], str] = {}

    for row in records:
        new_row = dict(row)

        for col in pseudonymize:
            if col in new_row and not _is_empty(new_row[col]):
                key = (col, _to_str(new_row[col]))
                if key not in pseudo_map:
                    pseudo_map[key] = _pseudonymize_value(new_row[col], salt)
                new_row[col] = pseudo_map[key]

        for col in generalize:
            if col in new_row:
                new_row[col] = _generalize_value(new_row[col])

        for col in suppress:
            if col in new_row:
                new_row[col] = "*"

        transformed.append(new_row)

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
