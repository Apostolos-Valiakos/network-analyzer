"""
Evaluates the stored role snapshots against Kubernetes (Phase 6).

On the testbed, Kubernetes knows what each pod is: its labels and names
(k8s_role_hints.json) give the role each pod's IP should have. This compares
the role snapshots of a period, per source (live DPI and pcap), with that
ground truth:
  - precision per predicted role and recall per true role, over every
    snapshot row whose IP belonged to a pod with a hint at the time;
  - how often a labelled IP stayed "Unidentified";
  - re-identification time: for every pod that started on an IP during the
    period (first sighting, e.g. after a restart), the delay until the first
    snapshot that gave that IP the right role. Snapshots are taken every
    window (DPI) or interval (pcap), so the delay is at least that long.

Run on the backend (needs DATABASE_URL), e.g. in the backend container:
    python evaluate_roles.py --hours 24                # Markdown report
    python evaluate_roles.py --hours 24 --format json  # for scripts
"""
import argparse
import json
import statistics
import sys
import time
from collections import Counter, defaultdict
from typing import Callable, Dict, Iterable, List, Optional, Tuple

Truth = Optional[Tuple[str, frozenset]]  # (true role, roles that count as right)


def evaluate(
    rows: Iterable[Tuple[str, float, str, str]],
    truth: Callable[[str, float], Truth],
    pod_starts: Iterable[Tuple[str, float, str, frozenset]] = (),
) -> Dict[str, dict]:
    """rows: (source, ts, ip, predicted role). truth(ip, ts) -> Truth.
    pod_starts: (ip, first_seen, true role, accepted roles) of pods that
    started in the period. Returns one result per source."""
    by_source: Dict[str, list] = defaultdict(list)
    for source, ts, ip, role in rows:
        by_source[source].append((ts, ip, role))
    pod_starts = list(pod_starts)

    results = {}
    for source, items in sorted(by_source.items()):
        labelled = []
        for ts, ip, role in items:
            t = truth(ip, ts)
            if t is not None:
                labelled.append((ts, ip, role, t[0], role in t[1]))
        results[source] = _scores(items, labelled)
        results[source]["reidentification"] = _reidentification(items, pod_starts)
    return results


def _scores(items, labelled) -> dict:
    predicted, predicted_right = Counter(), Counter()
    support, recalled = Counter(), Counter()
    confusion: Dict[str, Counter] = defaultdict(Counter)
    for _, _, role, true_role, right in labelled:
        predicted[role] += 1
        support[true_role] += 1
        confusion[true_role][role] += 1
        if right:
            predicted_right[role] += 1
            recalled[true_role] += 1
    right_total = sum(1 for row in labelled if row[4])
    unidentified = sum(1 for row in labelled if row[2] == "Unidentified")
    return {
        "snapshots": len({ts for ts, _, _ in items}),
        "rows": len(items),
        "labelled_rows": len(labelled),
        "accuracy": _ratio(right_total, len(labelled)),
        "unidentified_rate": _ratio(unidentified, len(labelled)),
        "recall": {r: _ratio(recalled[r], n) for r, n in sorted(support.items())},
        "support": dict(sorted(support.items())),
        "precision": {r: _ratio(predicted_right[r], n) for r, n in sorted(predicted.items())},
        "confusion": {t: dict(sorted(c.items())) for t, c in sorted(confusion.items())},
    }


def _reidentification(items, pod_starts) -> dict:
    by_ip: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
    for ts, ip, role in items:
        by_ip[ip].append((ts, role))
    delays, missed = [], []
    for ip, started, true_role, accepted in pod_starts:
        hits = [ts for ts, role in by_ip.get(ip, []) if ts >= started and role in accepted]
        if hits:
            delays.append(min(hits) - started)
        else:
            missed.append({"ip": ip, "role": true_role, "started": started})
    return {
        "pod_starts": len(pod_starts),
        "identified": len(delays),
        "median_seconds": round(statistics.median(delays), 1) if delays else None,
        "max_seconds": round(max(delays), 1) if delays else None,
        "not_identified": missed,
    }


def _ratio(part: int, whole: int) -> Optional[float]:
    return round(part / whole, 4) if whole else None


# ── Database ─────────────────────────────────────────────────────────────────


def evaluate_database(t0: float, t1: float) -> Dict[str, dict]:
    """evaluate() over the snapshots and pod sightings stored between t0 and
    t1. Needs an app context."""
    import k8s_identity
    import role_fusion
    from models import PodIpSighting, RoleSnapshot, utc_from_timestamp

    rows = [
        (r.source, r.ts, r.ip_address, r.role)
        for r in RoleSnapshot.query.filter(RoleSnapshot.ts >= t0, RoleSnapshot.ts <= t1)
    ]

    cache: Dict[Tuple[str, float], Truth] = {}

    def truth(ip: str, ts: float) -> Truth:
        key = (ip, ts)
        if key not in cache:
            info = k8s_identity.at(ip, ts)
            cache[key] = role_fusion.hint_for(info) if info and info.get("pod") else None
        return cache[key]

    starts = []
    for s in PodIpSighting.query.filter(
        PodIpSighting.first_seen >= utc_from_timestamp(t0),
        PodIpSighting.first_seen <= utc_from_timestamp(t1),
    ):
        hint = role_fusion.hint_for({"labels": s.labels or {}, "workload": s.workload, "pod": s.pod})
        if hint:
            started = s.first_seen.replace(tzinfo=_utc()).timestamp()
            starts.append((s.ip, started, hint[0], hint[1]))
    return evaluate(rows, truth, starts)


def _utc():
    from datetime import timezone
    return timezone.utc


# ── Report ────────────────────────────────────────────────────────────────────


def _pct(value) -> str:
    return "—" if value is None else f"{value * 100:.1f}%"


def markdown(results: Dict[str, dict], t0: float, t1: float) -> str:
    out = [f"# Role evaluation against Kubernetes",
           "",
           f"Period: {time.strftime('%Y-%m-%d %H:%M', time.gmtime(t0))} to "
           f"{time.strftime('%Y-%m-%d %H:%M', time.gmtime(t1))} UTC", ""]
    if not results:
        out.append("No role snapshots in this period.")
    for source, r in results.items():
        re_id = r["reidentification"]
        out += [
            f"## Source: {source}",
            "",
            f"- Snapshots: {r['snapshots']}, rows: {r['rows']}, rows with a pod hint: {r['labelled_rows']}",
            f"- Accuracy: {_pct(r['accuracy'])}; labelled IPs left Unidentified: {_pct(r['unidentified_rate'])}",
            f"- Pods started in the period: {re_id['pod_starts']}, identified: {re_id['identified']}"
            + (f", median delay {re_id['median_seconds']} s, max {re_id['max_seconds']} s"
               if re_id["identified"] else ""),
            "",
            "| True role | Rows | Recall |",
            "|---|---|---|",
        ]
        out += [f"| {role} | {r['support'][role]} | {_pct(v)} |" for role, v in r["recall"].items()]
        out += ["", "| Predicted role | Precision |", "|---|---|"]
        out += [f"| {role} | {_pct(v)} |" for role, v in r["precision"].items()]
        out.append("")
    return "\n".join(out)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--hours", type=float, default=24, help="length of the period (default 24)")
    parser.add_argument("--to", type=float, default=None, help="end of the period, epoch seconds (default now)")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args(argv)
    t1 = args.to if args.to is not None else time.time()
    t0 = t1 - args.hours * 3600

    from dotenv import load_dotenv
    load_dotenv()
    import db_setup

    app = db_setup.database_only_app()
    with app.app_context():
        results = evaluate_database(t0, t1)
    if args.format == "json":
        print(json.dumps({"from": t0, "to": t1, "sources": results}, indent=2))
    else:
        print(markdown(results, t0, t1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
