#!/usr/bin/env python3
"""
Privacy report for one PCAP: per-host records, then (k, l, t) and the
re-identification measures before and after each transformation step.

Usage:
    python server/privacy_report.py PILOT-PCAP/R10_22Oct2026.pcap \
        --pilot PUC4-R10 --out server/results/privacy_R10

Writes records.csv, releases.csv, report.json and report.md to --out.
"""

import argparse
import csv
import json
import os
import random
import sys
from collections import defaultdict
from statistics import mean
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from privacy_metrics import (  # noqa: E402
    apply_transformations,
    compute_privacy_metrics,
    compute_utility_metrics,
)
from privacy_records import records_from_pcap  # noqa: E402

QI = ["subnet", "mac_vendor", "service_port", "packets", "duration_s"]
SA = "role"
DIRECT = ["ip", "mac"]
COARSE = {
    "subnet": "ip_mask_16",
    "service_port": "port_class",
    "packets": "numeric_magnitude",
    "duration_s": "numeric_bins_30",
}
MINIMAL_QI = ["scope", "service_port", "packets"]
MINIMAL_COARSE = {"service_port": "port_class", "packets": "numeric_magnitude"}

# Each step adds one technique to the previous one.
RELEASES = [
    {"name": "R0 Raw profile", "qi": QI},
    {"name": "R1 Pseudonymise ip, mac", "qi": QI, "pseudonymize": DIRECT},
    {
        "name": "R2 + Generalise QIs",
        "qi": QI,
        "pseudonymize": DIRECT,
        "generalize": list(COARSE),
        "profiles": COARSE,
    },
    {
        "name": "R3 + Suppress rare values (<3)",
        "qi": QI,
        "pseudonymize": DIRECT,
        "generalize": list(COARSE),
        "profiles": COARSE,
        "thresholds": {col: 3 for col in QI},
    },
    {
        "name": "R4 + Suppress records (k>=5)",
        "qi": QI,
        "pseudonymize": DIRECT,
        "generalize": list(COARSE),
        "profiles": COARSE,
        "thresholds": {col: 3 for col in QI},
        "record_k": 5,
    },
    {
        "name": "R5 Minimal QI + generalise",
        "qi": MINIMAL_QI,
        "pseudonymize": DIRECT,
        "generalize": list(MINIMAL_COARSE),
        "profiles": MINIMAL_COARSE,
    },
    {
        "name": "R6 Minimal QI + suppress (k>=3)",
        "qi": MINIMAL_QI,
        "pseudonymize": DIRECT,
        "generalize": list(MINIMAL_COARSE),
        "profiles": MINIMAL_COARSE,
        "record_k": 3,
    },
]


def transform(records: List[Dict[str, Any]], cfg: Dict[str, Any]):
    return apply_transformations(
        records,
        cfg.get("pseudonymize", []),
        cfg.get("generalize", []),
        cfg.get("suppress", []),
        pseudonymization_mode="per_pilot",
        pseudonymization_technique="hmac_sha256",
        generalize_profiles=cfg.get("profiles", {}),
        suppress_thresholds=cfg.get("thresholds", {}),
        record_suppression_k=cfg.get("record_k", 0),
        record_suppression_qi=cfg["qi"],
    )


def partial_qi_attack(release, qi, drop_p=0.5, repeats=20, seed=42):
    """Adversary knows each QI value with probability 1 - drop_p and guesses
    uniformly among matching rows (CSR paper, Sec. IV-C)."""
    if not release:
        return 0.0
    rng = random.Random(seed)
    scores = []
    for _ in range(repeats):
        for target in release:
            known = {q: target.get(q) for q in qi if rng.random() > drop_p}
            if not known:
                scores.append(1.0 / len(release))
                continue
            matches = sum(
                1 for row in release if all(row.get(q) == v for q, v in known.items())
            )
            scores.append(1.0 / matches if matches else 0.0)
    return round(100.0 * mean(scores), 1)


def mac_linkage(records: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """MACs seen behind more than one IP: a pseudonymised IP stays linkable
    through the MAC column unless the MAC is pseudonymised too."""
    by_mac = defaultdict(list)
    for row in records:
        if row["mac"] != "routed":
            by_mac[row["mac"]].append(row["ip"])
    return {mac: ips for mac, ips in by_mac.items() if len(ips) > 1}


def run(pcap: str, pilot: str, out_dir: str) -> Dict[str, Any]:
    os.makedirs(out_dir, exist_ok=True)
    records = records_from_pcap(
        pcap, pilot=pilot, cache_path=os.path.join(out_dir, "tshark_fields.tsv")
    )
    rows = []
    for cfg in RELEASES:
        release = transform(records, cfg)
        metrics = compute_privacy_metrics(release, cfg["qi"], SA)
        utility = compute_utility_metrics(records, release, cfg["qi"])
        rows.append(
            {
                "release": cfg["name"],
                "qi": "+".join(cfg["qi"]),
                "sa": SA,
                **metrics,
                "partial_qi_reid_pct": partial_qi_attack(release, cfg["qi"]),
                **utility,
            }
        )

    with open(os.path.join(out_dir, "records.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
        writer.writeheader()
        writer.writerows(records)
    with open(os.path.join(out_dir, "releases.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    roles = defaultdict(int)
    for row in records:
        roles[row["role"]] += 1
    report = {
        "pcap": os.path.basename(pcap),
        "pilot": pilot,
        "hosts": len(records),
        "roles": dict(sorted(roles.items(), key=lambda kv: -kv[1])),
        "quasi_identifiers": QI,
        "sensitive_attribute": SA,
        "mac_linkage": mac_linkage(records),
        "releases": rows,
    }
    with open(os.path.join(out_dir, "report.json"), "w") as f:
        json.dump(report, f, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w") as f:
        f.write(markdown(report))
    return report


def markdown(report: Dict[str, Any]) -> str:
    cols = [
        ("release", "Release"),
        ("records", "Rows"),
        ("equivalence_classes", "Classes"),
        ("k_anonymity", "k"),
        ("k_record_weighted", "k_rw"),
        ("l_diversity", "l"),
        ("entropy_l_diversity", "l_H"),
        ("t_closeness", "t"),
        ("uniqueness_pct", "Unique %"),
        ("avg_reid_risk_pct", "Exact-QI reID %"),
        ("partial_qi_reid_pct", "Partial-QI reID %"),
        ("ppi", "PPI"),
        ("ppi_rw", "PPI'"),
        ("rows_retained_pct", "Rows kept %"),
        ("suppressed_cells_pct", "Cells suppressed %"),
        ("qi_value_retention_pct", "QI values kept %"),
    ]
    lines = [
        f"# Privacy report: {report['pcap']} ({report['pilot']})",
        "",
        f"Hosts: {report['hosts']}. QI: {', '.join(report['quasi_identifiers'])}. "
        f"SA: {report['sensitive_attribute']}.",
        "",
        "| " + " | ".join(h for _, h in cols) + " |",
        "|" + "---|" * len(cols),
    ]
    for row in report["releases"]:
        lines.append("| " + " | ".join(str(row[k]) for k, _ in cols) + " |")
    lines += ["", "MACs behind several IPs:"]
    for mac, ips in report["mac_linkage"].items():
        lines.append(f"- {mac}: {', '.join(ips)}")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("pcap")
    parser.add_argument("--pilot", default="PUC4-R10")
    parser.add_argument("--out", default="server/results/privacy_report")
    args = parser.parse_args()
    report = run(args.pcap, args.pilot, args.out)
    print(markdown(report))


if __name__ == "__main__":
    main()
