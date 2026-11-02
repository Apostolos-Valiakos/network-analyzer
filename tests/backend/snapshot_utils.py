"""
Snapshot (golden-file) helpers for characterisation tests.

A snapshot records what a function or route returns *today*, so refactoring
can prove it changed nothing. Files live in tests/backend/snapshots/*.json.

    pytest                      # compare against stored snapshots
    pytest --update-snapshots   # rewrite them from current output (review the diff!)

Outputs that depend on an external tool record that tool's version; when the
running version differs, the test is skipped instead of failing, because the
difference would come from the tool and not from our code.
"""

import difflib
import json
import os
import re
import shutil
import subprocess
from functools import lru_cache

import pytest

SNAPSHOT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "snapshots")
FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
FLOAT_DIGITS = 6

# Captures used by the characterisation tests:
#   sample.pcap           58 packets  NGAP, NAS-5GS, SCTP, DNS
#   ppc_5g_and_oran.pcap 236 packets  NGAP, E2AP, SCTP, TCP, ICMP, DNS
SNAPSHOT_CAPTURES = ["sample.pcap", "ppc_5g_and_oran.pcap"]


def normalize(value):
    """JSON-safe, order-stable form: tuples -> lists, sets -> sorted lists,
    numpy scalars -> Python, floats rounded to FLOAT_DIGITS."""
    try:
        import numpy as np
    except ImportError:  # pragma: no cover
        np = None

    if isinstance(value, dict):
        return {_key(k): normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalize(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted((normalize(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    if np is not None:
        if isinstance(value, np.ndarray):
            return normalize(value.tolist())
        if isinstance(value, np.bool_):
            return bool(value)
        if isinstance(value, np.integer):
            return int(value)
        if isinstance(value, np.floating):
            value = float(value)
    if isinstance(value, float):
        return round(value, FLOAT_DIGITS)
    return value


def _key(k):
    if isinstance(k, tuple):
        return "|".join(str(part) for part in k)
    return str(k)


def _dump(data) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


@lru_cache(maxsize=1)
def tshark_version():
    """'major.minor' of the tshark the backend uses, or None if it is missing."""
    try:
        from tshark import tshark_path  # server/tshark.py, same lookup as the app
        exe = tshark_path()
    except ImportError:
        exe = shutil.which("tshark")
    if not exe:
        return None
    out = subprocess.run([exe, "--version"], capture_output=True, text=True).stdout
    m = re.search(r"(\d+)\.(\d+)\.\d+", out)
    return f"{m.group(1)}.{m.group(2)}" if m else None


@lru_cache(maxsize=1)
def scapy_version():
    try:
        import scapy
        return ".".join(scapy.VERSION.split(".")[:2])
    except Exception:
        return None


class Snapshot:
    def __init__(self, update: bool):
        self.update = update

    def assert_match(self, name: str, data, tools: dict = None):
        """Compare `data` with snapshots/<name>.json.

        `tools` maps tool name -> version string the output depends on,
        e.g. {"tshark": "4.6"}; it is stored with the snapshot.
        """
        tools = {k: v for k, v in (tools or {}).items()}
        path = os.path.join(SNAPSHOT_DIR, f"{name}.json")
        actual = {"recorded_with": tools, "data": normalize(data)}

        if self.update:
            os.makedirs(SNAPSHOT_DIR, exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(_dump(actual))
            return

        if not os.path.exists(path):
            pytest.fail(
                f"No snapshot '{name}'. Run `pytest --update-snapshots`, "
                f"review the new file, and commit it."
            )
        with open(path, encoding="utf-8") as f:
            expected = json.load(f)

        recorded = expected.get("recorded_with", {})
        for tool, version in recorded.items():
            if tools.get(tool) != version:
                pytest.skip(
                    f"Snapshot '{name}' was recorded with {tool} {version}, "
                    f"this machine has {tools.get(tool)}"
                )

        if expected["data"] != actual["data"]:
            diff = "".join(
                difflib.unified_diff(
                    _dump(expected["data"]).splitlines(keepends=True),
                    _dump(actual["data"]).splitlines(keepends=True),
                    fromfile=f"snapshots/{name}.json",
                    tofile="current output",
                    n=2,
                )
            )
            lines = diff.splitlines()
            shown = "\n".join(lines[:80])
            more = f"\n... {len(lines) - 80} more diff lines" if len(lines) > 80 else ""
            pytest.fail(f"Output differs from snapshot '{name}':\n{shown}{more}", pytrace=False)
