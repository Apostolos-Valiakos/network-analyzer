"""
Snapshot (golden-file) helpers for characterisation tests.

A snapshot records what a function or route returns *today*, so refactoring
can prove it changed nothing. Files live in tests/backend/snapshots/*.json.

    pytest                      # compare against stored snapshots
    pytest --update-snapshots   # rewrite them from current output (review the diff!)

Outputs that depend on an external tool record that tool's version. Running
`--update-snapshots` under another version (e.g. tshark 4.4 in the production
image) records it too: as a mark on the main file when the output is the same,
or as <name>.tshark-4.4.json when it differs. A version with no recording is
skipped instead of failing, because the difference would come from the tool
and not from our code.
"""

import difflib
import glob
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


def _read(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _write(path, snapshot):
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(_dump(snapshot))


def _variant_path(name: str, tools: dict, main_tools: dict) -> str:
    """snapshots/<name>.<tool>-<version>[.<tool>-<version>].json, naming the
    tools whose version differs from the main snapshot's."""
    differing = sorted(t for t in tools if tools[t] != main_tools.get(t))
    suffix = ".".join(f"{t}-{tools[t]}" for t in differing)
    return os.path.join(SNAPSHOT_DIR, f"{name}.{suffix}.json")


class Snapshot:
    """Golden-file comparison that tolerates several tool versions.

    The main file snapshots/<name>.json is recorded with the dev machine's
    tools. Recording under other tool versions (e.g. tshark 4.4 in the
    production image) either marks the main file as also matching them
    ("same_output_with"), when the output is identical, or writes a variant
    file such as <name>.tshark-4.4.json, when it differs. A comparison uses
    the variant for the running tools, else the main file if it was recorded
    with or marked as matching them, else it skips.
    """

    def __init__(self, update: bool):
        self.update = update

    def assert_match(self, name: str, data, tools: dict = None):
        """Compare `data` with the snapshot for `name` and the running tools.

        `tools` maps tool name -> version string the output depends on,
        e.g. {"tshark": "4.6"}; it is stored with the snapshot.
        """
        tools = {k: v for k, v in (tools or {}).items()}
        main_path = os.path.join(SNAPSHOT_DIR, f"{name}.json")
        actual = {"recorded_with": tools, "data": normalize(data)}
        main = _read(main_path) if os.path.exists(main_path) else None

        if self.update:
            self._record(name, main_path, main, actual)
            return

        if main is None:
            pytest.fail(
                f"No snapshot '{name}'. Run `pytest --update-snapshots`, "
                f"review the new file, and commit it."
            )
        main_tools = main.get("recorded_with", {})
        variant_path = _variant_path(name, tools, main_tools)
        if main_tools != tools and os.path.exists(variant_path):
            expected, shown_name = _read(variant_path), os.path.basename(variant_path)
        elif main_tools == tools or tools in main.get("same_output_with", []):
            expected, shown_name = main, f"{name}.json"
        else:
            differing = {t: v for t, v in main_tools.items() if tools.get(t) != v}
            pytest.skip(
                f"Snapshot '{name}' was recorded with {differing}, this machine has "
                f"{ {t: tools.get(t) for t in differing} }; record it here with "
                f"`pytest --update-snapshots`"
            )

        if expected["data"] != actual["data"]:
            diff = "".join(
                difflib.unified_diff(
                    _dump(expected["data"]).splitlines(keepends=True),
                    _dump(actual["data"]).splitlines(keepends=True),
                    fromfile=f"snapshots/{shown_name}",
                    tofile="current output",
                    n=2,
                )
            )
            lines = diff.splitlines()
            shown = "\n".join(lines[:80])
            more = f"\n... {len(lines) - 80} more diff lines" if len(lines) > 80 else ""
            pytest.fail(f"Output differs from snapshot '{shown_name}':\n{shown}{more}", pytrace=False)

    @staticmethod
    def _record(name, main_path, main, actual):
        tools = actual["recorded_with"]
        main_tools = (main or {}).get("recorded_with")

        if main is None or main_tools == tools or set(main_tools) != set(tools):
            # (Re-)record the main file: same versions, or the output now
            # depends on different tools (variants and marks of the old tool
            # set no longer apply). Other versions' "same as" marks only stay
            # valid while the output is unchanged.
            if set((main or {}).get("recorded_with", {})) != set(tools):
                main = None
                for stale in glob.glob(os.path.join(SNAPSHOT_DIR, f"{glob.escape(name)}.*.json")):
                    os.remove(stale)
            if main is not None and main["data"] == actual["data"] and main.get("same_output_with"):
                actual = {**actual, "same_output_with": main["same_output_with"]}
            _write(main_path, actual)
            return

        variant_path = _variant_path(name, tools, main_tools)
        same = [t for t in main.get("same_output_with", []) if t != tools]
        if main["data"] == actual["data"]:
            same.append(tools)
            if os.path.exists(variant_path):
                os.remove(variant_path)
        else:
            _write(variant_path, actual)
        updated = {k: v for k, v in main.items() if k != "same_output_with"}
        if same:
            updated["same_output_with"] = sorted(same, key=lambda t: json.dumps(t, sort_keys=True))
        if updated != main:
            _write(main_path, updated)
