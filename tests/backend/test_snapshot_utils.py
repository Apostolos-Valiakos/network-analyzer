"""
Snapshot helper: one main file per snapshot, plus per-tool-version recordings
(a "same_output_with" mark when the output is identical, a
<name>.<tool>-<version>.json file when it differs).
"""
import json
import os

import pytest

import snapshot_utils
from snapshot_utils import Snapshot

DEV = {"tshark": "4.6"}
PROD = {"tshark": "4.4"}


@pytest.fixture()
def snap_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot_utils, "SNAPSHOT_DIR", str(tmp_path))
    return tmp_path


def _files(directory):
    return sorted(p.name for p in directory.iterdir())


def _load(directory, filename):
    return json.loads((directory / filename).read_text(encoding="utf-8"))


def test_records_and_matches_main_file(snap_dir):
    Snapshot(update=True).assert_match("roles", {"a": 1}, tools=DEV)
    assert _files(snap_dir) == ["roles.json"]
    Snapshot(update=False).assert_match("roles", {"a": 1}, tools=DEV)


def test_other_version_without_recording_skips(snap_dir):
    Snapshot(update=True).assert_match("roles", {"a": 1}, tools=DEV)
    with pytest.raises(pytest.skip.Exception, match="update-snapshots"):
        Snapshot(update=False).assert_match("roles", {"a": 1}, tools=PROD)


def test_identical_output_marks_main_file(snap_dir):
    Snapshot(update=True).assert_match("roles", {"a": 1}, tools=DEV)
    Snapshot(update=True).assert_match("roles", {"a": 1}, tools=PROD)

    assert _files(snap_dir) == ["roles.json"]
    main = _load(snap_dir, "roles.json")
    assert main["recorded_with"] == DEV
    assert main["same_output_with"] == [PROD]
    Snapshot(update=False).assert_match("roles", {"a": 1}, tools=PROD)
    Snapshot(update=False).assert_match("roles", {"a": 1}, tools=DEV)
    with pytest.raises(pytest.fail.Exception, match="roles.json"):
        Snapshot(update=False).assert_match("roles", {"a": 2}, tools=PROD)


def test_different_output_writes_variant(snap_dir):
    Snapshot(update=True).assert_match("roles", {"a": 1}, tools=DEV)
    Snapshot(update=True).assert_match("roles", {"a": 2}, tools=PROD)

    assert _files(snap_dir) == ["roles.json", "roles.tshark-4.4.json"]
    assert "same_output_with" not in _load(snap_dir, "roles.json")
    Snapshot(update=False).assert_match("roles", {"a": 2}, tools=PROD)
    Snapshot(update=False).assert_match("roles", {"a": 1}, tools=DEV)
    with pytest.raises(pytest.fail.Exception, match=r"roles\.tshark-4\.4\.json"):
        Snapshot(update=False).assert_match("roles", {"a": 1}, tools=PROD)


def test_variant_names_only_the_differing_tools(snap_dir):
    Snapshot(update=True).assert_match("route", [1], tools={"scapy": "2.7", "tshark": "4.6"})
    Snapshot(update=True).assert_match("route", [2], tools={"scapy": "2.7", "tshark": "4.4"})
    assert "route.tshark-4.4.json" in _files(snap_dir)
    Snapshot(update=True).assert_match("route", [3], tools={"scapy": "2.6", "tshark": "4.4"})
    assert "route.scapy-2.6.tshark-4.4.json" in _files(snap_dir)


def test_rerecording_switches_between_mark_and_variant(snap_dir):
    Snapshot(update=True).assert_match("roles", {"a": 1}, tools=DEV)
    Snapshot(update=True).assert_match("roles", {"a": 2}, tools=PROD)
    # The production output now matches again: the variant goes, the mark comes.
    Snapshot(update=True).assert_match("roles", {"a": 1}, tools=PROD)
    assert _files(snap_dir) == ["roles.json"]
    assert _load(snap_dir, "roles.json")["same_output_with"] == [PROD]
    # And differs again: the mark goes, the variant comes back.
    Snapshot(update=True).assert_match("roles", {"a": 3}, tools=PROD)
    assert _files(snap_dir) == ["roles.json", "roles.tshark-4.4.json"]
    assert "same_output_with" not in _load(snap_dir, "roles.json")


def test_changed_main_output_drops_same_marks(snap_dir):
    Snapshot(update=True).assert_match("roles", {"a": 1}, tools=DEV)
    Snapshot(update=True).assert_match("roles", {"a": 1}, tools=PROD)

    # Unchanged dev output keeps the mark ...
    Snapshot(update=True).assert_match("roles", {"a": 1}, tools=DEV)
    assert _load(snap_dir, "roles.json")["same_output_with"] == [PROD]
    # ... changed dev output drops it, so 4.4 is unverified (skipped) again.
    Snapshot(update=True).assert_match("roles", {"a": 9}, tools=DEV)
    assert "same_output_with" not in _load(snap_dir, "roles.json")
    with pytest.raises(pytest.skip.Exception):
        Snapshot(update=False).assert_match("roles", {"a": 9}, tools=PROD)


def test_snapshot_without_tools_ignores_versions(snap_dir):
    Snapshot(update=True).assert_match("web", {"x": 1})
    Snapshot(update=True).assert_match("web", {"x": 1})
    assert _files(snap_dir) == ["web.json"]
    assert "same_output_with" not in _load(snap_dir, "web.json")
    Snapshot(update=False).assert_match("web", {"x": 1})


def test_missing_snapshot_fails(snap_dir):
    with pytest.raises(pytest.fail.Exception, match="No snapshot"):
        Snapshot(update=False).assert_match("nothing", {}, tools=DEV)
    assert not os.listdir(snap_dir)


def test_changed_tool_set_rerecords_main_file(snap_dir):
    # The output used to depend on Scapy and tshark, and now on tshark only.
    old_tools = {"scapy": "2.7", "tshark": "4.6"}
    Snapshot(update=True).assert_match("route", [1], tools=old_tools)
    Snapshot(update=True).assert_match("route", [2], tools={"scapy": "2.8", "tshark": "4.4"})
    assert _files(snap_dir) == ["route.json", "route.scapy-2.8.tshark-4.4.json"]

    Snapshot(update=True).assert_match("route", [3], tools=DEV)
    assert _files(snap_dir) == ["route.json"]
    main = _load(snap_dir, "route.json")
    assert main["recorded_with"] == DEV
    assert main["data"] == [3]
    Snapshot(update=False).assert_match("route", [3], tools=DEV)
