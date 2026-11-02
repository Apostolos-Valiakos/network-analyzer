"""
Tests for the sensor's /get-pcap slicing (Host Files/pcap_server.py), loaded
under its own module name because it runs on the sensor, not in the backend.
"""

import importlib.util
import os
import shutil
import subprocess
import time
from datetime import datetime

import pytest

_HOST_FILES = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "Host Files")
)
SAMPLE = os.path.join(os.path.dirname(__file__), "fixtures", "sample.pcap")
TOKEN = {"X-Internal-Token": "sensor-test-token"}


@pytest.fixture()
def sensor(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRET_TOKEN", TOKEN["X-Internal-Token"])
    # The module creates its capture folder on import; keep that out of the repo.
    monkeypatch.setattr(os, "makedirs", lambda *a, **k: None)
    spec = importlib.util.spec_from_file_location(
        "sensor_pcap_server", os.path.join(_HOST_FILES, "pcap_server.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.undo()
    monkeypatch.setattr(module, "PCAP_DIR", str(tmp_path))
    return module


def _ring_file(folder, index, start_ts, end_ts):
    """A file named like dumpcap's ring buffer, spanning start_ts..end_ts."""
    stamp = datetime.fromtimestamp(start_ts).strftime("%Y%m%d%H%M%S")
    path = os.path.join(str(folder), f"continuous_capture_{index:05d}_{stamp}.pcap")
    shutil.copy(SAMPLE, path)
    os.utime(path, (end_ts, end_ts))
    return path


class TestRingFileSelection:
    def test_only_overlapping_files_are_selected(self, sensor, tmp_path):
        base = 1_790_000_000
        old = _ring_file(tmp_path, 1, base, base + 100)
        mid = _ring_file(tmp_path, 2, base + 100, base + 200)
        new = _ring_file(tmp_path, 3, base + 200, base + 300)
        assert sensor.ring_files_for_window([old, mid, new], base + 120, base + 180) == [mid]
        assert sensor.ring_files_for_window([old, mid, new], base + 150, base + 250) == [mid, new]

    def test_edges_have_slack(self, sensor, tmp_path):
        base = 1_790_000_000
        old = _ring_file(tmp_path, 1, base, base + 100)
        assert sensor.ring_files_for_window([old], base + 101, base + 150) == [old]

    def test_unparseable_name_falls_back_to_all_files(self, sensor, tmp_path):
        base = 1_790_000_000
        odd = tmp_path / "continuous_manual.pcap"
        odd.write_bytes(b"")
        old = _ring_file(tmp_path, 1, base, base + 100)
        assert sensor.ring_files_for_window([old, str(odd)], base + 500, base + 600) == [old, str(odd)]

    def test_nothing_overlapping_falls_back_to_all_files(self, sensor, tmp_path):
        base = 1_790_000_000
        old = _ring_file(tmp_path, 1, base, base + 100)
        assert sensor.ring_files_for_window([old], base + 500, base + 600) == [old]


@pytest.mark.integration
@pytest.mark.skipif(
    shutil.which("mergecap") is None or shutil.which("editcap") is None,
    reason="needs mergecap and editcap on PATH",
)
class TestGetPcapSlice:
    def _packet_times(self):
        out = subprocess.run(
            ["tshark", "-r", SAMPLE, "-T", "fields", "-e", "frame.time_epoch"],
            capture_output=True, text=True,
        ).stdout.split()
        return float(out[0]), float(out[-1])

    def test_slice_contains_the_packets_on_any_time_zone(self, sensor, tmp_path):
        """Times are passed to editcap as local time; on a non-UTC host the
        previous UTC strings produced an empty slice."""
        first, last = self._packet_times()
        _ring_file(tmp_path, 1, first - 5, last + 5)
        res = sensor.app.test_client().get(
            f"/get-pcap?start_time={first - 2}&end_time={last + 2}", headers=TOKEN
        )
        assert res.status_code == 200
        assert res.headers["Content-Disposition"].endswith(f"slice_{int(first - 2)}.pcap")
        out = tmp_path / "result.pcap"
        out.write_bytes(res.data)
        count = subprocess.run(
            ["tshark", "-r", str(out), "-T", "fields", "-e", "frame.number"],
            capture_output=True, text=True,
        ).stdout.split()
        assert len(count) == 58

    def test_window_outside_the_capture_gives_an_empty_slice(self, sensor, tmp_path):
        first, last = self._packet_times()
        _ring_file(tmp_path, 1, first - 5, last + 5)
        res = sensor.app.test_client().get(
            f"/get-pcap?start_time={first - 7200}&end_time={first - 3600}", headers=TOKEN
        )
        assert res.status_code == 200
        out = tmp_path / "result.pcap"
        out.write_bytes(res.data)
        count = subprocess.run(
            ["tshark", "-r", str(out), "-T", "fields", "-e", "frame.number"],
            capture_output=True, text=True,
        ).stdout.split()
        assert count == []

    def test_no_temporary_files_are_left_in_the_working_folder(self, sensor, tmp_path, monkeypatch):
        work = tmp_path / "cwd"
        work.mkdir()
        monkeypatch.chdir(work)
        first, last = self._packet_times()
        _ring_file(tmp_path, 1, first - 5, last + 5)
        sensor.app.test_client().get(
            f"/get-pcap?start_time={first - 2}&end_time={last + 2}", headers=TOKEN
        )
        assert list(work.iterdir()) == []
