"""
Unit tests for the helpers extracted in refactoring Phase 1:
server/tshark.py, server/settings.py and the pure helpers in app.py.
"""

import os
import subprocess
import sys

import pytest

_SERVER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "server"))
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)

import settings
import tshark


@pytest.fixture()
def fresh_lookup():
    """tshark_path() is cached per process; clear it around each test."""
    tshark.tshark_path.cache_clear()
    yield
    tshark.tshark_path.cache_clear()


# ── tshark lookup ────────────────────────────────────────────────────────────


class TestTsharkLookup:
    def test_tshark_path_env_var_wins(self, fresh_lookup, monkeypatch, tmp_path):
        exe = tmp_path / "tshark.exe"
        exe.write_text("")
        monkeypatch.setenv("TSHARK_PATH", str(exe))
        monkeypatch.setattr(tshark.shutil, "which", lambda name: "/elsewhere/tshark")
        assert tshark.tshark_path() == str(exe)

    def test_missing_env_path_falls_back_to_path(self, fresh_lookup, monkeypatch, tmp_path):
        monkeypatch.setenv("TSHARK_PATH", str(tmp_path / "missing.exe"))
        monkeypatch.setattr(tshark.shutil, "which", lambda name: "/usr/bin/tshark")
        assert tshark.tshark_path() == "/usr/bin/tshark"

    def test_not_found_anywhere_returns_none(self, fresh_lookup, monkeypatch):
        monkeypatch.delenv("TSHARK_PATH", raising=False)
        monkeypatch.setattr(tshark.shutil, "which", lambda name: None)
        monkeypatch.setattr(tshark.sys, "platform", "linux")
        assert tshark.tshark_path() is None

    def test_fields_command_raises_file_not_found_subclass(self, fresh_lookup, monkeypatch):
        monkeypatch.delenv("TSHARK_PATH", raising=False)
        monkeypatch.setattr(tshark.shutil, "which", lambda name: None)
        monkeypatch.setattr(tshark.sys, "platform", "linux")
        # Existing callers catch FileNotFoundError; the subclass keeps that working.
        with pytest.raises(FileNotFoundError):
            tshark.fields_command("x.pcap", ["ip.src"])

    def test_fields_command_layout(self, fresh_lookup, monkeypatch):
        monkeypatch.setenv("TSHARK_PATH", "")
        monkeypatch.setattr(tshark.shutil, "which", lambda name: "/usr/bin/tshark")
        cmd = tshark.fields_command(
            "a.pcap", ["ip.src", "ip.dst"], read_options=["-n"], display_filter="ip",
            extra=["-E", "separator=/t"],
        )
        assert cmd == [
            "/usr/bin/tshark", "-r", "a.pcap", "-n", "-T", "fields", "-Y", "ip",
            "-e", "ip.src", "-e", "ip.dst", "-E", "separator=/t",
        ]

    def test_run_returns_on_nonzero_exit(self):
        result = tshark.run([sys.executable, "-c", "import sys; print('out'); sys.exit(14)"])
        assert result.returncode == 14
        assert result.stdout.strip() == "out"

    def test_run_honours_timeout(self):
        with pytest.raises(subprocess.TimeoutExpired):
            tshark.run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)


# ── settings ─────────────────────────────────────────────────────────────────


class TestSettings:
    def test_output_dirs_are_absolute_and_inside_server(self):
        for d in settings.OUTPUT_DIRS:
            assert os.path.isabs(d)
            assert os.path.dirname(d) == settings.SERVER_DIR

    def test_sensor_url_reads_env_each_call(self, monkeypatch):
        monkeypatch.setenv("SENSOR_URL", "http://sensor-a:5005")
        assert settings.sensor_url("/get-pcap") == "http://sensor-a:5005/get-pcap"
        monkeypatch.setenv("SENSOR_URL", "http://sensor-b:5005")
        assert settings.sensor_url() == "http://sensor-b:5005"

    def test_sensor_url_default(self, monkeypatch):
        monkeypatch.delenv("SENSOR_URL", raising=False)
        assert settings.sensor_url("/x") == "http://172.18.0.1:5005/x"


# ── app.py pure helpers ──────────────────────────────────────────────────────


class TestFlowAlert:
    def test_large_transfer_is_error(self):
        from blueprints.monitoring import flow_alert

        alert = flow_alert("1.1.1.1", "2.2.2.2", 6_000_000, 10, "SF")
        assert alert == {
            "level": "error",
            "title": "Massive Data Transfer",
            "message": "IP 1.1.1.1 sent 5.72 MB to 2.2.2.2.",
        }

    def test_bytes_rule_wins_over_packets_and_rej(self):
        from blueprints.monitoring import flow_alert

        alert = flow_alert("a", "b", 6_000_000, 9_999, "REJ")
        assert alert["title"] == "Massive Data Transfer"

    def test_packet_flood_before_rejected(self):
        from blueprints.monitoring import flow_alert

        alert = flow_alert("a", "b", 10, 5_001, "REJ")
        assert alert["title"] == "Packet Flood Detected"

    def test_rejected_connection(self):
        from blueprints.monitoring import flow_alert

        alert = flow_alert("a", "b", 10, 1, "REJ")
        assert alert["message"] == "a attempted to connect to a closed port on b."

    def test_thresholds_are_exclusive_and_normal_flow_is_quiet(self):
        from blueprints.monitoring import flow_alert

        assert flow_alert("a", "b", 5_000_000, 5_000, "SF") is None
