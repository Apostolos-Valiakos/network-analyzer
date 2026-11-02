"""
Tests for server/packet_table.py (the one shared tshark extraction) and the
pipeline worker's handling of an unreadable capture.
"""

import os
import subprocess
import sys

import pytest

_SERVER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "server"))
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)

import packet_table
from packet_table import _outer_ports
from snapshot_utils import tshark_version

needs_tshark = pytest.mark.skipif(tshark_version() is None, reason="needs tshark on PATH")


# ── Which transport header counts ────────────────────────────────────────────


class TestOuterPorts:
    def _ports(self, stack, tcp=("", ""), udp=("", "")):
        return _outer_ports(stack.split(":"), tcp[0], tcp[1], udp[0], udp[1])

    def test_plain_tcp(self):
        assert self._ports("eth:ethertype:ip:tcp", tcp=("443", "5000")) == (443, 5000)

    def test_outer_udp_of_a_gtp_tunnel_wins_over_inner_tcp(self):
        ports = self._ports("eth:ethertype:ip:udp:gtp:ip:tcp", tcp=("80", "90"), udp=("2152", "2152"))
        assert ports == (2152, 2152)

    def test_first_occurrence_of_the_same_protocol(self):
        ports = self._ports("eth:ethertype:ip:udp:gtp:ip:udp", udp=("2152,53", "2152,6000"))
        assert ports == (2152, 2152)

    def test_transport_quoted_in_icmp_error_does_not_count(self):
        assert self._ports("eth:ethertype:ip:icmp:ip:udp:data", udp=("53", "6000")) is None

    def test_sctp_has_no_tcp_udp_ports(self):
        assert self._ports("eth:ethertype:ip:sctp:ngap") is None

    def test_non_first_fragment_has_no_ports(self):
        assert self._ports("eth:ethertype:ip:udp") is None


# ── Extraction and cache ─────────────────────────────────────────────────────


@needs_tshark
class TestExtractionAndCache:
    def test_cache_is_written_and_reused(self, capture_copy, monkeypatch):
        path = capture_copy("sample.pcap")
        first_read = list(packet_table.columns(path, ["frame.number", "ip.src"]))
        assert os.path.exists(path + packet_table.CACHE_SUFFIX)

        def fail(*a, **k):
            raise AssertionError("tshark ran again despite a valid cache")

        monkeypatch.setattr(packet_table, "_extract", fail)
        assert list(packet_table.columns(path, ["frame.number", "ip.src"])) == first_read

    def test_changed_capture_is_extracted_again(self, capture_copy, monkeypatch):
        path = capture_copy("sample.pcap")
        packet_table.ensure(path)
        calls = []
        real = packet_table._extract
        monkeypatch.setattr(packet_table, "_extract", lambda p: calls.append(p) or real(p))

        with open(capture_copy("ppc_5g_and_oran.pcap"), "rb") as src, open(path, "wb") as dst:
            dst.write(src.read())
        rows = list(packet_table.columns(path, ["frame.number"]))
        assert calls == [path]
        assert len(rows) == 236

    def test_changed_field_list_invalidates_the_cache(self, capture_copy, monkeypatch):
        path = capture_copy("sample.pcap")
        packet_table.ensure(path)
        with open(path + packet_table.CACHE_SUFFIX, "r+", encoding="utf-8") as f:
            f.write("#stale")  # as if written by an older field list
        calls = []
        real = packet_table._extract
        monkeypatch.setattr(packet_table, "_extract", lambda p: calls.append(p) or real(p))
        packet_table.ensure(path)
        assert calls == [path]

    def test_one_row_per_frame_including_non_ip(self, capture_copy):
        rows = list(packet_table.outer_packets(capture_copy("sample.pcap")))
        assert len(rows) == 58
        assert sum(1 for r in rows if r is None) == 2  # the two ARP frames

    def test_lines_require_filters_frames(self, capture_copy):
        path = capture_copy("sample.pcap")
        text = packet_table.lines(path, ["frame.number", "ip.src"], require="ip.src")
        assert len(text.splitlines()) == 56
        assert all(line.split("\t")[1] for line in text.splitlines())

    def test_garbage_file_raises(self, tmp_path):
        bad = tmp_path / "bad.pcap"
        bad.write_bytes(b"this is not a capture at all, just some text......")
        with pytest.raises(packet_table.TsharkFailed):
            packet_table.ensure(str(bad))
        assert not os.path.exists(str(bad) + packet_table.CACHE_SUFFIX)

    def test_truncated_capture_still_gives_complete_packets(self, capture_copy):
        path = capture_copy("sample.pcap")
        with open(path, "rb") as f:
            data = f.read()
        with open(path, "wb") as f:
            f.write(data[:-7])
        rows = list(packet_table.columns(path, ["frame.number"]))
        assert len(rows) == 57


# ── Pipeline worker: tshark failure must not look like success ───────────────


class _ListQueue:
    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)


@needs_tshark
def test_worker_reports_unreadable_capture(app, fresh_db, tmp_path):
    from Preprocess import _pipeline_worker

    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"this is not a capture at all, just some text......")
    queue = _ListQueue()
    _pipeline_worker(str(bad), "rule_based", queue)
    assert queue.items[0]["status"] == "failed"
    assert queue.items[0]["message"].startswith("Failed to load packets:")


def test_worker_reports_missing_tshark(app, fresh_db, tmp_path, monkeypatch):
    import tshark
    from Preprocess import _pipeline_worker

    def missing(*a, **k):
        raise tshark.TsharkNotFound("tshark not found")

    monkeypatch.setattr(packet_table.tshark, "fields_command", missing)
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"x")
    queue = _ListQueue()
    _pipeline_worker(str(pcap), "rule_based", queue)
    assert queue.items[0] == {"status": "failed", "message": "Failed to load packets: tshark not found"}


def test_main_process_is_not_a_worker():
    from app import _is_pipeline_worker

    assert _is_pipeline_worker() is False


_SPAWN_SCRIPT = """
import multiprocessing as mp
import sys
sys.path.insert(0, {server!r})
import app  # imported as __mp_main__'s dependency, as in the real child

def child():
    print("child-flag", app._is_pipeline_worker(), flush=True)

if __name__ == "__main__":
    print("parent-flag", app._is_pipeline_worker(), flush=True)
    mp.set_start_method("spawn")
    p = mp.Process(target=child)
    p.start()
    p.join()
else:
    print("import-in-child-flag", __name__, app._is_pipeline_worker(), flush=True)
"""


@pytest.mark.integration
def test_spawned_child_skips_database_setup(tmp_path):
    """A real spawned child: the guard must hold while the main module is being
    re-imported, before multiprocessing.parent_process() is available."""
    script = tmp_path / "spawn_probe.py"
    script.write_text(_SPAWN_SCRIPT.format(server=_SERVER_DIR))
    env = dict(
        os.environ,
        DATABASE_URL="sqlite:///" + str(tmp_path / "probe.db").replace("\\", "/"),
        JWT_SECRET_KEY="spawn-probe-secret-spawn-probe-secret",
    )
    result = subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=env, timeout=120, cwd=str(tmp_path),
    )
    assert "parent-flag False" in result.stdout, result.stderr[-800:]
    assert "import-in-child-flag __mp_main__ True" in result.stdout
    assert "child-flag True" in result.stdout
    # Setup logs this once per run on SQLite, so once means only the parent ran it.
    assert (result.stdout + result.stderr).count("Schema migration skipped") == 1
