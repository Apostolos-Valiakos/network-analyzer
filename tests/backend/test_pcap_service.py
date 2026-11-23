"""
Pure unit tests for pcap_generator_service.handle_pcap_chunk.
No Flask, no DB — just the file-writing logic.
"""

import base64
import os
import struct
import tempfile
import shutil

import pytest
import sys

# Ensure server/ is on path (conftest.py does this, but make explicit for clarity)
_SERVER_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "server")
)
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)

from pcap_generator_service import (
    handle_pcap_chunk,
    _PCAP_GLOBAL_HEADER,
    _pcap_packet_header,
    PCAP_OUTPUT_DIR,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def tmp_output_dir(monkeypatch, tmp_path):
    """Redirect all PCAP output to a temporary directory."""
    import pcap_generator_service as svc

    monkeypatch.setattr(svc, "PCAP_OUTPUT_DIR", str(tmp_path))
    return tmp_path


# ── _PCAP_GLOBAL_HEADER ───────────────────────────────────────────────────────


class TestGlobalHeader:
    def test_magic_number(self):
        magic = struct.unpack_from("<I", _PCAP_GLOBAL_HEADER)[0]
        assert magic == 0xA1B2C3D4

    def test_version_major(self):
        major = struct.unpack_from("<H", _PCAP_GLOBAL_HEADER, 4)[0]
        assert major == 2

    def test_version_minor(self):
        minor = struct.unpack_from("<H", _PCAP_GLOBAL_HEADER, 6)[0]
        assert minor == 4

    def test_link_type_ethernet(self):
        link_type = struct.unpack_from("<I", _PCAP_GLOBAL_HEADER, 20)[0]
        assert link_type == 1

    def test_header_length_is_24_bytes(self):
        assert len(_PCAP_GLOBAL_HEADER) == 24


# ── _pcap_packet_header ───────────────────────────────────────────────────────


class TestPacketHeader:
    def test_header_is_16_bytes(self):
        assert len(_pcap_packet_header(100)) == 16

    def test_captured_and_original_length_equal(self):
        pkt_len = 200
        header = _pcap_packet_header(pkt_len)
        caplen = struct.unpack_from("<I", header, 8)[0]
        origlen = struct.unpack_from("<I", header, 12)[0]
        assert caplen == pkt_len
        assert origlen == pkt_len

    def test_timestamp_seconds_reasonable(self):
        import time

        before = int(time.time()) - 2
        header = _pcap_packet_header(50)
        ts_sec = struct.unpack_from("<I", header, 0)[0]
        after = int(time.time()) + 2
        assert before <= ts_sec <= after


# ── handle_pcap_chunk ────────────────────────────────────────────────────────


class TestHandlePcapChunk:
    def test_missing_session_id_returns_failure(self):
        ok, name, err = handle_pcap_chunk("", [])
        assert ok is False
        assert name is None
        assert err is not None

    def test_none_session_id_returns_failure(self):
        ok, name, err = handle_pcap_chunk(None, [])
        assert ok is False

    def test_empty_packets_creates_pcap_with_global_header(self, tmp_output_dir):
        ok, name, err = handle_pcap_chunk("session_empty", [], is_final_chunk=False)
        assert ok is True
        assert err is None
        path = os.path.join(str(tmp_output_dir), "session_empty.pcap")
        assert os.path.exists(path)
        with open(path, "rb") as f:
            data = f.read()
        assert data == _PCAP_GLOBAL_HEADER

    def test_valid_packet_written_to_file(self, tmp_output_dir):
        pkt_bytes = b"\xff" * 60
        b64 = base64.b64encode(pkt_bytes).decode()
        ok, name, err = handle_pcap_chunk("session_valid", [b64], is_final_chunk=False)
        assert ok is True
        path = os.path.join(str(tmp_output_dir), "session_valid.pcap")
        with open(path, "rb") as f:
            data = f.read()
        # global header + packet header (16 bytes) + packet data (60 bytes)
        assert len(data) == 24 + 16 + 60

    def test_multiple_packets_in_one_chunk(self, tmp_output_dir):
        pkts = [base64.b64encode(b"\xaa" * 40).decode() for _ in range(3)]
        ok, name, err = handle_pcap_chunk("session_multi", pkts, is_final_chunk=False)
        assert ok is True
        path = os.path.join(str(tmp_output_dir), "session_multi.pcap")
        size = os.path.getsize(path)
        expected = 24 + 3 * (16 + 40)
        assert size == expected

    def test_invalid_base64_skipped_silently(self, tmp_output_dir):
        valid_b64 = base64.b64encode(b"\x00" * 10).decode()
        packets = ["!!!not_b64!!!", valid_b64, "%%bad%%"]
        ok, name, err = handle_pcap_chunk("session_bad_b64", packets)
        assert ok is True
        path = os.path.join(str(tmp_output_dir), "session_bad_b64.pcap")
        size = os.path.getsize(path)
        # Only 1 valid packet written
        assert size == 24 + 16 + 10

    def test_is_final_chunk_true_returns_filename(self, tmp_output_dir):
        ok, name, err = handle_pcap_chunk("session_final", [], is_final_chunk=True)
        assert ok is True
        assert name == "session_final.pcap"

    def test_session_id_path_traversal_sanitised(self, tmp_output_dir):
        ok, name, err = handle_pcap_chunk("../../etc/passwd", [], is_final_chunk=True)
        assert ok is True
        # os.path.basename strips directory components
        assert name == "passwd.pcap"
        # Must NOT create a file outside tmp_output_dir
        assert not os.path.exists("/etc/passwd_pcap")

    def test_chunks_accumulate_across_calls(self, tmp_output_dir):
        pkt1 = base64.b64encode(b"\x01" * 20).decode()
        pkt2 = base64.b64encode(b"\x02" * 30).decode()
        handle_pcap_chunk("session_accum", [pkt1], is_final_chunk=False)
        handle_pcap_chunk("session_accum", [pkt2], is_final_chunk=True)
        path = os.path.join(str(tmp_output_dir), "session_accum.pcap")
        size = os.path.getsize(path)
        # global header written once + 2 packet records
        assert size == 24 + (16 + 20) + (16 + 30)

    def test_returned_filename_is_basename_dot_pcap(self, tmp_output_dir):
        ok, name, err = handle_pcap_chunk("my_session_id", [])
        assert ok is True
        assert name == "my_session_id.pcap"
        assert os.sep not in name
