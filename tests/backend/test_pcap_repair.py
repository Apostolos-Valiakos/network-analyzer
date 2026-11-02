"""Tests for server/pcap_repair.py: only an incomplete tail is ever removed."""

import os
import shutil
import struct
import sys

_SERVER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "server"))
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)

from pcap_repair import trim_incomplete_tail

SAMPLE = os.path.join(os.path.dirname(__file__), "fixtures", "sample.pcap")


def _block(block_type, body=b"\0" * 8):
    length = 12 + len(body)
    head = struct.pack("<II", block_type, length)
    return head + body + struct.pack("<I", length)


def _section_header():
    body = b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1)
    return _block(0x0A0D0D0A, body)


def _pcapng(tmp_path, tail=b""):
    good = _section_header() + _block(1) + _block(6) + _block(6)
    path = tmp_path / "c.pcap"
    path.write_bytes(good + tail)
    return str(path), len(good)


def test_intact_pcapng_is_untouched(tmp_path):
    path, size = _pcapng(tmp_path)
    assert trim_incomplete_tail(path) == 0
    assert os.path.getsize(path) == size


def test_stray_bytes_are_trimmed(tmp_path):
    path, size = _pcapng(tmp_path, tail=b"\x01\x02\x03\x04")
    assert trim_incomplete_tail(path) == 4
    assert os.path.getsize(path) == size


def test_block_running_past_eof_is_trimmed(tmp_path):
    partial = _block(6, b"\x07" * 40)[:-10]
    path, size = _pcapng(tmp_path, tail=partial)
    assert trim_incomplete_tail(path) == len(partial)
    assert os.path.getsize(path) == size


def test_zero_filled_tail_is_trimmed(tmp_path):
    # Seen on captures copied while dumpcap was writing: 3,952 zero bytes.
    path, size = _pcapng(tmp_path, tail=b"\0" * 3952)
    assert trim_incomplete_tail(path) == 3952
    assert os.path.getsize(path) == size


def test_zeros_followed_by_data_are_left_alone(tmp_path):
    original = b"\0" * 64 + _block(6)
    path, size = _pcapng(tmp_path, tail=original)
    assert trim_incomplete_tail(path) == 0
    assert os.path.getsize(path) == size + len(original)


def test_corrupt_block_in_the_middle_is_left_alone(tmp_path):
    data = bytearray(_section_header() + _block(1) + _block(6) + _block(6))
    data[-4:] = b"\xff\xff\xff\xff"  # trailing length no longer matches
    path = tmp_path / "c.pcap"
    path.write_bytes(bytes(data))
    assert trim_incomplete_tail(str(path)) == 0
    assert os.path.getsize(path) == len(data)


def test_cut_off_classic_pcap_is_trimmed_to_last_full_record(tmp_path):
    path = tmp_path / "c.pcap"
    shutil.copy(SAMPLE, path)
    size = os.path.getsize(path)
    with open(path, "r+b") as f:
        f.truncate(size - 7)
    assert trim_incomplete_tail(str(path)) > 0
    # Trimming again finds nothing further to do.
    assert trim_incomplete_tail(str(path)) == 0


def test_intact_classic_pcap_is_untouched(tmp_path):
    path = tmp_path / "c.pcap"
    shutil.copy(SAMPLE, path)
    assert trim_incomplete_tail(str(path)) == 0


def test_non_capture_file_is_untouched(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_bytes(b"just text")
    assert trim_incomplete_tail(str(path)) == 0
    assert path.read_bytes() == b"just text"
