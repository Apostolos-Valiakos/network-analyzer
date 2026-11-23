# server/pcap_repair.py
"""
Trims incomplete trailing data from pcap / pcapng captures.

Captures that were cut off mid-write (dumpcap killed, ring-buffer rotation,
interrupted copy) end in a partial record. Every complete packet is still
readable, but tshark reports "cut short in the middle of a packet" and exits
non-zero. Truncating after the last complete record makes the file clean.

Only a *truncated* tail is removed, including a zero-filled one. A structurally
corrupt block in the middle of a pcapng file is left untouched so no readable
data is ever discarded.
"""
import logging
import os
import struct

logger = logging.getLogger(__name__)

_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"  # palindrome: same in either byte order
_PCAPNG_BOM = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}

# Classic pcap magics (microsecond and nanosecond variants) -> byte order
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}
_PCAP_GLOBAL_HDR_LEN = 24
_PCAP_RECORD_HDR_LEN = 16


def _only_zeros_from(f, offset: int) -> bool:
    f.seek(offset)
    while True:
        chunk = f.read(1 << 20)
        if not chunk:
            return True
        if chunk.count(0) != len(chunk):
            return False


def _pcapng_valid_length(f, size: int):
    """Returns the offset after the last complete block, or None if the file
    is corrupt (rather than truncated) and must not be trimmed."""
    off, endian = 0, "<"
    while off < size:
        if off + 12 > size:
            return off  # tail too short to be a block
        f.seek(off)
        hdr = f.read(12)
        if hdr[:4] == _PCAPNG_SHB:
            endian = _PCAPNG_BOM.get(hdr[8:12])
            if endian is None:
                return None
        blen = struct.unpack(endian + "I", hdr[4:8])[0]
        if blen < 12 or blen % 4:
            # All zeros to EOF is unwritten space from copying a capture while
            # dumpcap was still writing it, not a damaged block.
            return off if _only_zeros_from(f, off) else None
        if off + blen > size:
            return off  # last block runs past EOF
        f.seek(off + blen - 4)
        if struct.unpack(endian + "I", f.read(4))[0] != blen:
            return None
        off += blen
    return off


def _pcap_valid_length(f, size: int, endian: str) -> int:
    """Returns the offset after the last complete record of a classic pcap."""
    off = _PCAP_GLOBAL_HDR_LEN
    while off + _PCAP_RECORD_HDR_LEN <= size:
        f.seek(off)
        record_header = f.read(_PCAP_RECORD_HDR_LEN)
        # Zeros parse as empty records; all zeros to EOF is unwritten space
        # from copying a capture mid-write, as for pcapng.
        if record_header.count(0) == _PCAP_RECORD_HDR_LEN and _only_zeros_from(f, off):
            break
        incl_len = struct.unpack(endian + "I", record_header[8:12])[0]
        if off + _PCAP_RECORD_HDR_LEN + incl_len > size:
            break
        off += _PCAP_RECORD_HDR_LEN + incl_len
    return off


def _valid_length(f, size: int):
    """Offset after the last complete record of the open capture `f`, None if
    a block before the end is corrupt, or False if it is not a capture."""
    f.seek(0)
    magic = f.read(4)
    if magic == _PCAPNG_SHB:
        return _pcapng_valid_length(f, size)
    if magic in _PCAP_MAGICS and size >= _PCAP_GLOBAL_HDR_LEN:
        return _pcap_valid_length(f, size, _PCAP_MAGICS[magic])
    return False


def complete_length(path: str):
    """
    Number of leading bytes of `path` that hold complete records, without
    changing the file: safe on a capture dumpcap is still writing.

    Returns the file size for an intact capture, a smaller value when the tail
    is incomplete (partial record or unwritten zeros), and None when the file
    is not a capture, is corrupt before the end, or cannot be read; callers
    should then use the whole file.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            valid = _valid_length(f, size)
    except OSError:
        logger.exception("Could not check capture %s", path)
        return None
    if valid is False or valid is None or valid == 0:
        return None
    return min(valid, size)


def trim_incomplete_tail(path: str) -> int:
    """
    Truncates `path` right after its last complete record.
    Returns the number of bytes removed (0 if the file is intact, corrupt,
    or not a pcap/pcapng capture).

    Never use this on a capture that is still being written (the sensor's
    active ring file): use complete_length() and read that many bytes instead.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            valid = _valid_length(f, size)
            if valid is False:
                return 0
            if valid is None:
                logger.warning("Not trimming %s: corrupt block before end of file", path)
                return 0
            if valid == 0 or valid >= size:
                return 0
            f.truncate(valid)
    except OSError:
        logger.exception("Could not check/trim capture %s", path)
        return 0

    removed = size - valid
    logger.warning("Trimmed %d incomplete trailing bytes from %s", removed, path)
    return removed
