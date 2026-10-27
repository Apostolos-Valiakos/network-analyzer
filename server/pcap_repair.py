# server/pcap_repair.py
"""
Trims incomplete trailing data from pcap / pcapng captures.

Captures that were cut off mid-write (dumpcap killed, ring-buffer rotation,
interrupted copy) end in a partial record. Every complete packet is still
readable, but tshark reports "cut short in the middle of a packet" and exits
non-zero. Truncating after the last complete record makes the file clean.

Only a *truncated* tail is removed. A structurally corrupt block in the middle
of a pcapng file is left untouched so no readable data is ever discarded.
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
            return None
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
        f.seek(off + 8)
        incl_len = struct.unpack(endian + "I", f.read(4))[0]
        if off + _PCAP_RECORD_HDR_LEN + incl_len > size:
            break
        off += _PCAP_RECORD_HDR_LEN + incl_len
    return off


def trim_incomplete_tail(path: str) -> int:
    """
    Truncates `path` right after its last complete record.
    Returns the number of bytes removed (0 if the file is intact, corrupt,
    or not a pcap/pcapng capture).
    """
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            magic = f.read(4)
            if magic == _PCAPNG_SHB:
                valid = _pcapng_valid_length(f, size)
            elif magic in _PCAP_MAGICS and size >= _PCAP_GLOBAL_HDR_LEN:
                valid = _pcap_valid_length(f, size, _PCAP_MAGICS[magic])
            else:
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
