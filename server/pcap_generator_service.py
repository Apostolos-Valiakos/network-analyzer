import base64
import logging
import os
import struct
import time
from typing import List

import settings

logger = logging.getLogger(__name__)

# Module-level name kept so tests can monkeypatch it.
PCAP_OUTPUT_DIR = settings.PCAP_GEN_OUTPUT_DIR
os.makedirs(PCAP_OUTPUT_DIR, exist_ok=True)

# PCAP global header — written once at the start of each new file.
# Little-endian, magic 0xa1b2c3d4, version 2.4, LINKTYPE_ETHERNET (1).
_PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,  # magic number
    2, 4,        # version major / minor
    0,           # timezone offset (GMT)
    0,           # timestamp accuracy
    65535,       # snapshot length
    1,           # link-layer type: Ethernet
)


def _pcap_packet_header(pkt_len: int) -> bytes:
    ts = time.time()
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    return struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len)


def handle_pcap_chunk(session_id: str, packets: List[str]):
    """Appends `packets` (base64 frames) to <session_id>.pcap, creating it with
    a pcap header first. Whether this is the last chunk only matters to the
    caller, which marks the record complete."""
    if not session_id:
        return False, None, "Missing session_id"

    safe_filename = f"{os.path.basename(session_id)}.pcap"
    file_path = os.path.join(PCAP_OUTPUT_DIR, safe_filename)

    try:
        is_new_file = not os.path.exists(file_path)
        with open(file_path, "ab") as f:
            if is_new_file:
                f.write(_PCAP_GLOBAL_HEADER)
            for b64_pkt in packets:
                if not b64_pkt:
                    continue
                try:
                    pkt_bytes = base64.b64decode(b64_pkt)
                except ValueError as e:  # binascii.Error: not valid base64
                    logger.warning("Skipping a packet that is not valid base64: %s", e)
                    continue
                # Write errors (disk full, ...) are real failures: the outer
                # handler reports them instead of skipping packet after packet.
                f.write(_pcap_packet_header(len(pkt_bytes)))
                f.write(pkt_bytes)
        return True, safe_filename, None
    except Exception as e:
        logger.exception("Writing chunk to %s failed", file_path)
        return False, None, str(e)

