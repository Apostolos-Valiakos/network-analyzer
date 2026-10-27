import os
import base64
import struct
import time
from typing import List, Union

# Resolve path relative to this file so it always points to
# server/generated_pcaps/ regardless of where Flask is launched from.
_HERE = os.path.dirname(os.path.abspath(__file__))
PCAP_OUTPUT_DIR = os.path.join(_HERE, "generated_pcaps")
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


def handle_pcap_chunk(
    session_id: str, packets: List[str], is_final_chunk: bool = False
):
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
                    f.write(_pcap_packet_header(len(pkt_bytes)))
                    f.write(pkt_bytes)
                except Exception as e:
                    print(f"Error decoding packet: {e}")
                    continue
        return True, safe_filename, None
    except Exception as e:
        return False, None, str(e)


##
# Legacy function - Kept for backward compatibility if needed,
# but rewritten to be safer.
def save_pcap_data(raw_binary_data):
    try:
        # Use a simpler naming convention
        import uuid

        filename = f"capture_{uuid.uuid4().hex[:8]}.pcap"
        file_path = os.path.join(PCAP_OUTPUT_DIR, filename)

        with open(file_path, "wb") as f:
            f.write(raw_binary_data)

        return True, "File saved successfully", filename
    except Exception as e:
        return False, str(e), None
