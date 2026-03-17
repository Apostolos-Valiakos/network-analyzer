import pyshark
import asyncio
from typing import List, Dict, Any


##
# Initializes a pyshark capture for UE-specific analysis.
# REFACTOR: Removed "all_packets.json" write to improve performance.
# REFACTOR: Improved Asyncio loop handling for Flask compatibility.
def initialize_analysis_for_ue(filepath: str) -> List[Dict[str, Any]]:
    """
    Extracts UE information (IMSI, GUTI, IPs) from a PCAP.
    """
    # Fix for Pyshark in Flask: Create a new loop if the current one is closed/missing
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            asyncio.set_event_loop(asyncio.new_event_loop())
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    try:
        # KeepPacket=False saves RAM by not keeping packets in memory after parsing
        capture = pyshark.FileCapture(filepath, keep_packets=False)

        all_ue_info = []

        for packet in capture:
            ue_info = extract_ue_info(packet)
            if ue_info:
                all_ue_info.append(ue_info)

        capture.close()
        return all_ue_info

    except Exception as e:
        print(f"UE Analysis Error: {e}")
        return []


##
# Extracts specific UE fields (IMSI, GUTI, PDU Session) from a packet.
def extract_ue_info(packet):
    ue_info = {}
    found_info = False

    try:
        # Iterate over layers safely
        for layer in packet.layers:
            # Check for NGAP / NAS-5GS layers specifically
            if layer.layer_name in ["ngap", "nas_5gs", "e2ap"]:
                # Helper to safely get field values
                def get_field(names):
                    for name in names:
                        if hasattr(layer, name):
                            return getattr(layer, name)
                    return None

                # Extract IDs
                imsi = get_field(["e212.imsi", "nas_5gs.imsi", "imsi"])
                if imsi:
                    ue_info["imsi"] = imsi
                    found_info = True

                guti = get_field(["nas_5gs.5g_guti", "5g_guti", "guti"])
                if guti:
                    ue_info["guti"] = guti
                    found_info = True

                pdu_id = get_field(["nas_5gs.pdu_session_id", "pdu_session_id"])
                if pdu_id:
                    ue_info["pdu_session_id"] = pdu_id
                    found_info = True

    except Exception:
        pass

    # Basic IP extraction if we found UE markers
    if found_info and "IP" in packet:
        ue_info["ip_src"] = packet.ip.src
        ue_info["ip_dst"] = packet.ip.dst
        ue_info["frame_number"] = packet.number
        return ue_info

    return None
