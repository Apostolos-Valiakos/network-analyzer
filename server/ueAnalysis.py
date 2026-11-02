import logging
from typing import Any, Dict, List, Optional

import packet_table

logger = logging.getLogger(__name__)

# Protocols that carry UE identities directly. NAS-5GS sent inside NGAP is part
# of the same frame. NAS relayed between core functions over HTTP/2 (SBI) is left
# out: it has no subscriber identity, and its IPs are core functions, not a UE.
_UE_PROTOCOLS = {"ngap", "nas-5gs", "e2ap"}
_EXCLUDED_PROTOCOL = "http2"

# SUCI with SUPI format 0 (IMSI) and protection scheme 0 (null scheme) carries
# the IMSI in clear: MCC + MNC + MSIN.
_SUPI_FORMAT_IMSI = "0"
_NULL_SCHEME = "0"

_FIELDS = [
    "frame.number",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "e212.imsi",
    "e212.mcc",
    "e212.mnc",
    "nas-5gs.mm.suci.supi_fmt",
    "nas-5gs.mm.suci.scheme_id",
    "nas-5gs.mm.suci.msin",
    "nas-5gs.5g_tmsi",
    "nas-5gs.pdu_session_id",
]


def _imsi_from_null_scheme_suci(row: Dict[str, str]) -> Optional[str]:
    msin = row["nas-5gs.mm.suci.msin"]
    if not msin:
        return None
    if row["nas-5gs.mm.suci.supi_fmt"] != _SUPI_FORMAT_IMSI:
        return None
    if row["nas-5gs.mm.suci.scheme_id"] != _NULL_SCHEME:
        return None  # concealed SUCI: the MSIN field holds ciphertext
    mcc, mnc = row["e212.mcc"], row["e212.mnc"]
    if not (mcc and mnc):
        return None
    # tshark shows the MNC as a number; 2-digit MNCs keep a leading zero.
    return f"{mcc}{mnc.zfill(2)}{msin}"


def extract_ue_info(row: Dict[str, str]) -> Optional[Dict[str, str]]:
    """UE fields (IMSI, GUTI, PDU session) from one packet-table row, or None."""
    protocols = set(row["frame.protocols"].split(":"))
    if not (protocols & _UE_PROTOCOLS) or _EXCLUDED_PROTOCOL in protocols:
        return None
    if not row["ip.src"]:
        return None

    # A frame can hold several occurrences of a field; the first one is used.
    row = {name: packet_table.first(value) for name, value in row.items()}

    ue_info = {}
    imsi = row["e212.imsi"] or _imsi_from_null_scheme_suci(row)
    if imsi:
        ue_info["imsi"] = imsi
    # The 5G-TMSI is the UE-specific part of the 5G-GUTI.
    if row["nas-5gs.5g_tmsi"]:
        ue_info["guti"] = row["nas-5gs.5g_tmsi"]
    if row["nas-5gs.pdu_session_id"]:
        ue_info["pdu_session_id"] = row["nas-5gs.pdu_session_id"]

    if not ue_info:
        return None
    ue_info["ip_src"] = row["ip.src"]
    ue_info["ip_dst"] = row["ip.dst"]
    ue_info["frame_number"] = row["frame.number"]
    return ue_info


def initialize_analysis_for_ue(filepath: str) -> List[Dict[str, Any]]:
    """Extracts UE information (IMSI, GUTI, PDU session) from a PCAP."""
    try:
        records = (extract_ue_info(row) for row in packet_table.row_dicts(filepath, _FIELDS))
        return [record for record in records if record]
    except Exception:
        logger.exception("UE analysis failed on %s", filepath)
        return []
