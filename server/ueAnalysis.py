import logging
import re
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


_ADDRESS_FIELDS = [
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
    "nas-5gs.pdu_session_id",
    "nas-5gs.sm.pdu_addr_inf_ipv4",
    "ngap.RAN_UE_NGAP_ID",
    "tcp.stream",
    "http2.streamid",
    "http2.headers.path",
]

# SBI URLs that name the subscriber, e.g. the AMF's N1N2 message transfer
# /namf-comm/v1/ue-contexts/imsi-001010123456780/n1-n2-messages
_SBI_IMSI = re.compile(r"/ue-contexts/imsi-(\d{5,15})(?:/|$)")


def _tokens(value: str) -> List[str]:
    return [t for t in value.split(",") if t] if value else []


def ue_addresses(rows) -> Dict[str, Dict[str, str]]:
    """{IMSI: {"ipv4", "pdu_session_id", "frame_number", "ip_src", "ip_dst"}}
    from PDU Session Establishment Accept messages (PDU address information).

    The Accept is linked to a subscriber in one of two ways:
      - SBI: the SMF sends it to the AMF over HTTP/2, unciphered. The request
        URL of the same HTTP/2 stream names the subscriber (/ue-contexts/imsi-…).
      - NGAP: when NAS is not ciphered, the Accept carries the RAN UE NGAP ID
        that the UE's registration (with its IMSI) used on the same gNB–AMF
        association.
    The last address seen for an IMSI wins.
    """
    rows = list(rows)
    stream_imsi: Dict[tuple, str] = {}  # (tcp.stream, http2 stream id) -> IMSI
    ran_id_imsi: Dict[tuple, str] = {}  # (association, RAN UE NGAP ID) -> IMSI
    for row in rows:
        imsi_match = _SBI_IMSI.search(row["http2.headers.path"])
        streams = _tokens(row["http2.streamid"])
        if imsi_match and len(streams) == 1:
            stream_imsi[(row["tcp.stream"], streams[0])] = imsi_match.group(1)
        first = {name: packet_table.first(value) for name, value in row.items()}
        imsi = first["e212.imsi"] or _imsi_from_null_scheme_suci(first)
        ran_id = first["ngap.RAN_UE_NGAP_ID"]
        if imsi and ran_id and first["ip.src"]:
            association = tuple(sorted((first["ip.src"], first["ip.dst"])))
            ran_id_imsi[(association, ran_id)] = imsi

    addresses: Dict[str, Dict[str, str]] = {}
    for row in rows:
        address = packet_table.first(row["nas-5gs.sm.pdu_addr_inf_ipv4"])
        if not address:
            continue
        first = {name: packet_table.first(value) for name, value in row.items()}
        imsi = None
        for stream_id in _tokens(row["http2.streamid"]):
            imsi = stream_imsi.get((row["tcp.stream"], stream_id))
            if imsi:
                break
        if not imsi and first["ngap.RAN_UE_NGAP_ID"]:
            association = tuple(sorted((first["ip.src"], first["ip.dst"])))
            imsi = ran_id_imsi.get((association, first["ngap.RAN_UE_NGAP_ID"]))
        if imsi:
            addresses[imsi] = {
                "ipv4": address,
                "pdu_session_id": first["nas-5gs.pdu_session_id"],
                "frame_number": first["frame.number"],
                "ip_src": first["ip.src"],
                "ip_dst": first["ip.dst"],
            }
    return addresses


def initialize_analysis_for_ue(filepath: str) -> List[Dict[str, Any]]:
    """Extracts UE information (IMSI, GUTI, PDU session, UE IPv4 address) from
    a PCAP. Every record of an IMSI whose PDU address is known gets
    "ue_ip_addr_ipv4"; an IMSI seen only in an SBI Accept gets a record of its own.

    Errors reading the capture propagate, so the caller can tell "no UEs"
    from "could not look".
    """
    records = (extract_ue_info(row) for row in packet_table.row_dicts(filepath, _FIELDS))
    records = [record for record in records if record]

    addresses = ue_addresses(packet_table.row_dicts(filepath, _ADDRESS_FIELDS))
    for record in records:
        found = addresses.get(record.get("imsi"))
        if found:
            record["ue_ip_addr_ipv4"] = found["ipv4"]
    known = {record.get("imsi") for record in records}
    for imsi, found in addresses.items():
        if imsi not in known:
            records.append({
                "imsi": imsi,
                "pdu_session_id": found["pdu_session_id"],
                "ue_ip_addr_ipv4": found["ipv4"],
                "ip_src": found["ip_src"],
                "ip_dst": found["ip_dst"],
                "frame_number": found["frame_number"],
            })
    return records
