"""
Unit tests for ueAnalysis.extract_ue_info with hand-written packet-table rows.

Real extraction is covered by the ue_sessions snapshot in
test_characterization.py (sample.pcap frame 9: null-scheme SUCI).
"""

import os
import sys

_SERVER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "server"))
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)

from ueAnalysis import _FIELDS, extract_ue_info

NGAP_STACK = "eth:ethertype:ip:sctp:ngap:nas-5gs"


def _row(protocols=NGAP_STACK, **fields):
    row = {name: "" for name in _FIELDS}
    row.update({"frame.number": "7", "frame.protocols": protocols,
                "ip.src": "10.1.1.1", "ip.dst": "10.1.1.2"})
    row.update(fields)
    return row


def _suci(scheme="0", supi_fmt="0", mcc="999", mnc="70", msin="0000000001"):
    return {
        "nas-5gs.mm.suci.supi_fmt": supi_fmt,
        "nas-5gs.mm.suci.scheme_id": scheme,
        "nas-5gs.mm.suci.msin": msin,
        "e212.mcc": mcc,
        "e212.mnc": mnc,
    }


def _extract(protocols=NGAP_STACK, **fields):
    return extract_ue_info(_row(protocols, **fields))


def test_null_scheme_suci_gives_imsi():
    assert _extract(**_suci()) == {
        "imsi": "999700000000001",
        "ip_src": "10.1.1.1",
        "ip_dst": "10.1.1.2",
        "frame_number": "7",
    }


def test_single_digit_mnc_is_zero_padded():
    assert _extract(**_suci(mcc="001", mnc="1"))["imsi"] == "001010000000001"


def test_concealed_suci_gives_no_imsi():
    # Protection scheme 1 (ECIES profile A): the MSIN field holds ciphertext.
    assert _extract(**_suci(scheme="1")) is None


def test_nai_format_suci_gives_no_imsi():
    assert _extract(**_suci(supi_fmt="1")) is None


def test_plain_imsi_field_wins():
    info = _extract(**{"e212.imsi": "001010123456789"}, **_suci())
    assert info["imsi"] == "001010123456789"


def test_tmsi_and_pdu_session_id():
    info = _extract(**{"nas-5gs.5g_tmsi": "0xc0000001", "nas-5gs.pdu_session_id": "1"})
    assert info["guti"] == "0xc0000001"
    assert info["pdu_session_id"] == "1"
    assert "imsi" not in info


def test_first_occurrence_is_used_and_ip_is_the_outer_header():
    info = _extract(**{"nas-5gs.pdu_session_id": "5,6", "ip.src": "10.1.1.1,172.16.0.1",
                       "ip.dst": "10.1.1.2,172.16.0.2"})
    assert info["pdu_session_id"] == "5"
    assert (info["ip_src"], info["ip_dst"]) == ("10.1.1.1", "10.1.1.2")


def test_frames_without_a_ue_protocol_are_ignored():
    assert _extract("eth:ethertype:ip:udp:dns", **_suci()) is None


def test_nas_relayed_over_http2_is_ignored():
    # AMF <-> SMF traffic: core-function IPs and no subscriber identity.
    stack = "sll:ethertype:ip:tcp:http2:mime_multipart:json:nas-5gs:nas-5gs"
    assert _extract(stack, **{"nas-5gs.pdu_session_id": "1"}) is None


def test_frame_without_ipv4_is_ignored():
    assert _extract("eth:ethertype:ipv6:sctp:ngap", **{"ip.src": "", "ip.dst": ""}, **_suci()) is None


def test_row_without_identities_returns_none():
    assert _extract() is None
