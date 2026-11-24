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


# ── UE addresses from PDU Session Establishment Accept ───────────────────────

from ueAnalysis import _ADDRESS_FIELDS, ue_addresses  # noqa: E402

SBI_STACK = "sll:ethertype:ip:tcp:http2:mime_multipart:json:nas-5gs:nas-5gs:ngap:ngap"
N1N2_PATH = "/namf-comm/v1/ue-contexts/imsi-001010123456780/n1-n2-messages"


def _arow(**fields):
    row = {name: "" for name in _ADDRESS_FIELDS}
    row.update({"frame.number": "1", "frame.protocols": SBI_STACK,
                "ip.src": "127.0.0.1", "ip.dst": "127.0.0.5"})
    row.update(fields)
    return row


class TestUeAddresses:
    def test_sbi_accept_is_linked_through_its_http2_stream(self):
        rows = [
            _arow(**{"frame.number": "10", "tcp.stream": "271", "http2.streamid": "49",
                     "http2.headers.path": N1N2_PATH}),
            _arow(**{"frame.number": "11", "tcp.stream": "271", "http2.streamid": "49",
                     "nas-5gs.sm.pdu_addr_inf_ipv4": "10.45.0.101",
                     "nas-5gs.pdu_session_id": "1"}),
        ]
        found = ue_addresses(rows)
        assert found["001010123456780"]["ipv4"] == "10.45.0.101"
        assert found["001010123456780"]["pdu_session_id"] == "1"

    def test_other_stream_or_connection_is_not_linked(self):
        rows = [
            _arow(**{"tcp.stream": "271", "http2.streamid": "49", "http2.headers.path": N1N2_PATH}),
            _arow(**{"tcp.stream": "271", "http2.streamid": "51",
                     "nas-5gs.sm.pdu_addr_inf_ipv4": "10.45.0.101"}),
            _arow(**{"tcp.stream": "272", "http2.streamid": "49",
                     "nas-5gs.sm.pdu_addr_inf_ipv4": "10.45.0.102"}),
        ]
        assert ue_addresses(rows) == {}

    def test_unciphered_ngap_accept_is_linked_through_the_ran_ue_id(self):
        registration = _arow(**{"frame.protocols": NGAP_STACK, "ip.src": "10.1.1.1",
                                "ip.dst": "10.1.1.2", "ngap.RAN_UE_NGAP_ID": "3",
                                "e212.imsi": "999700000000001"})
        accept = _arow(**{"frame.protocols": NGAP_STACK, "ip.src": "10.1.1.2",
                          "ip.dst": "10.1.1.1", "ngap.RAN_UE_NGAP_ID": "3",
                          "nas-5gs.sm.pdu_addr_inf_ipv4": "10.45.0.7"})
        other_gnb = _arow(**{"frame.protocols": NGAP_STACK, "ip.src": "10.1.1.2",
                             "ip.dst": "10.1.1.9", "ngap.RAN_UE_NGAP_ID": "3",
                             "nas-5gs.sm.pdu_addr_inf_ipv4": "10.45.0.8"})
        assert ue_addresses([registration, accept, other_gnb]) == {
            "999700000000001": {
                "ipv4": "10.45.0.7", "pdu_session_id": "", "frame_number": "1",
                "ip_src": "10.1.1.2", "ip_dst": "10.1.1.1",
            }
        }

    def test_accept_without_a_known_subscriber_is_ignored(self):
        assert ue_addresses([_arow(**{"nas-5gs.sm.pdu_addr_inf_ipv4": "10.45.0.101"})]) == {}


def test_upload_stores_the_ue_address(monkeypatch):
    """initialize_analysis_for_ue sets the key the upload route stores in
    ue_sessions.ip_address."""
    import ueAnalysis

    reg = {name: "" for name in _FIELDS}
    reg.update({"frame.number": "5", "frame.protocols": NGAP_STACK, "ip.src": "10.1.1.1",
                "ip.dst": "10.1.1.2", "e212.imsi": "001010123456780"})

    def fake_rows(path, fields):
        if fields is ueAnalysis._FIELDS:
            return iter([reg])
        return iter([
            _arow(**{"tcp.stream": "1", "http2.streamid": "3", "http2.headers.path": N1N2_PATH}),
            _arow(**{"tcp.stream": "1", "http2.streamid": "3",
                     "nas-5gs.sm.pdu_addr_inf_ipv4": "10.45.0.101"}),
            # an IMSI seen only over SBI gets its own record
            _arow(**{"tcp.stream": "2", "http2.streamid": "5",
                     "http2.headers.path": "/namf-comm/v1/ue-contexts/imsi-001010000000009/n1-n2-messages"}),
            _arow(**{"tcp.stream": "2", "http2.streamid": "5",
                     "nas-5gs.sm.pdu_addr_inf_ipv4": "10.45.0.109"}),
        ])

    monkeypatch.setattr(ueAnalysis.packet_table, "row_dicts", fake_rows)
    records = ueAnalysis.initialize_analysis_for_ue("x.pcap")
    by_imsi = {r["imsi"]: r for r in records}
    assert by_imsi["001010123456780"]["ue_ip_addr_ipv4"] == "10.45.0.101"
    assert by_imsi["001010123456780"]["frame_number"] == "5"
    assert by_imsi["001010000000009"]["ue_ip_addr_ipv4"] == "10.45.0.109"
