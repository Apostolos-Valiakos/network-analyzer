"""
Tests for server/role_evidence.py: the evidence collector shared by the role
engine and the sensor's live DPI agent. Serialization and merging must give
exactly the roles a single pass over the same packets gives.
"""

import json
import os
import subprocess
import sys

import pytest

from role_engine import resolve_roles
from role_evidence import (
    EVIDENCE_FORMAT,
    IpEvidence,
    PcapObservations,
    _infer_cross_ip,
    _parse_line,
)

SERVER_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "server")


def line(src="", dst="", protos="", sctp_src="", sctp_dst="", udp_src="",
         udp_dst="", tcp_dst="", ngap="", ngap_ue="", e2ap="", pfcp="", path=""):
    return "\t".join([src, dst, protos, sctp_src, sctp_dst, udp_src, udp_dst,
                      tcp_dst, ngap, ngap_ue, e2ap, pfcp, path])


# A small 5G core: AMF/gNB over NGAP, SMF/UPF over PFCP, an SBI call, GTP-U
# in both directions, and RIC Redis/E2T clients.
LINES = [
    line("10.0.0.2", "10.0.0.1", "sctp:ngap", "9487", "38412", ngap="15", ngap_ue="1"),
    line("10.0.0.1", "10.0.0.2", "sctp:ngap", "38412", "9487", ngap="15"),
    line("10.0.0.3", "10.0.0.4", "udp:pfcp", udp_src="8805", udp_dst="8805", pfcp="50"),
    line("10.0.0.4", "10.0.0.3", "udp:pfcp", udp_src="8805", udp_dst="8805", pfcp="51"),
    line("10.0.0.5", "10.0.0.3", "tcp:http2", tcp_dst="7777", path="/nsmf-pdusession/v1/sm-contexts"),
    line("10.0.0.2,10.45.0.2", "10.0.0.4,8.8.8.8", "udp:gtp:ip", udp_src="2152", udp_dst="2152"),
    line("10.0.0.2,10.45.0.2", "10.0.0.4,8.8.8.8", "udp:gtp:ip", udp_src="2152", udp_dst="2152"),
    line("10.0.0.4,8.8.8.8", "10.0.0.2,10.45.0.2", "udp:gtp:ip", udp_src="2152", udp_dst="2152"),
    line("10.0.0.9", "10.0.0.7", "tcp", tcp_dst="6379"),
    line("10.0.0.9", "10.0.0.8", "tcp", tcp_dst="38000"),
    line("10.0.0.8", "10.0.0.10", "sctp:e2ap", "36421", "5000", e2ap="1"),
]


def observe(lines):
    obs = PcapObservations()
    for ln in lines:
        _parse_line(ln, obs)
    return obs


def roles(obs):
    _infer_cross_ip(obs)
    return {ip: (a.role, a.confidence, a.reasoning) for ip, a in resolve_roles(obs).items()}


class TestSerialization:
    def test_round_trip_through_json_keeps_roles(self):
        direct = observe(LINES)
        copied = PcapObservations.from_dict(json.loads(json.dumps(observe(LINES).to_dict())))
        assert roles(copied) == roles(direct)

    def test_round_trip_keeps_every_counter(self):
        obs = observe(LINES)
        copied = PcapObservations.from_dict(json.loads(json.dumps(obs.to_dict())))
        assert copied.to_dict() == obs.to_dict()

    def test_gtpu_flows_are_counted_not_listed(self):
        obs = observe(LINES)
        assert obs.gtpu_flows[("10.0.0.2", "10.0.0.4", "10.45.0.2", "8.8.8.8")] == 2
        assert len(obs.gtpu_flows) == 2

    def test_unknown_format_is_refused(self):
        data = observe(LINES).to_dict()
        data["format"] = EVIDENCE_FORMAT + 1
        with pytest.raises(ValueError, match="unsupported evidence format"):
            PcapObservations.from_dict(data)

    def test_unknown_counters_are_ignored_and_missing_ones_default(self):
        ev = IpEvidence.from_dict({"ip": "10.0.0.1", "ngap_amf_side": 3, "future_counter": 7})
        assert ev.ngap_amf_side == 3
        assert ev.pfcp_upf_side == 0
        assert not hasattr(ev, "future_counter")

    def test_inferred_observations_cannot_be_serialized(self):
        obs = observe(LINES)
        _infer_cross_ip(obs)
        with pytest.raises(ValueError):
            obs.to_dict()


class TestMerge:
    @pytest.mark.parametrize("split", [1, 4, 6, 9])
    def test_merged_windows_give_the_single_pass_roles(self, split):
        merged = observe(LINES[:split])
        merged.merge(observe(LINES[split:]))
        assert roles(merged) == roles(observe(LINES))

    def test_merge_adds_counts_and_combines_sets(self):
        a, b = observe(LINES), observe(LINES)
        a.merge(b)
        amf = a.evidence["10.0.0.1"]
        assert amf.ngap_amf_side == 2 * b.evidence["10.0.0.1"].ngap_amf_side
        assert amf.peers == {"10.0.0.2"}
        assert a.gtpu_flows[("10.0.0.2", "10.0.0.4", "10.45.0.2", "8.8.8.8")] == 4

    def test_merge_copies_new_ips_instead_of_sharing_them(self):
        a, b = PcapObservations(), observe(LINES)
        before = b.evidence["10.0.0.1"].ngap_amf_side
        a.merge(b)
        a.evidence["10.0.0.1"].ngap_amf_side += 100
        a.evidence["10.0.0.1"].peers.add("10.9.9.9")
        assert b.evidence["10.0.0.1"].ngap_amf_side == before
        assert "10.9.9.9" not in b.evidence["10.0.0.1"].peers

    def test_merge_after_inference_is_refused(self):
        a, b = observe(LINES), observe(LINES)
        _infer_cross_ip(a)
        with pytest.raises(ValueError):
            a.merge(b)
        with pytest.raises(ValueError):
            b.merge(a)

    def test_inference_runs_once(self):
        obs = observe(LINES)
        _infer_cross_ip(obs)
        with pytest.raises(ValueError):
            _infer_cross_ip(obs)

    def test_ip_evidence_of_another_ip_is_refused(self):
        with pytest.raises(ValueError):
            IpEvidence("10.0.0.1").merge(IpEvidence("10.0.0.2"))


def test_module_imports_without_flask_or_the_database():
    """The sensor image has no Flask or SQLAlchemy: role_evidence must not
    pull them in."""
    code = (
        "import sys, role_evidence; "
        "bad = [m for m in ('flask', 'flask_sqlalchemy', 'sqlalchemy', 'models', "
        "'packet_table') if m in sys.modules]; "
        "print(','.join(bad))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], cwd=SERVER_DIR, capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == ""
