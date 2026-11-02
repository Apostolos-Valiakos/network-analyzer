"""
Unit tests for the evidence-based role engine (server/role_engine.py).

Most tests build synthetic tshark output lines — no tshark, no DB needed.
The integration test at the bottom runs the real engine against the sample
pcap shipped in server/generated_pcaps/.
"""

import os
import shutil

import pytest

import role_engine
from role_engine import (
    ROLE_ENGINE_VERSION,
    PcapObservations,
    _parse_line,
    _infer_cross_ip,
    assess_pcap,
    get_or_compute_roles,
    resolve_roles,
    roles_as_strings,
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def make_line(
    src="",
    dst="",
    protos="",
    sctp_src="",
    sctp_dst="",
    udp_src="",
    udp_dst="",
    tcp_dst="",
    ngap="",
    ngap_ue="",
    e2ap="",
    pfcp="",
    path="",
):
    """Build one tab-separated line in the collector's field order."""
    return "\t".join(
        [src, dst, protos, sctp_src, sctp_dst, udp_src, udp_dst, tcp_dst,
         ngap, ngap_ue, e2ap, pfcp, path]
    )


def obs_from_lines(*lines):
    obs = PcapObservations()
    for line in lines:
        _parse_line(line, obs)
    _infer_cross_ip(obs)
    return obs


def roles_from_lines(*lines):
    return roles_as_strings(resolve_roles(obs_from_lines(*lines)))


# ── Direction-awareness (regression: request/response must not flip roles) ───


class TestDirectionAwareness:
    NGAP_REQ = make_line("10.0.0.1", "10.0.0.2", "eth:ethertype:ip:sctp:ngap",
                         sctp_src="51670", sctp_dst="38412", ngap="21")
    NGAP_RESP = make_line("10.0.0.2", "10.0.0.1", "eth:ethertype:ip:sctp:ngap",
                          sctp_src="38412", sctp_dst="51670", ngap="21")

    def test_ngap_request_alone(self):
        roles = roles_from_lines(self.NGAP_REQ)
        assert roles == {"10.0.0.1": "gNB", "10.0.0.2": "AMF"}

    def test_ngap_response_does_not_flip(self):
        """NGSetupResponse (AMF→gNB, same procedureCode) must reinforce,
        not swap, the labels — the core defect of the old engine."""
        roles = roles_from_lines(self.NGAP_REQ, self.NGAP_RESP)
        assert roles == {"10.0.0.1": "gNB", "10.0.0.2": "AMF"}

    def test_ngap_response_alone(self):
        roles = roles_from_lines(self.NGAP_RESP)
        assert roles == {"10.0.0.1": "gNB", "10.0.0.2": "AMF"}

    def test_e2ap_request_and_response(self):
        req = make_line("10.1.0.5", "10.1.0.9", "eth:ethertype:ip:sctp:e2ap",
                        sctp_src="40000", sctp_dst="36422", e2ap="1")
        resp = make_line("10.1.0.9", "10.1.0.5", "eth:ethertype:ip:sctp:e2ap",
                         sctp_src="36422", sctp_dst="40000", e2ap="1")
        roles = roles_from_lines(req, resp)
        assert roles == {"10.1.0.5": "E2_NODE", "10.1.0.9": "NEAR_RT_RIC"}

    def test_pfcp_session_request_and_response(self):
        req = make_line("10.2.0.4", "10.2.0.7", "eth:ethertype:ip:udp:pfcp",
                        udp_src="8805", udp_dst="8805", pfcp="50")
        resp = make_line("10.2.0.7", "10.2.0.4", "eth:ethertype:ip:udp:pfcp",
                         udp_src="8805", udp_dst="8805", pfcp="51")
        roles = roles_from_lines(req, resp)
        assert roles == {"10.2.0.4": "SMF", "10.2.0.7": "UPF"}

    def test_pfcp_session_report_request_comes_from_upf(self):
        report = make_line("10.2.0.7", "10.2.0.4", "eth:ethertype:ip:udp:pfcp",
                           udp_src="8805", udp_dst="8805", pfcp="56")
        roles = roles_from_lines(report)
        assert roles == {"10.2.0.7": "UPF", "10.2.0.4": "SMF"}

    def test_pfcp_heartbeat_only_is_ambiguous(self):
        hb = make_line("10.2.0.3", "10.2.0.6", "eth:ethertype:ip:udp:pfcp",
                       udp_src="8805", udp_dst="8805", pfcp="1")
        hb2 = make_line("10.2.0.6", "10.2.0.3", "eth:ethertype:ip:udp:pfcp",
                        udp_src="8805", udp_dst="8805", pfcp="2")
        roles = roles_from_lines(hb, hb2)
        assert roles == {"10.2.0.3": "PFCP_NODE", "10.2.0.6": "PFCP_NODE"}

    def test_ngap_embedded_in_sbi_produces_no_ngap_evidence(self):
        """NGAP PDUs inside namf-comm multipart bodies ride over TCP —
        without SCTP 38412 they must not label anyone gNB/AMF."""
        line = make_line("10.0.0.9", "10.0.0.8", "eth:ethertype:ip:tcp:http2:ngap",
                         tcp_dst="7777", ngap="21")
        roles = roles_from_lines(line)
        assert "gNB" not in roles.values()
        assert "AMF" not in roles.values()


# ── SBI detection ─────────────────────────────────────────────────────────────


class TestSbiDetection:
    def _sbi(self, src, dst, path):
        return make_line(src, dst, "eth:ethertype:ip:tcp:http2",
                         tcp_dst="7777", path=path)

    def test_new_prefixes_bsf_udr_udsf(self):
        roles = roles_from_lines(
            self._sbi("10.3.0.1", "10.3.0.15", "/nbsf-management/v1/pcfBindings"),
            self._sbi("10.3.0.1", "10.3.0.20", "/nudr-dr/v1/policy-data"),
            self._sbi("10.3.0.1", "10.3.0.21", "/nudsf-dr/v1/data"),
        )
        assert roles["10.3.0.15"] == "BSF"
        assert roles["10.3.0.20"] == "UDR"
        assert roles["10.3.0.21"] == "UDSF"

    def test_scp_serves_multiple_prefixes(self):
        obs = obs_from_lines(
            self._sbi("10.3.0.1", "10.3.0.200", "/namf-comm/v1/ue-contexts"),
            self._sbi("10.3.0.1", "10.3.0.200", "/nausf-auth/v1/ue-authentications"),
        )
        assessments = resolve_roles(obs)
        scp = assessments["10.3.0.200"]
        assert scp.role == "SCP"
        assert scp.confidence == 0.92

    def test_nf_status_notify_is_not_a_role_signal(self):
        """Every Open5GS NF serves /nnrf-nfm/v1/nf-status-notify (NRF
        callback) — it must not make an AUSF look like the NRF or an SCP."""
        roles = roles_from_lines(
            self._sbi("10.3.0.10", "10.3.0.11", "/nnrf-nfm/v1/nf-status-notify"),
            self._sbi("10.3.0.1", "10.3.0.11", "/nausf-auth/v1/ue-authentications"),
        )
        assert roles["10.3.0.11"] == "AUSF"

    def test_multiple_paths_in_one_frame_are_all_seen(self):
        line = make_line(
            "10.3.0.1", "10.3.0.12", "eth:ethertype:ip:tcp:http2", tcp_dst="7777",
            path="/nudm-sdm/v2/imsi-1/am-data,/nudm-uecm/v1/imsi-1/registrations",
        )
        roles = roles_from_lines(line)
        assert roles["10.3.0.12"] == "UDM"


# ── O-RAN / infra ports ───────────────────────────────────────────────────────


class TestOranAndInfra:
    E2_LINE = make_line("10.4.0.5", "10.4.0.9", "eth:ethertype:ip:sctp:e2ap",
                        sctp_src="40000", sctp_dst="36421", e2ap="1")
    REDIS_LINE = make_line("10.4.0.2", "10.4.0.3", "eth:ethertype:ip:tcp",
                           tcp_dst="6379")

    def test_redis_with_e2_context_is_oran_redis(self):
        roles = roles_from_lines(self.E2_LINE, self.REDIS_LINE)
        assert roles["10.4.0.3"] == "REDIS"

    def test_redis_without_e2_context_is_generic_infra(self):
        roles = roles_from_lines(self.REDIS_LINE)
        assert roles["10.4.0.3"] == "INFRA_REDIS"

    def test_no_placeholder_keys_ever(self):
        """Regression: the old engine leaked literal 'redis_ip_placeholder'
        / 'e2t_ip_placeholder' nodes into the results."""
        e2t = make_line("10.4.0.6", "10.4.0.7", "eth:ethertype:ip:tcp",
                        tcp_dst="38000")
        roles = roles_from_lines(self.E2_LINE, self.REDIS_LINE, e2t)
        assert not any("placeholder" in ip for ip in roles)
        assert roles["10.4.0.7"] == "E2T"

    def test_ric_client_heuristic(self):
        e2t = make_line("10.4.0.8", "10.4.0.7", "eth:ethertype:ip:tcp",
                        tcp_dst="38000")
        redis = make_line("10.4.0.8", "10.4.0.3", "eth:ethertype:ip:tcp",
                          tcp_dst="6379")
        roles = roles_from_lines(e2t, redis)
        assert roles["10.4.0.8"] == "NEAR_RT_RIC"

    def test_mongodb_and_webui_are_open5gs_infra(self):
        mongo = make_line("10.5.0.1", "10.5.0.2", "eth:ethertype:ip:tcp",
                          tcp_dst="27017")
        webui = make_line("10.5.0.1", "10.5.0.3", "eth:ethertype:ip:tcp",
                          tcp_dst="9999")
        roles = roles_from_lines(mongo, webui)
        assert roles["10.5.0.2"] == "OPEN5GS_INFRA"
        assert roles["10.5.0.3"] == "OPEN5GS_INFRA"


# ── GTP-U / UE / DN inference ─────────────────────────────────────────────────


class TestGtpuAndUe:
    PFCP_REQ = make_line("10.6.0.4", "10.6.0.7", "eth:ethertype:ip:udp:pfcp",
                         udp_src="8805", udp_dst="8805", pfcp="50")
    # Uplink GTP-U: gNB (10.6.0.1) → UPF (10.6.0.7), inner UE 10.45.0.2 → DN 8.8.8.8
    GTPU_UL = make_line("10.6.0.1,10.45.0.2", "10.6.0.7,8.8.8.8",
                        "eth:ethertype:ip:udp:gtp:ip:udp:dns",
                        udp_src="2152", udp_dst="2152")

    def test_inner_uplink_src_is_ue(self):
        roles = roles_from_lines(self.PFCP_REQ, self.GTPU_UL)
        assert roles["10.45.0.2"] == "UE"

    def test_inner_public_peer_is_external_dn(self):
        roles = roles_from_lines(self.PFCP_REQ, self.GTPU_UL)
        assert roles["8.8.8.8"] == "External/DN"

    def test_gtpu_peer_of_upf_is_gnb(self):
        roles = roles_from_lines(self.PFCP_REQ, self.GTPU_UL)
        assert roles["10.6.0.1"] == "gNB"
        assert roles["10.6.0.7"] == "UPF"

    def test_inner_only_private_without_upf_anchor_is_ue(self):
        gtpu = make_line("10.6.0.1,10.45.0.9", "10.6.0.99,1.1.1.1",
                         "eth:ethertype:ip:udp:gtp:ip:tcp",
                         udp_src="2152", udp_dst="2152")
        roles = roles_from_lines(gtpu)
        assert roles["10.45.0.9"] == "UE"


# ── RRC handling ──────────────────────────────────────────────────────────────


class TestRrc:
    def test_ngap_encapsulated_rrc_is_not_ue_evidence(self):
        """Regression: the old get_unique_rrc_ips matched NGAP-encapsulated
        RRC and tagged the AMF/gNB as UE."""
        line = make_line("10.7.0.1", "10.7.0.5",
                         "eth:ethertype:ip:sctp:ngap:ngap:nr-rrc",
                         sctp_src="51670", sctp_dst="38412", ngap="44", ngap_ue="0")
        roles = roles_from_lines(line)
        assert roles["10.7.0.1"] == "gNB"
        assert roles["10.7.0.5"] == "AMF"
        assert "UE" not in roles.values()

    def test_raw_rrc_is_ue_evidence(self):
        line = make_line("10.7.0.30", "10.7.0.31", "eth:ethertype:ip:udp:nr-rrc",
                         udp_src="9999", udp_dst="9999")
        roles = roles_from_lines(line)
        assert "UE" in roles.values()


# ── Parser robustness ─────────────────────────────────────────────────────────


class TestParser:
    def test_icmp_quoted_packet_is_skipped(self):
        """ICMP errors quote the offending packet, producing reversed
        comma-aggregated fields — must yield no evidence at all."""
        line = make_line("10.8.0.6,10.8.0.3", "10.8.0.3,10.8.0.6",
                         "eth:ethertype:ip:icmp:ip:udp:pfcp",
                         udp_src="8805", udp_dst="8805", pfcp="50")
        obs = obs_from_lines(line)
        assert obs.evidence == {}

    def test_short_line_is_padded(self):
        obs = obs_from_lines("10.9.0.1\t10.9.0.2\teth:ethertype:ip:tcp")
        assert set(obs.evidence) == {"10.9.0.1", "10.9.0.2"}

    def test_non_ip_line_is_ignored(self):
        obs = obs_from_lines(make_line("", "", "eth:ethertype:ipv6:tcp"))
        assert obs.evidence == {}

    def test_every_identified_role_has_confidence_and_reasoning(self):
        obs = obs_from_lines(
            TestDirectionAwareness.NGAP_REQ,
            TestGtpuAndUe.PFCP_REQ,
            TestGtpuAndUe.GTPU_UL,
            TestOranAndInfra.REDIS_LINE,
        )
        for ip, a in resolve_roles(obs).items():
            if a.role != "Unidentified":
                assert a.confidence > 0, f"{ip} ({a.role}) has zero confidence"
                assert a.reasoning, f"{ip} ({a.role}) has empty reasoning"

    def test_unidentified_fallback(self):
        line = make_line("10.9.0.5", "10.9.0.6", "eth:ethertype:ip:tcp:tls",
                         tcp_dst="443")
        assessments = resolve_roles(obs_from_lines(line))
        # No UPF in capture → plain-traffic rule does not fire → Unidentified
        assert assessments["10.9.0.6"].role == "Unidentified"
        assert assessments["10.9.0.6"].confidence == 0.0


# ── DB cache versioning ───────────────────────────────────────────────────────


class TestCacheVersioning:
    def _make_pcap_record(self, app, path):
        from models import db as _db
        from models import PcapFile

        with app.app_context():
            rec = PcapFile(
                filename=os.path.basename(path),
                original_filename=os.path.basename(path),
                file_path=path,
                file_size=1,
                status="COMPLETED",
            )
            _db.session.add(rec)
            _db.session.commit()
            return rec.id

    def test_stale_version_rows_are_replaced(self, app, fresh_db, monkeypatch):
        from models import db as _db
        from models import IpRole
        from role_engine import RoleAssessment

        path = "cache_test_dummy.pcap"
        pcap_id = self._make_pcap_record(app, path)

        with app.app_context():
            # Legacy row from the old engine (engine_version defaults to "")
            _db.session.add(IpRole(pcap_id=pcap_id, ip_address="1.2.3.4",
                                   role="gNB", reasoning="Optimized TShark DPI"))
            _db.session.commit()

        fresh = {
            "1.2.3.4": RoleAssessment(ip="1.2.3.4", role="AMF",
                                      confidence=0.95, reasoning="new engine"),
            "5.6.7.8": RoleAssessment(ip="5.6.7.8", role="gNB",
                                      confidence=0.95, reasoning="new engine"),
        }
        monkeypatch.setattr(role_engine, "assess_pcap", lambda p: fresh)

        with app.app_context():
            result = get_or_compute_roles(path)
            assert roles_as_strings(result) == {"1.2.3.4": "AMF", "5.6.7.8": "gNB"}

            rows = IpRole.query.filter_by(pcap_id=pcap_id).all()
            assert len(rows) == 2  # stale row deleted, no duplicates
            assert all(r.engine_version == ROLE_ENGINE_VERSION for r in rows)
            assert {r.ip_address: r.role for r in rows} == {
                "1.2.3.4": "AMF", "5.6.7.8": "gNB",
            }

    def test_current_version_rows_are_served_from_cache(self, app, fresh_db, monkeypatch):
        from models import db as _db
        from models import IpRole

        path = "cache_hit_dummy.pcap"
        pcap_id = self._make_pcap_record(app, path)

        with app.app_context():
            _db.session.add(IpRole(pcap_id=pcap_id, ip_address="9.9.9.9",
                                   role="UPF", confidence=0.95,
                                   reasoning="cached", engine_version=ROLE_ENGINE_VERSION))
            _db.session.commit()

        def _boom(p):
            raise AssertionError("assess_pcap must not run on a cache hit")

        monkeypatch.setattr(role_engine, "assess_pcap", _boom)

        with app.app_context():
            result = get_or_compute_roles(path)
        assert roles_as_strings(result) == {"9.9.9.9": "UPF"}
        assert result["9.9.9.9"].confidence == 0.95


# ── Integration: real tshark against the sample pcap ─────────────────────────


SAMPLE_PCAP = os.path.join(
    os.path.dirname(__file__), "..", "..", "server", "generated_pcaps", "1st_run.pcap"
)


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
@pytest.mark.skipif(not os.path.exists(SAMPLE_PCAP), reason="sample pcap missing")
class TestIntegration1stRun:
    @pytest.fixture(scope="class")
    def assessments(self):
        return assess_pcap(SAMPLE_PCAP)

    def test_core_network_functions(self, assessments):
        roles = roles_as_strings(assessments)
        assert roles["127.0.0.5"] == "AMF"
        assert roles["127.0.0.1"] == "gNB"
        assert roles["127.0.0.4"] == "SMF"
        assert roles["127.0.0.7"] == "UPF"
        assert roles["127.0.0.10"] == "NRF"
        assert roles["127.0.0.11"] == "AUSF"
        assert roles["127.0.0.12"] == "UDM"
        assert roles["127.0.0.13"] == "PCF"
        assert roles["127.0.0.15"] == "BSF"
        assert roles["127.0.0.20"] == "UDR"

    def test_scp_detected_not_mislabeled_as_amf(self, assessments):
        assert assessments["127.0.0.200"].role == "SCP"

    def test_oran_components(self, assessments):
        roles = roles_as_strings(assessments)
        assert roles["10.244.0.77"] == "NEAR_RT_RIC"
        assert roles["10.244.0.1"] == "E2_NODE"

    def test_ambiguous_pfcp_nodes(self, assessments):
        roles = roles_as_strings(assessments)
        assert roles["127.0.0.3"] == "PFCP_NODE"
        assert roles["127.0.0.6"] == "PFCP_NODE"

    def test_no_garbage_entries(self, assessments):
        import ipaddress

        for ip in assessments:
            ipaddress.ip_address(ip)  # raises on non-IP keys

    def test_confidence_populated(self, assessments):
        for a in assessments.values():
            if a.role != "Unidentified":
                assert a.confidence > 0
                assert a.reasoning
