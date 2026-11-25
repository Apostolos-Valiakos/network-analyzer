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
    ran_name="",
    amf_name="",
    e2_node="",
    e2_plmn="",
    e2_gnb="",
    pfcp_ies="",
    node_id="",
    node_fqdn="",
    json="",
):
    """Build one tab-separated line in the collector's field order."""
    return "\t".join(
        [src, dst, protos, sctp_src, sctp_dst, udp_src, udp_dst, tcp_dst,
         ngap, ngap_ue, e2ap, pfcp, path, ran_name, amf_name, e2_node,
         e2_plmn, e2_gnb, pfcp_ies, node_id, node_fqdn, json]
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
        monkeypatch.setattr(role_engine, "assess_pcap", lambda p, warnings=None: fresh)

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

        def _boom(p, warnings=None):
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


# ── Self-declared identities (NG Setup, E2 Setup) ────────────────────────────


class TestSetupIdentities:
    GNB, AMF, RIC = "10.0.0.2", "10.0.0.1", "10.0.0.9"

    def ng_setup(self):
        request = make_line(self.GNB, self.AMF, "sctp:ngap", "9487", "38412",
                            ngap="21", ran_name="cu-01, site A")
        response = make_line(self.AMF, self.GNB, "sctp:ngap", "38412", "9487",
                             ngap="21", amf_name="open5gs-amf0")
        return request, response

    def test_ng_setup_names_go_to_their_own_side(self):
        obs = obs_from_lines(*self.ng_setup())
        assert obs.evidence[self.GNB].ran_node_names == {"cu-01, site A"}
        assert obs.evidence[self.AMF].amf_names == {"open5gs-amf0"}
        assert not obs.evidence[self.GNB].amf_names
        assert not obs.evidence[self.AMF].ran_node_names

    def test_names_appear_in_the_reasoning(self):
        assessments = resolve_roles(obs_from_lines(*self.ng_setup()))
        assert "NG Setup RAN name 'cu-01, site A'" in assessments[self.GNB].reasoning
        assert "NG Setup AMF name 'open5gs-amf0'" in assessments[self.AMF].reasoning

    def test_ng_setup_embedded_in_e2_setup_is_ignored(self):
        """E2 Setup carries a copy of an NG Setup: its names are not about
        the endpoints of the RIC link."""
        line = make_line(self.GNB, self.RIC, "sctp:e2ap:ngap", "44945", "36421",
                         ngap="21,21", e2ap="1", ran_name="dummy-name",
                         amf_name="test_amf_name", e2_node="0", e2_plmn="00f110",
                         e2_gnb="000004")
        obs = obs_from_lines(line)
        assert not obs.evidence[self.RIC].amf_names
        assert not obs.evidence[self.GNB].ran_node_names
        assert obs.evidence[self.GNB].ngap_ran_side == 0

    def test_e2_setup_names_the_e2_node(self):
        line = make_line(self.GNB, self.RIC, "sctp:e2ap", "44945", "36421",
                         e2ap="1", e2_node="0", e2_plmn="00f110,00f110",
                         e2_gnb="000004")
        obs = obs_from_lines(line)
        assert obs.evidence[self.GNB].e2_node_ids == {"gNB PLMN 00f110 gNB-ID 000004"}
        assert not obs.evidence[self.RIC].e2_node_ids
        reasoning = resolve_roles(obs)[self.GNB].reasoning
        assert "E2 Setup node 'gNB PLMN 00f110 gNB-ID 000004'" in reasoning

    def test_other_e2_procedures_do_not_name_the_node(self):
        line = make_line(self.GNB, self.RIC, "sctp:e2ap", "44945", "36421",
                         e2ap="8", e2_node="0", e2_plmn="00f110")
        assert not obs_from_lines(line).evidence[self.GNB].e2_node_ids

    def test_unknown_e2_node_type_is_kept_as_a_number(self):
        line = make_line(self.GNB, self.RIC, "sctp:e2ap", "44945", "36421",
                         e2ap="1", e2_node="7")
        assert obs_from_lines(line).evidence[self.GNB].e2_node_ids == {"type 7"}

    def test_gnb_that_is_also_an_e2_node_keeps_both_identities(self):
        e2 = make_line(self.GNB, self.RIC, "sctp:e2ap", "44945", "36421",
                       e2ap="1", e2_node="0", e2_plmn="00f110", e2_gnb="000004")
        gnb = resolve_roles(obs_from_lines(*self.ng_setup(), e2))[self.GNB]
        assert gnb.role == "gNB"
        assert "NG Setup RAN name" in gnb.reasoning
        assert "E2 Setup node" in gnb.reasoning

    def test_long_name_lists_are_shortened(self):
        obs = obs_from_lines(*self.ng_setup())
        obs.evidence[self.AMF].amf_names = {"a", "b", "c", "d", "e"}
        assert "'a', 'b', 'c' (+2 more)" in resolve_roles(obs)[self.AMF].reasoning


FIXTURE_ORAN = os.path.join(os.path.dirname(__file__), "fixtures", "ppc_5g_and_oran.pcap")


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_fixture_setup_identities():
    """The O-RAN fixture: srs-cu-01 is the gNB and E2 node, open5gs-amf0 the
    AMF, and the NG Setup copy inside E2 Setup ("dummy-name") is ignored."""
    roles = assess_pcap(FIXTURE_ORAN)
    gnb, amf = roles["10.250.100.42"], roles["10.250.100.41"]
    assert gnb.role == "gNB" and "'srs-cu-01'" in gnb.reasoning
    assert "E2 Setup node 'gNB PLMN 00f110 gNB-ID 000004'" in gnb.reasoning
    assert amf.role == "AMF" and "'open5gs-amf0'" in amf.reasoning
    assert not any(
        "dummy-name" in a.reasoning or "test_amf_name" in a.reasoning for a in roles.values()
    )


# ── NFProfiles (NRF signalling) ───────────────────────────────────────────────


def sbi_body(src, dst, *members):
    """An HTTP/2 DATA frame whose JSON body has these path_with_value members."""
    return make_line(src, dst, "sll:ip:tcp:http2:json", tcp_dst="7777", json=",".join(members))


class TestNrfProfiles:
    CLIENT, NRF, SCP = "127.0.0.1", "127.0.0.10", "127.0.0.200"

    def test_registration_names_the_listed_address_not_the_sender(self):
        """Open5GS clients send from 127.0.0.1 through the SCP: only the
        profile's ipv4Addresses identify the NF."""
        body = sbi_body(self.CLIENT, self.SCP, "/nfInstanceId:x", "/nfType:AUSF",
                        "/ipv4Addresses/[]:127.0.0.11", "/priority:0")
        roles = resolve_roles(obs_from_lines(body))
        assert roles["127.0.0.11"].role == "AUSF"
        assert roles["127.0.0.11"].confidence == 0.93
        assert "NRF profile type 'AUSF'" in roles["127.0.0.11"].reasoning
        assert roles[self.CLIENT].role == "Unidentified"
        assert roles[self.SCP].role == "Unidentified"

    def test_status_notification_profile_counts(self):
        body = sbi_body(self.NRF, self.CLIENT, "/event:NF_REGISTERED",
                        "/nfProfile/nfType:SMF", "/nfProfile/ipv4Addresses/[]:127.0.0.4")
        assert obs_from_lines(body).evidence["127.0.0.4"].nrf_nf_types == {"SMF"}

    def test_service_endpoints_and_allowed_types_are_not_the_profile(self):
        body = sbi_body(self.CLIENT, self.NRF, "/nfType:PCF",
                        "/ipv4Addresses/[]:127.0.0.13",
                        "/nfServices/[]/ipEndPoints/[]/ipv4Address:127.0.0.99",
                        "/allowedNfTypes/[]:AMF")
        obs = obs_from_lines(body)
        assert obs.evidence["127.0.0.13"].nrf_nf_types == {"PCF"}
        assert "127.0.0.99" not in obs.evidence

    def test_discovery_results_with_several_profiles_are_ignored(self):
        body = sbi_body(self.NRF, self.CLIENT,
                        "/nfInstances/[]/nfType:AMF", "/nfInstances/[]/ipv4Addresses/[]:127.0.0.5",
                        "/nfInstances/[]/nfType:SMF", "/nfInstances/[]/ipv4Addresses/[]:127.0.0.4")
        obs = obs_from_lines(body)
        assert "127.0.0.5" not in obs.evidence and "127.0.0.4" not in obs.evidence

    def test_two_top_level_types_in_one_body_are_ignored(self):
        body = sbi_body(self.CLIENT, self.NRF, "/nfType:AMF", "/nfType:SMF",
                        "/ipv4Addresses/[]:127.0.0.5")
        assert "127.0.0.5" not in obs_from_lines(body).evidence

    @pytest.mark.parametrize("bad", ["not-an-ip", "::1", "300.1.1.1"])
    def test_invalid_addresses_are_skipped(self, bad):
        body = sbi_body(self.CLIENT, self.NRF, "/nfType:UDM", f"/ipv4Addresses/[]:{bad}",
                        "/ipv4Addresses/[]:127.0.0.12")
        obs = obs_from_lines(body)
        assert bad not in obs.evidence
        assert obs.evidence["127.0.0.12"].nrf_nf_types == {"UDM"}

    def test_odd_nf_type_values_are_ignored(self):
        body = sbi_body(self.CLIENT, self.NRF, "/nfType:<script>", "/ipv4Addresses/[]:127.0.0.12")
        assert "127.0.0.12" not in obs_from_lines(body).evidence

    def test_json_outside_http2_is_ignored(self):
        """PENM's own HTTP/1 API also carries JSON."""
        line = make_line(self.CLIENT, self.NRF, "ip:tcp:http:json", tcp_dst="5555",
                         json="/nfType:AMF,/ipv4Addresses/[]:127.0.0.5")
        assert "127.0.0.5" not in obs_from_lines(line).evidence

    def test_conflicting_profile_types_decide_nothing(self):
        lines = [sbi_body(self.CLIENT, self.NRF, f"/nfType:{t}", "/ipv4Addresses/[]:127.0.0.30")
                 for t in ("AMF", "SMF")]
        assessment = resolve_roles(obs_from_lines(*lines))["127.0.0.30"]
        assert assessment.role == "Unidentified"

    def test_protocol_evidence_outranks_the_profile(self):
        """An IP that terminates NGAP is the AMF (0.95) even if a profile
        said otherwise; the profile type stays visible in the reasoning."""
        ngap = make_line("127.0.0.1", "127.0.0.5", "sctp:ngap", "9487", "38412", ngap="15")
        body = sbi_body(self.CLIENT, self.NRF, "/nfType:SMF", "/ipv4Addresses/[]:127.0.0.5")
        amf = resolve_roles(obs_from_lines(ngap, body))["127.0.0.5"]
        assert amf.role == "AMF" and amf.confidence == 0.95
        assert "NRF profile type 'SMF'" in amf.reasoning

    def test_profile_outranks_traffic_pattern_sbi_rules(self):
        """The SCP proxies /nnrf calls, so on traffic alone it also looks
        like the NRF; its own profile settles it."""
        lines = [
            make_line(self.CLIENT, self.SCP, "tcp:http2", tcp_dst="7777", path="/nnrf-nfm/v1/nf-instances/x"),
            sbi_body(self.CLIENT, self.NRF, "/nfType:SCP", "/ipv4Addresses/[]:127.0.0.200"),
        ]
        scp = resolve_roles(obs_from_lines(*lines))[self.SCP]
        assert scp.role == "SCP"
        assert "NRF (0.90)" in scp.reasoning


# ── PFCP Node ID and Function Features ───────────────────────────────────────


def pfcp(src, dst, msg_type, ies="", node_id="", fqdn=""):
    return make_line(src, dst, "udp:pfcp", udp_src="8805", udp_dst="8805", pfcp=msg_type,
                     pfcp_ies=ies, node_id=node_id, node_fqdn=fqdn)


class TestPfcpAssociation:
    SGWC, SGWU, SMF, UPF = "127.0.0.3", "127.0.0.6", "127.0.0.4", "127.0.0.7"

    def test_node_id_belongs_to_the_sender(self):
        obs = obs_from_lines(
            pfcp(self.SMF, self.UPF, "5", "60,96,89", node_id=self.SMF),
            pfcp(self.UPF, self.SMF, "6", "60,19,96,43", node_id=self.UPF),
        )
        assert obs.evidence[self.SMF].pfcp_node_ids == {self.SMF}
        assert obs.evidence[self.UPF].pfcp_node_ids == {self.UPF}

    def test_fqdn_node_id_is_kept(self):
        obs = obs_from_lines(pfcp(self.UPF, self.SMF, "6", "60,43", fqdn="upf.core.local"))
        assert obs.evidence[self.UPF].pfcp_node_ids == {"upf.core.local"}

    def test_features_name_the_side_but_the_role_stays_pfcp_node(self):
        """An EPC SGW-C/SGW-U announces the same features, so association
        alone does not make an SMF or UPF."""
        roles = resolve_roles(obs_from_lines(
            pfcp(self.SGWC, self.SGWU, "5", "60,96,89", node_id=self.SGWC),
            pfcp(self.SGWU, self.SGWC, "6", "60,19,96,43", node_id=self.SGWU),
        ))
        sgwc, sgwu = roles[self.SGWC], roles[self.SGWU]
        assert (sgwc.role, sgwc.confidence) == ("PFCP_NODE", 0.50)
        assert (sgwu.role, sgwu.confidence) == ("PFCP_NODE", 0.50)
        assert "control-plane side" in sgwc.reasoning
        assert "user-plane side" in sgwu.reasoning
        assert f"PFCP Node ID '{self.SGWU}'" in sgwu.reasoning

    def test_heartbeat_only_side_stays_unknown(self):
        roles = resolve_roles(obs_from_lines(pfcp(self.SGWC, self.SGWU, "1", "96")))
        assert roles[self.SGWC].confidence == 0.40
        assert "CP/UP side unknown" in roles[self.SGWC].reasoning

    def test_session_messages_still_decide_smf_and_upf(self):
        roles = resolve_roles(obs_from_lines(
            pfcp(self.SMF, self.UPF, "5", "60,96,89", node_id=self.SMF),
            pfcp(self.UPF, self.SMF, "6", "60,19,96,43", node_id=self.UPF),
            pfcp(self.SMF, self.UPF, "50", "60,57", node_id=self.SMF),
            pfcp(self.UPF, self.SMF, "51", "60,19"),
        ))
        assert roles[self.SMF].role == "SMF" and roles[self.UPF].role == "UPF"
        assert f"PFCP Node ID '{self.UPF}'" in roles[self.UPF].reasoning


FIXTURE_NRF_PFCP = os.path.join(os.path.dirname(__file__), "fixtures", "open5gs_nrf_pfcp.pcap")


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
@pytest.mark.skipif(not os.path.exists(FIXTURE_NRF_PFCP), reason="fixture missing")
def test_fixture_nrf_profiles_and_pfcp_association():
    """Open5GS on loopback (cut from a testbed capture): NF registrations
    through the SCP, NRF replies and notifications, and PFCP association and
    heartbeats only (session messages were left out; they carry an IMSI)."""
    roles = assess_pcap(FIXTURE_NRF_PFCP)
    expected = {
        "127.0.0.4": "SMF", "127.0.0.5": "AMF", "127.0.0.10": "NRF", "127.0.0.11": "AUSF",
        "127.0.0.12": "UDM", "127.0.0.13": "PCF", "127.0.0.14": "NSSF", "127.0.0.15": "BSF",
        "127.0.0.20": "UDR", "127.0.0.200": "SCP",
    }
    assert {ip: roles[ip].role for ip in expected} == expected
    assert roles["127.0.0.1"].role == "Unidentified"  # the clients' shared source address
    for ip, side in (("127.0.0.3", "control-plane"), ("127.0.0.6", "user-plane"),
                     ("127.0.0.7", "user-plane")):
        assert roles[ip].role == "PFCP_NODE"
        assert side in roles[ip].reasoning
        assert f"PFCP Node ID '{ip}'" in roles[ip].reasoning
