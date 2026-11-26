"""
Kubernetes identity in role results (server/role_fusion.py): the hint table,
the agree / mismatch / suggest rules, and the routes that apply them.
"""
import os
import time

import pytest

import role_fusion
from models import PodIpSighting, RoleSnapshot, ServiceIpSighting, db, utc_from_timestamp

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "ppc_5g_and_oran.pcap")


def sight(app, ip, pod, t0, t1, app_label=None, workload=None, namespace="team-5g"):
    with app.app_context():
        db.session.add(PodIpSighting(
            ip=ip, namespace=namespace, pod=pod, workload=workload,
            labels={"app": app_label} if app_label else {},
            first_seen=utc_from_timestamp(t0), last_seen=utc_from_timestamp(t1),
        ))
        db.session.commit()


def entry(role, confidence=0.95, reasoning="traffic"):
    return {"role": role, "confidence": confidence, "reasoning": reasoning}


class TestHints:
    @pytest.mark.parametrize("info, role", [
        ({"labels": {"app": "open5gs-amf"}}, "AMF"),
        ({"labels": {"app.kubernetes.io/name": "open5gs", "app": "open5gs-smf"}}, "SMF"),
        ({"workload": "srsran-gnb"}, "gNB"),
        ({"pod": "srs-cu-01"}, "gNB"),
        ({"labels": {"app": "flexric-ric"}}, "NEAR_RT_RIC"),
        ({"pod": "open5gs-amf0-7f9c"}, "AMF"),
        ({"labels": {"app": "open5gs-mongodb"}}, "OPEN5GS_INFRA"),
    ])
    def test_hint_from_labels_and_names(self, info, role):
        assert role_fusion.hint_for(info)[0] == role

    def test_component_label_wins_over_name(self):
        info = {"labels": {"app.kubernetes.io/component": "upf", "app": "core"}, "pod": "amf-x"}
        assert role_fusion.hint_for(info)[0] == "UPF"

    @pytest.mark.parametrize("info", [{"pod": "coredns-5d78"}, {"labels": {"app": "grafana"}}, {}])
    def test_no_hint(self, info):
        assert role_fusion.hint_for(info) is None

    def test_tokens_must_be_whole_words(self):
        assert role_fusion.hint_for({"pod": "scheduler"}) is None  # contains "du"
        assert role_fusion.hint_for({"pod": "circuit"}) is None    # contains "cu"


class TestAnnotate:
    T = 1_789_000_000.0

    @pytest.fixture(autouse=True)
    def _db(self, app, fresh_db):
        with app.app_context():
            yield

    def test_agreement_raises_confidence(self, app):
        sight(app, "10.244.0.31", "open5gs-amf-abc", self.T, self.T + 60, "open5gs-amf")
        roles = {"10.244.0.31": entry("AMF", 0.6)}
        role_fusion.annotate(roles, self.T, self.T + 60)
        amf = roles["10.244.0.31"]
        assert amf["confidence"] == pytest.approx(0.7)
        assert "pod team-5g/open5gs-amf-abc agrees (AMF)" in amf["reasoning"]
        assert amf["k8s"] == {"namespace": "team-5g", "pod": "open5gs-amf-abc", "hint_role": "AMF"}

    def test_confidence_is_capped(self, app):
        sight(app, "10.244.0.31", "amf-0", self.T, self.T + 60, "open5gs-amf")
        roles = {"10.244.0.31": entry("AMF", 0.95)}
        role_fusion.annotate(roles, self.T, self.T)
        assert roles["10.244.0.31"]["confidence"] == 0.99

    def test_also_roles_agree(self, app):
        sight(app, "10.244.0.40", "srsran-gnb-0", self.T, self.T + 60, "srsran-gnb")
        roles = {"10.244.0.40": entry("E2_NODE", 0.95)}
        role_fusion.annotate(roles, self.T, self.T)
        assert "k8s_mismatch" not in roles["10.244.0.40"]["k8s"]

    def test_disagreement_keeps_the_role_and_flags_it(self, app):
        sight(app, "10.244.0.31", "open5gs-amf-abc", self.T, self.T + 60, "open5gs-amf")
        roles = {"10.244.0.31": entry("SMF", 0.95)}
        role_fusion.annotate(roles, self.T, self.T)
        smf = roles["10.244.0.31"]
        assert (smf["role"], smf["confidence"]) == ("SMF", 0.95)
        assert smf["k8s"]["k8s_mismatch"] is True
        assert "suggests AMF, the traffic says SMF" in smf["reasoning"]

    def test_unidentified_gets_a_suggested_role(self, app):
        sight(app, "10.244.0.31", "open5gs-nssf-0", self.T, self.T + 60, "open5gs-nssf")
        roles = {"10.244.0.31": entry("Unidentified", 0.0)}
        role_fusion.annotate(roles, self.T, self.T)
        nssf = roles["10.244.0.31"]
        assert nssf["role"] == "Unidentified" and nssf["confidence"] == 0.0
        assert nssf["k8s"]["suggested_role"] == "NSSF"

    def test_service_address_shows_the_service_without_a_hint(self, app):
        with app.app_context():
            db.session.add(ServiceIpSighting(
                ip="10.96.0.10", namespace="team-5g", service="open5gs-amf",
                first_seen=utc_from_timestamp(self.T), last_seen=utc_from_timestamp(self.T)))
            db.session.commit()
        roles = {"10.96.0.10": entry("AMF", 0.95)}
        role_fusion.annotate(roles, self.T, self.T)
        assert roles["10.96.0.10"]["k8s"] == {"namespace": "team-5g", "service": "team-5g/open5gs-amf"}
        assert roles["10.96.0.10"]["confidence"] == 0.95

    def test_ips_without_identity_are_untouched(self, app):
        sight(app, "10.244.0.31", "amf-0", self.T, self.T + 60, "open5gs-amf")
        roles = {"10.16.0.5": entry("External/DN", 0.4)}
        role_fusion.annotate(roles, self.T, self.T)
        assert roles == {"10.16.0.5": entry("External/DN", 0.4)}

    def test_lookup_failure_is_a_warning(self, app, monkeypatch):
        sight(app, "10.244.0.31", "amf-0", self.T, self.T + 60, "open5gs-amf")

        def boom(*a):
            raise RuntimeError("db down")
        monkeypatch.setattr(role_fusion.k8s_identity, "during", boom)
        warnings = []
        roles = {"10.244.0.31": entry("AMF")}
        role_fusion.annotate(roles, self.T, self.T, warnings)
        assert "k8s" not in roles["10.244.0.31"]
        assert warnings and "could not be read" in warnings[0]


@pytest.mark.integration
def test_capture_span_matches_the_fixture(app, fresh_db):
    """annotate_capture looks pods up over the capture's own time span."""
    span = role_fusion.capture_span(FIXTURE)
    assert span is not None and span[1] - span[0] == pytest.approx(46.2, abs=0.1)
    sight(app, "10.250.100.41", "open5gs-amf-0", span[0], span[1], "open5gs-amf")
    roles = {"10.250.100.41": entry("AMF"), "10.250.100.42": entry("gNB")}
    with app.app_context():
        role_fusion.annotate_capture(roles, FIXTURE)
    assert roles["10.250.100.41"]["k8s"]["pod"] == "open5gs-amf-0"
    assert "k8s" not in roles["10.250.100.42"]


def test_no_kubernetes_data_skips_everything(app, fresh_db, monkeypatch):
    """Without Hubble data nothing is looked up or read (not even the capture)."""
    monkeypatch.setattr(role_fusion, "capture_span", lambda path: pytest.fail("read the capture"))
    roles = {"1.1.1.1": entry("AMF")}
    with app.app_context():
        role_fusion.annotate_capture(roles, "missing.pcap")
    assert roles == {"1.1.1.1": entry("AMF")}


class TestLatestRolesRoute:
    LATEST = "/v1/network/roles/latest"

    def _snapshot(self, app, ts, ip="10.244.0.31", role="AMF"):
        with app.app_context():
            db.session.add(RoleSnapshot(ts=ts, ip_address=ip, role=role, confidence=0.8,
                                        reasoning="NGAP", source="dpi"))
            db.session.commit()

    def test_json_rows_carry_the_pod(self, client, app, admin_headers):
        now = time.time()
        self._snapshot(app, now)
        sight(app, "10.244.0.31", "open5gs-amf-abc", now - 300, now, "open5gs-amf")
        row = client.get(f"{self.LATEST}?format=json", headers=admin_headers).get_json()[0]
        assert row["k8s"]["pod"] == "open5gs-amf-abc"
        assert row["confidence"] == pytest.approx(0.9)

    def test_csv_gets_k8s_columns(self, client, app, admin_headers):
        now = time.time()
        self._snapshot(app, now)
        self._snapshot(app, now, ip="10.16.0.9", role="External/DN")
        sight(app, "10.244.0.31", "open5gs-amf-abc", now - 300, now, "open5gs-amf")
        text = client.get(f"{self.LATEST}?format=csv", headers=admin_headers).get_data(as_text=True)
        header = text.splitlines()[0].split(",")
        assert "k8s_pod" in header and "k8s_mismatch" in header and "k8s" not in header
        assert "open5gs-amf-abc" in text

    def test_rows_stay_unchanged_without_kubernetes_data(self, client, app, admin_headers):
        self._snapshot(app, time.time())
        row = client.get(f"{self.LATEST}?format=json", headers=admin_headers).get_json()[0]
        assert "k8s" not in row and row["confidence"] == 0.8
