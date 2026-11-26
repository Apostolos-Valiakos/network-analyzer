"""
Kubernetes identities from Hubble on the backend: POST /v1/ingest/hubble and
the time-based lookup (server/k8s_identity.py).
"""
import os

import pytest

import k8s_identity
from models import HubbleFlow, PodIpSighting, ServiceIpSighting

TOKEN = {"X-Internal-Token": os.environ["SECRET_TOKEN"]}
URL = "/v1/ingest/hubble"
T = 1_789_000_000.0


def pod(ip="10.244.0.31", pod_name="open5gs-amf-abc", first=T, last=T + 60, **extra):
    item = {"ip": ip, "namespace": "team-5g", "pod": pod_name, "workload": "open5gs-amf",
            "workload_kind": "Deployment", "labels": {"app": "open5gs-amf"},
            "identity": 31337, "node": "node-1", "first_seen": first, "last_seen": last}
    item.update(extra)
    return item


def send(client, **body):
    return client.post(URL, json=body, headers=TOKEN)


@pytest.fixture(autouse=True)
def _old_data_is_kept(monkeypatch):
    """The fixed timestamps are years old; keep them past the pruning."""
    monkeypatch.setenv("HUBBLE_RETENTION_HOURS", str(24 * 365 * 50))


class TestIngest:
    def test_requires_the_internal_token(self, client):
        assert client.post(URL, json={}).status_code == 401

    @pytest.mark.parametrize("body", [
        None,
        {"sightings": "x"},
        {"sightings": [{"ip": "1.1.1.1", "namespace": "a", "first_seen": T, "last_seen": T}]},
        {"sightings": [pod(last=T - 1)]},
        {"sightings": [pod(first="yesterday")]},
        {"sightings": [pod(labels=["app"])]},
        {"services": [{"ip": "10.96.0.1", "namespace": "a", "first_seen": T, "last_seen": T}]},
        {"flows": [{"minute": T, "src_ip": "a", "dst_ip": "b", "count": 0}]},
        {"flows": [{"minute": T, "src_ip": "a", "dst_ip": "b", "dst_port": 70000, "count": 1}]},
    ])
    def test_bad_batches_are_400_and_store_nothing(self, client, app, body):
        res = client.post(URL, json=body, headers=TOKEN)
        assert res.status_code == 400
        with app.app_context():
            assert PodIpSighting.query.count() == 0

    def test_batch_is_stored(self, client, app):
        res = send(client, sightings=[pod()],
                   services=[{"ip": "10.96.0.10", "namespace": "team-5g", "service": "open5gs-nrf",
                              "first_seen": T, "last_seen": T}],
                   flows=[{"minute": T, "src_ip": "10.244.0.30", "dst_ip": "10.244.0.31",
                           "dst_port": 38412, "protocol": "SCTP", "verdict": "FORWARDED",
                           "src_pod": "team-5g/gnb", "dst_pod": "team-5g/amf", "count": 5}])
        assert res.status_code == 200
        assert res.get_json() == {"status": "success", "sightings": 1, "services": 1, "flows": 1}
        with app.app_context():
            row = PodIpSighting.query.one()
            assert (row.namespace, row.pod, row.labels) == ("team-5g", "open5gs-amf-abc",
                                                            {"app": "open5gs-amf"})
            assert ServiceIpSighting.query.one().service == "open5gs-nrf"


class TestSpans:
    def test_the_same_pod_extends_its_span(self, client, app):
        send(client, sightings=[pod(first=T, last=T + 60)])
        send(client, sightings=[pod(first=T + 120, last=T + 180)])
        with app.app_context():
            row = PodIpSighting.query.one()
            assert (row.last_seen - row.first_seen).total_seconds() == 180

    def test_a_long_gap_starts_a_new_span(self, client, app, monkeypatch):
        monkeypatch.setenv("SIGHTING_GAP_SECONDS", "300")
        send(client, sightings=[pod(first=T, last=T + 60)])
        send(client, sightings=[pod(first=T + 3600, last=T + 3660)])
        with app.app_context():
            assert PodIpSighting.query.count() == 2

    def test_another_pod_on_the_ip_starts_a_new_span(self, client, app):
        """An IP reused after a pod restart belongs to the new pod from then on."""
        send(client, sightings=[pod(pod_name="amf-old", first=T, last=T + 60)])
        send(client, sightings=[pod(pod_name="amf-new", first=T + 90, last=T + 150)])
        with app.app_context():
            assert k8s_identity.at("10.244.0.31", T + 30)["pod"] == "amf-old"
            assert k8s_identity.at("10.244.0.31", T + 120)["pod"] == "amf-new"

    def test_flows_of_the_same_minute_add_up(self, client, app):
        flow = {"minute": T, "src_ip": "a", "dst_ip": "b", "dst_port": 80, "protocol": "TCP",
                "verdict": "FORWARDED", "src_pod": "", "dst_pod": "", "count": 2}
        send(client, flows=[flow])
        send(client, flows=[dict(flow, count=3)])
        with app.app_context():
            assert HubbleFlow.query.one().count == 5

    def test_old_rows_are_pruned(self, client, app, monkeypatch):
        monkeypatch.setenv("HUBBLE_RETENTION_HOURS", "1")
        send(client, sightings=[pod()])  # years old
        with app.app_context():
            assert PodIpSighting.query.count() == 0


class TestLookup:
    def test_during_picks_the_pod_with_the_most_overlap(self, client, app):
        send(client, sightings=[pod(pod_name="a", first=T, last=T + 100)])
        send(client, sightings=[pod(pod_name="b", first=T + 110, last=T + 1000)])
        with app.app_context():
            assert k8s_identity.during("10.244.0.31", T + 50, T + 900)["pod"] == "b"

    def test_lookup_returns_the_pod_fields(self, client, app):
        send(client, sightings=[pod()])
        with app.app_context():
            info = k8s_identity.at("10.244.0.31", T + 10)
        assert info == {"namespace": "team-5g", "pod": "open5gs-amf-abc", "workload": "open5gs-amf",
                        "workload_kind": "Deployment", "node": "node-1",
                        "labels": {"app": "open5gs-amf"}}

    def test_slack_covers_the_refresh_lag(self, client, app):
        send(client, sightings=[pod(first=T, last=T + 60)])
        with app.app_context():
            assert k8s_identity.at("10.244.0.31", T + 150) is not None
            assert k8s_identity.at("10.244.0.31", T + 600) is None

    def test_service_addresses(self, client, app):
        send(client, services=[{"ip": "10.96.0.10", "namespace": "team-5g",
                                "service": "open5gs-nrf", "first_seen": T, "last_seen": T}])
        with app.app_context():
            assert k8s_identity.at("10.96.0.10", T) == {"service": "team-5g/open5gs-nrf",
                                                        "namespace": "team-5g"}

    def test_unknown_ip(self, client, app):
        with app.app_context():
            assert k8s_identity.at("10.244.9.9", T) is None
