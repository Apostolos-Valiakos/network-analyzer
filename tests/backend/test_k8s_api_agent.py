"""
The sensor's Kubernetes-API fallback (Host Files/k8s_api_agent.py): pod and
Service lists turned into sightings with source "k8s-api".
"""
import importlib.util
import os
from unittest.mock import MagicMock

import pytest
import requests

_AGENT = os.path.join(os.path.dirname(__file__), "..", "..", "Host Files", "k8s_api_agent.py")
NOW = 1_789_000_000.0


@pytest.fixture()
def mod():
    spec = importlib.util.spec_from_file_location("k8s_api_agent_under_test", _AGENT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pod(name="open5gs-amf-6d9c7b5f4-xk2lp", ip="10.244.0.31", phase="Running", host=False,
        labels=None, owner=("ReplicaSet", "open5gs-amf-6d9c7b5f4"), namespace="team-5g"):
    labels = {"app": "open5gs-amf", "pod-template-hash": "6d9c7b5f4"} if labels is None else labels
    meta = {"name": name, "namespace": namespace, "labels": labels}
    if owner:
        meta["ownerReferences"] = [{"kind": owner[0], "name": owner[1], "controller": True}]
    return {"metadata": meta, "spec": {"nodeName": "node-1", "hostNetwork": host},
            "status": {"phase": phase, "podIP": ip, "podIPs": [{"ip": ip}] if ip else []}}


def service(name="open5gs-nrf", ip="10.96.0.10"):
    return {"metadata": {"name": name, "namespace": "team-5g"},
            "spec": {"clusterIP": ip, "clusterIPs": [ip]}}


class TestSightings:
    def test_running_pod(self, mod):
        [s] = mod.pod_sightings([pod()], NOW)
        assert s == {"ip": "10.244.0.31", "namespace": "team-5g", "pod": "open5gs-amf-6d9c7b5f4-xk2lp",
                     "workload": "open5gs-amf", "workload_kind": "Deployment",
                     "labels": {"app": "open5gs-amf"}, "identity": None, "node": "node-1",
                     "first_seen": NOW, "last_seen": NOW}

    def test_statefulset_owner_is_kept(self, mod):
        [s] = mod.pod_sightings([pod(name="srsran-gnb-0", owner=("StatefulSet", "srsran-gnb"),
                                     labels={"app": "srsran-gnb"})], NOW)
        assert (s["workload"], s["workload_kind"]) == ("srsran-gnb", "StatefulSet")

    def test_bare_pod_has_no_workload(self, mod):
        [s] = mod.pod_sightings([pod(owner=None)], NOW)
        assert s["workload"] is None and s["workload_kind"] is None

    @pytest.mark.parametrize("item", [
        pod(phase="Pending"),
        pod(host=True),
        pod(ip=""),
        pod(labels={"app.kubernetes.io/part-of": "penm", "app": "penm-backend"}),
    ])
    def test_pods_that_give_no_sighting(self, mod, item):
        assert mod.pod_sightings([item], NOW) == []

    def test_services_without_headless_ones(self, mod):
        found = mod.service_sightings([service(), service("open5gs-amf", "None")], NOW)
        assert [(s["ip"], s["service"]) for s in found] == [("10.96.0.10", "open5gs-nrf")]


def make_agent(mod, tmp_path, responses, namespaces=("team-5g",), post_status=200):
    token = tmp_path / "token"
    token.write_text("sa-token\n")
    get = MagicMock(side_effect=responses)
    post = MagicMock(return_value=MagicMock(status_code=post_status, text=""))
    agent = mod.K8sApiAgent("https://10.96.0.1:443", list(namespaces), "http://b/v1/ingest/hubble",
                            "tok", token_file=str(token), ca_file=str(tmp_path / "missing.crt"),
                            get=get, post=post, clock=lambda: NOW)
    return agent, get, post


def api(items, status=200):
    r = MagicMock(status_code=status)
    r.json.return_value = {"items": items}
    r.raise_for_status.side_effect = (
        requests.exceptions.HTTPError(str(status)) if status >= 400 else None)
    return r


class TestAgent:
    def test_collect_lists_pods_and_services_with_the_token(self, mod, tmp_path):
        agent, get, _ = make_agent(mod, tmp_path, [api([pod()]), api([service()])])
        batch = agent.collect()
        assert batch["source"] == "k8s-api" and batch["flows"] == []
        assert len(batch["sightings"]) == 1 and len(batch["services"]) == 1
        url = get.call_args_list[0].args[0]
        assert url == "https://10.96.0.1:443/api/v1/namespaces/team-5g/pods"
        assert get.call_args.kwargs["headers"] == {"Authorization": "Bearer sa-token"}

    def test_a_forbidden_namespace_is_skipped(self, mod, tmp_path):
        agent, _, _ = make_agent(mod, tmp_path, [api([], 403), api([pod(namespace="team-ric")]),
                                                 api([])], namespaces=("team-5g", "team-ric"))
        batch = agent.collect()
        assert [s["namespace"] for s in batch["sightings"]] == ["team-ric"]

    def test_nothing_is_sent_when_every_namespace_fails(self, mod, tmp_path):
        agent, _, _ = make_agent(mod, tmp_path, [requests.exceptions.ConnectionError()])
        assert agent.collect() is None and not agent.pending

    def test_flush_retries_and_drops_invalid(self, mod, tmp_path):
        agent, _, post = make_agent(mod, tmp_path, [api([pod()]), api([])])
        agent.collect()
        post.side_effect = [requests.exceptions.ConnectionError(), MagicMock(status_code=400, text="")]
        agent.flush()
        assert len(agent.pending) == 1
        agent.flush()
        assert not agent.pending

    def test_configuration(self, mod):
        assert mod.namespaces({"K8S_NAMESPACES": "team-5g, team-ric,"}) == ["team-5g", "team-ric"]
        assert mod.api_url({"KUBERNETES_SERVICE_HOST": "10.96.0.1", "KUBERNETES_SERVICE_PORT": "443"}) \
            == "https://10.96.0.1:443"
        assert mod.ingest_url({"HOST_API_URL": "http://b:5555/v1/ingest/zeek"}) == \
            "http://b:5555/v1/ingest/hubble"
        with pytest.raises(SystemExit):
            mod.api_url({})


def test_batches_are_stored_with_their_source(mod, tmp_path, client, app, monkeypatch):
    import k8s_identity
    from models import PodIpSighting

    monkeypatch.setenv("HUBBLE_RETENTION_HOURS", str(24 * 365 * 50))
    agent, _, _ = make_agent(mod, tmp_path, [api([pod()]), api([service()])])
    agent.post = lambda url, json, headers, timeout: client.post(
        "/v1/ingest/hubble", json=json, headers=headers)
    agent.token = os.environ["SECRET_TOKEN"]
    agent.collect()
    agent.flush()
    assert not agent.pending
    with app.app_context():
        assert PodIpSighting.query.one().source == "k8s-api"
        assert k8s_identity.at("10.244.0.31", NOW)["workload"] == "open5gs-amf"


def test_unknown_source_is_400(client):
    res = client.post("/v1/ingest/hubble", json={"source": "zeek"},
                      headers={"X-Internal-Token": os.environ["SECRET_TOKEN"]})
    assert res.status_code == 400
