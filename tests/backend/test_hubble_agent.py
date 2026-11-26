"""
The sensor's Hubble agent (Host Files/hubble_agent.py): reading
`hubble observe -o jsonpb` lines, sightings, flow counts, sending.
"""
import importlib.util
import json
import os
from unittest.mock import MagicMock

import pytest
import requests

_AGENT = os.path.join(os.path.dirname(__file__), "..", "..", "Host Files", "hubble_agent.py")


@pytest.fixture()
def mod():
    spec = importlib.util.spec_from_file_location("hubble_agent_under_test", _AGENT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def endpoint(pod="", namespace="team-5g", app="open5gs-amf", identity=31337, extra_labels=()):
    ep = {"ID": 1234, "identity": identity, "namespace": namespace if pod else "",
          "labels": ([f"k8s:app={app}", "k8s:io.kubernetes.pod.namespace=team-5g",
                      "k8s:pod-template-hash=6d9c7b5f4"] if pod else []) + list(extra_labels)}
    if pod:
        ep["pod_name"] = pod
        ep["workloads"] = [{"name": app, "kind": "Deployment"}]
    return ep


def flow_line(src_ip="10.244.0.30", dst_ip="10.244.0.31", src=None, dst=None,
              time="2026-11-25T10:00:05.123456789Z", l4=None, service=None, wrap=True):
    flow = {
        "time": time,
        "verdict": "FORWARDED",
        "IP": {"source": src_ip, "destination": dst_ip, "ipVersion": "IPv4"},
        "l4": l4 if l4 is not None else {"SCTP": {"source_port": 9487, "destination_port": 38412}},
        "source": src if src is not None else endpoint("srsran-gnb-0", app="srsran-gnb"),
        "destination": dst if dst is not None else endpoint("open5gs-amf-abc"),
        "Type": "L3_L4",
        "node_name": "xtrust6g-testbed",
    }
    if service:
        flow["destination_service"] = service
    return json.dumps({"flow": flow, "node_name": "xtrust6g-testbed", "time": time} if wrap else flow)


def make_agent(mod, statuses=(), max_pending=30):
    post = MagicMock(side_effect=[MagicMock(status_code=s, text="") if isinstance(s, int) else s
                                  for s in statuses])
    return mod.HubbleAgent("http://backend/v1/ingest/hubble", "tok", max_pending=max_pending,
                           post=post, clock=lambda: 1_000.0), post


class TestParsing:
    def test_time_with_nanoseconds(self, mod):
        assert mod.parse_time("2026-11-25T10:00:05.123456789Z") == pytest.approx(1795600805.123457)
        assert mod.parse_time("2026-11-25T10:00:05Z") == pytest.approx(1795600805.0)
        assert mod.parse_time("not a time") is None

    @pytest.mark.parametrize("wrap", [True, False])
    def test_flow_fields(self, mod, wrap):
        flow = mod.parse_flow(flow_line(wrap=wrap))
        assert (flow["src_ip"], flow["dst_ip"], flow["protocol"], flow["dst_port"]) == (
            "10.244.0.30", "10.244.0.31", "SCTP", 38412)
        assert flow["dst"]["pod"] == "open5gs-amf-abc"
        assert flow["dst"]["workload"] == "open5gs-amf"
        assert flow["node"] == "xtrust6g-testbed"

    def test_camel_case_field_names(self, mod):
        line = json.dumps({"flow": {
            "IP": {"source": "10.0.0.1", "destination": "10.0.0.2"},
            "l4": {"TCP": {"destinationPort": 7777}},
            "destination": {"podName": "nrf-0", "namespace": "team-5g", "labels": []},
            "destinationService": {"name": "nrf", "namespace": "team-5g"},
            "nodeName": "n1",
        }})
        flow = mod.parse_flow(line)
        assert flow["dst_port"] == 7777
        assert flow["dst"]["pod"] == "nrf-0"
        assert flow["service_name"] == "nrf"
        assert flow["node"] == "n1"

    @pytest.mark.parametrize("line", ["not json", json.dumps({"flow": {"l4": {}}})])
    def test_lines_that_are_not_ip_flows(self, mod, line):
        assert mod.parse_flow(line) is None


class TestAggregation:
    def test_both_pods_are_sighted(self, mod):
        agent, _ = make_agent(mod)
        agent.feed(flow_line())
        batch = agent.rotate()
        pods = {s["ip"]: s for s in batch["sightings"]}
        assert set(pods) == {"10.244.0.30", "10.244.0.31"}
        amf = pods["10.244.0.31"]
        assert (amf["namespace"], amf["pod"], amf["workload_kind"]) == (
            "team-5g", "open5gs-amf-abc", "Deployment")
        assert amf["labels"] == {"app": "open5gs-amf"}  # app labels only, prefix removed
        assert amf["first_seen"] == amf["last_seen"] == pytest.approx(1795600805.123457)

    def test_repeated_flows_widen_one_sighting(self, mod):
        agent, _ = make_agent(mod)
        agent.feed(flow_line(time="2026-11-25T10:00:05Z"))
        agent.feed(flow_line(time="2026-11-25T10:00:45Z"))
        amf = [s for s in agent.rotate()["sightings"] if s["ip"] == "10.244.0.31"][0]
        assert amf["last_seen"] - amf["first_seen"] == pytest.approx(40)

    def test_host_network_endpoints_give_no_pod_sighting(self, mod):
        agent, _ = make_agent(mod)
        host = endpoint(identity=1, extra_labels=["reserved:host"])
        agent.feed(flow_line(src_ip="10.16.0.90", src=host))
        assert [s["ip"] for s in agent.rotate()["sightings"]] == ["10.244.0.31"]

    def test_penm_pods_are_left_out(self, mod):
        agent, _ = make_agent(mod)
        penm = endpoint("penm-backend-0", namespace="team-penm", app="penm-backend",
                        extra_labels=["k8s:app.kubernetes.io/part-of=penm"])
        agent.feed(flow_line(src=penm))
        batch = agent.rotate()
        assert batch["sightings"] == [] and batch["flows"] == []
        assert agent.skipped_penm == 1

    def test_untranslated_service_address_is_a_service_sighting(self, mod):
        agent, _ = make_agent(mod)
        agent.feed(flow_line(dst_ip="10.96.0.10", dst=endpoint(),
                             service={"name": "open5gs-nrf", "namespace": "team-5g"}))
        batch = agent.rotate()
        assert [(s["ip"], s["service"]) for s in batch["services"]] == [("10.96.0.10", "open5gs-nrf")]

    def test_translated_service_flow_sights_the_pod_not_the_service(self, mod):
        agent, _ = make_agent(mod)
        agent.feed(flow_line(service={"name": "open5gs-amf", "namespace": "team-5g"}))
        assert agent.rotate()["services"] == []

    def test_flows_are_counted_per_minute(self, mod):
        agent, _ = make_agent(mod)
        agent.feed(flow_line(time="2026-11-25T10:00:05Z"))
        agent.feed(flow_line(time="2026-11-25T10:00:55Z"))
        agent.feed(flow_line(time="2026-11-25T10:01:05Z"))
        flows = sorted(agent.rotate()["flows"], key=lambda f: f["minute"])
        assert [f["count"] for f in flows] == [2, 1]
        assert flows[0]["minute"] % 60 == 0
        assert flows[0]["src_pod"] == "team-5g/srsran-gnb-0"
        assert flows[0]["dst_pod"] == "team-5g/open5gs-amf-abc"

    def test_portless_protocols_count_with_port_0(self, mod):
        agent, _ = make_agent(mod)
        agent.feed(flow_line(l4={"ICMPv4": {"type": 8}}))
        flow = agent.rotate()["flows"][0]
        assert (flow["protocol"], flow["dst_port"]) == ("ICMPv4", 0)

    def test_rotate_starts_afresh(self, mod):
        agent, _ = make_agent(mod)
        agent.feed(flow_line())
        agent.rotate()
        assert agent.rotate()["sightings"] == []


class TestSending:
    def test_failed_batches_are_retried_oldest_first(self, mod):
        agent, post = make_agent(mod, statuses=[requests.exceptions.ConnectionError(), 200, 200])
        first = agent.rotate()
        agent.rotate()
        agent.flush()
        assert agent.pending[0] is first
        agent.flush()
        assert not agent.pending
        assert post.call_args_list[1].kwargs["json"] is first

    def test_invalid_batches_are_dropped(self, mod):
        agent, _ = make_agent(mod, statuses=[400])
        agent.rotate()
        agent.flush()
        assert not agent.pending

    def test_queue_is_bounded(self, mod):
        agent, _ = make_agent(mod, max_pending=1)
        agent.rotate()
        agent.rotate()
        assert len(agent.pending) == 1 and agent.dropped == 1

    def test_ingest_url_and_command(self, mod):
        assert mod.ingest_url({"HOST_API_URL": "http://b:5555/v1/ingest/zeek"}) == \
            "http://b:5555/v1/ingest/hubble"
        assert mod.hubble_command("hubble", "relay:80") == [
            "hubble", "observe", "--server", "relay:80", "--follow", "-o", "jsonpb"]


def test_agent_batches_are_accepted_by_the_backend(mod, client, app, monkeypatch):
    """What the agent sends is what the backend stores."""
    import k8s_identity

    monkeypatch.setenv("HUBBLE_RETENTION_HOURS", str(24 * 365 * 50))
    token = os.environ["SECRET_TOKEN"]
    agent = mod.HubbleAgent("http://backend/v1/ingest/hubble", token,
                            post=lambda url, json, headers, timeout: client.post(
                                "/v1/ingest/hubble", json=json, headers=headers))
    agent.feed(flow_line(time="2026-11-25T10:00:05Z"))
    agent.feed(flow_line(dst_ip="10.96.0.10", dst=endpoint(),
                         service={"name": "open5gs-nrf", "namespace": "team-5g"}))
    agent.rotate()
    agent.flush()
    assert not agent.pending
    with app.app_context():
        amf = k8s_identity.at("10.244.0.31", 1795600805.0)
        assert amf["pod"] == "open5gs-amf-abc"
        assert k8s_identity.at("10.96.0.10", 1795600805.0)["service"] == "team-5g/open5gs-nrf"
