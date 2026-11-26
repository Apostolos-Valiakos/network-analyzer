"""
The sensor's live DPI agent (Host Files/dpi_agent.py), without tshark or a
backend: windows, the send queue, and the tshark command line.
"""
import importlib.util
import os
from unittest.mock import MagicMock

import pytest
import requests

import role_evidence

_AGENT = os.path.join(os.path.dirname(__file__), "..", "..", "Host Files", "dpi_agent.py")

AMF_LINE = "\t".join(["10.0.0.2", "10.0.0.1", "sctp:ngap", "9487", "38412"] + [""] * 3
                     + ["15"] + [""] * 13)


@pytest.fixture()
def mod():
    spec = importlib.util.spec_from_file_location("dpi_agent_under_test", _AGENT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def response(status, text=""):
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


def make_agent(mod, statuses=(), max_pending=60, times=None):
    post = MagicMock(side_effect=[response(s) if isinstance(s, int) else s for s in statuses])
    ticks = iter(times or [100.0 + 60 * i for i in range(100)])
    agent = mod.DpiAgent("http://backend/v1/ingest/dpi", "tok", max_pending=max_pending,
                         post=post, clock=lambda: next(ticks))
    return agent, post


class TestConfiguration:
    def test_ingest_url_comes_from_the_zeek_url(self, mod):
        env = {"HOST_API_URL": "http://10.0.0.9:5555/v1/ingest/zeek"}
        assert mod.ingest_url(env) == "http://10.0.0.9:5555/v1/ingest/dpi"

    def test_explicit_ingest_url_wins(self, mod):
        env = {"HOST_API_URL": "http://a/v1/ingest/zeek", "DPI_API_URL": "https://b/x"}
        assert mod.ingest_url(env) == "https://b/x"

    def test_missing_url_stops_the_agent(self, mod):
        with pytest.raises(SystemExit):
            mod.ingest_url({})

    def test_capture_filter_adds_the_exclusions(self, mod):
        assert mod.capture_filter("udp port 2152", "") == "udp port 2152"
        assert mod.capture_filter("udp port 2152", "not (port 22)") == "(udp port 2152) and (not (port 22))"

    def test_tshark_command(self, mod):
        cmd = mod.tshark_command("tshark", "any", "udp port 2152", snaplen=128, reset_packets=500000)
        assert cmd[:7] == ["tshark", "-i", "any", "-n", "-l", "-f", "udp port 2152"]
        assert cmd[cmd.index("-s") + 1] == "128"
        assert cmd[cmd.index("-M") + 1] == "500000"
        fields = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e"]
        assert fields == role_evidence._TSHARK_FIELDS
        assert "occurrence=a" in cmd and "aggregator=," in cmd

    def test_tshark_command_defaults_keep_whole_packets_and_state(self, mod):
        cmd = mod.tshark_command("tshark", "any", "tcp")
        assert "-s" not in cmd and "-M" not in cmd


class TestWindows:
    def test_rotate_closes_the_window(self, mod):
        agent, _ = make_agent(mod)
        agent.feed(AMF_LINE + "\n")
        payload = agent.rotate()
        assert (payload["window_start"], payload["window_end"]) == (100.0, 160.0)
        obs = role_evidence.PcapObservations.from_dict(payload["observations"])
        assert obs.evidence["10.0.0.1"].ngap_amf_side == 1
        assert len(payload["window_id"]) == 32
        nxt = agent.rotate()
        assert nxt["window_start"] == 160.0
        assert nxt["observations"]["evidence"] == {}
        assert nxt["window_id"] != payload["window_id"]

    def test_notes_go_out_with_the_window_once(self, mod):
        agent, _ = make_agent(mod)
        agent.note("capture restarted")
        agent.note("capture restarted")
        assert agent.rotate()["observations"]["warnings"] == ["capture restarted"]
        assert agent.rotate()["observations"]["warnings"] == []

    def test_blank_lines_are_ignored(self, mod):
        agent, _ = make_agent(mod)
        agent.feed("\n")
        agent.feed("")
        assert agent.rotate()["observations"]["evidence"] == {}

    def test_a_line_that_cannot_be_parsed_is_counted_not_fatal(self, mod, monkeypatch):
        agent, _ = make_agent(mod)
        monkeypatch.setattr(mod.role_evidence, "_parse_line", MagicMock(side_effect=ValueError))
        agent.feed(AMF_LINE)
        agent.feed(AMF_LINE)
        assert agent.parse_errors == 2


class TestSending:
    def test_accepted_windows_leave_the_queue(self, mod):
        agent, post = make_agent(mod, statuses=[200, 200])
        agent.rotate()
        agent.rotate()
        agent.flush()
        assert not agent.pending
        assert post.call_count == 2
        assert post.call_args.kwargs["headers"] == {"X-Internal-Token": "tok"}

    def test_a_failed_send_keeps_the_window_and_stops(self, mod):
        error = requests.exceptions.ConnectionError("down")
        agent, post = make_agent(mod, statuses=[error, 200, 200])
        first = agent.rotate()
        agent.rotate()
        agent.flush()
        assert post.call_count == 1
        assert agent.pending[0] is first
        agent.flush()
        assert not agent.pending
        sent = [c.kwargs["json"]["window_id"] for c in post.call_args_list]
        assert sent[0] == sent[1] == first["window_id"]  # oldest first, retried

    @pytest.mark.parametrize("status", [401, 500, 503])
    def test_other_errors_keep_the_window(self, mod, status):
        agent, _ = make_agent(mod, statuses=[status])
        agent.rotate()
        agent.flush()
        assert len(agent.pending) == 1

    def test_an_invalid_window_is_dropped(self, mod):
        agent, post = make_agent(mod, statuses=[400, 200])
        agent.rotate()
        agent.rotate()
        agent.flush()
        assert not agent.pending and post.call_count == 2

    def test_the_queue_drops_the_oldest_when_full(self, mod):
        agent, _ = make_agent(mod, max_pending=2)
        first = agent.rotate()
        agent.rotate()
        agent.rotate()
        assert len(agent.pending) == 2
        assert first not in agent.pending
        assert agent.dropped == 1


class TestStats:
    def test_stats_of_this_process_on_linux(self, mod):
        stats = mod.process_stats(os.getpid())
        if not os.path.exists("/proc/self/status"):
            assert stats is None
        else:
            assert stats["rss_mb"] > 0 and stats["cpu_seconds"] >= 0

    def test_missing_process(self, mod):
        assert mod.process_stats(2 ** 30) is None

    def test_log_stats_skips_runners_without_a_process(self, mod):
        runner = MagicMock(process=None, label="user-plane")
        mod.log_stats([runner])  # no error
