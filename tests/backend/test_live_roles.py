"""
Live DPI on the backend: POST /v1/ingest/dpi (server/live_roles.py) and the
source choice of GET /v1/network/roles/latest.
"""
import importlib.util
import os
import shutil
import time
import uuid

import pytest

from models import DpiEvidenceWindow, DpiIdentity, RoleSnapshot, db
from role_evidence import PcapObservations, _parse_line

TOKEN = {"X-Internal-Token": os.environ["SECRET_TOKEN"]}
URL = "/v1/ingest/dpi"


def line(src="", dst="", protos="", sctp_src="", sctp_dst="", ngap="", ran_name="",
         amf_name="", json="", tcp_dst=""):
    fields = [""] * 22
    fields[0], fields[1], fields[2] = src, dst, protos
    fields[3], fields[4], fields[7] = sctp_src, sctp_dst, tcp_dst
    fields[8], fields[13], fields[14], fields[21] = ngap, ran_name, amf_name, json
    return "\t".join(fields)


GNB_TO_AMF = line("10.0.0.2", "10.0.0.1", "sctp:ngap", "9487", "38412", ngap="21",
                  ran_name="cu-01")
AMF_TO_GNB = line("10.0.0.1", "10.0.0.2", "sctp:ngap", "38412", "9487", ngap="21",
                  amf_name="amf-0")
NRF_PROFILE = line("127.0.0.1", "127.0.0.10", "sll:ip:tcp:http2:json", tcp_dst="7777",
                   json="/nfType:AUSF,/ipv4Addresses/[]:10.0.0.11")


def window(*lines, end=None, length=60.0, window_id=None):
    obs = PcapObservations()
    for ln in lines:
        _parse_line(ln, obs)
    end = time.time() if end is None else end
    return {
        "window_id": window_id or uuid.uuid4().hex,
        "window_start": end - length,
        "window_end": end,
        "observations": obs.to_dict(),
    }


def snapshot(app, ts, source="dpi"):
    with app.app_context():
        rows = RoleSnapshot.query.filter_by(ts=ts, source=source).all()
        return {r.ip_address: r for r in rows}


# ── Ingest ────────────────────────────────────────────────────────────────────


class TestIngest:
    def test_requires_the_internal_token(self, client):
        assert client.post(URL, json=window()).status_code == 401
        assert client.post(URL, json=window(), headers={"X-Internal-Token": "wrong"}).status_code == 401

    @pytest.mark.parametrize("body", [
        None,
        [],
        {"window_start": 1, "window_end": 2, "observations": {}},
        {"window_id": "w", "window_start": "1", "window_end": 2, "observations": {}},
        {"window_id": "w", "window_start": 5, "window_end": 5, "observations": {"format": 1}},
        {"window_id": "w", "window_start": 0, "window_end": 4000, "observations": {"format": 1}},
        {"window_id": "w", "window_start": 1, "window_end": 2, "observations": "x"},
        {"window_id": "w", "window_start": 1, "window_end": 2, "observations": {"format": 99}},
        {"window_id": "x" * 65, "window_start": 1, "window_end": 2, "observations": {"format": 1}},
    ])
    def test_bad_bodies_are_400(self, client, body):
        res = client.post(URL, json=body, headers=TOKEN)
        assert res.status_code == 400
        assert "error" in res.get_json()

    def test_window_is_stored_with_a_dpi_snapshot(self, client, app):
        body = window(GNB_TO_AMF, AMF_TO_GNB)
        res = client.post(URL, json=body, headers=TOKEN)
        assert res.status_code == 200
        assert res.get_json() == {"status": "success", "roles": 2}
        rows = snapshot(app, body["window_end"])
        assert rows["10.0.0.1"].role == "AMF"
        assert "NG Setup AMF name 'amf-0'" in rows["10.0.0.1"].reasoning
        assert rows["10.0.0.2"].role == "gNB"
        with app.app_context():
            assert DpiEvidenceWindow.query.count() == 1

    def test_a_resent_window_is_ignored(self, client, app):
        body = window(GNB_TO_AMF)
        client.post(URL, json=body, headers=TOKEN)
        res = client.post(URL, json=body, headers=TOKEN)
        assert res.get_json() == {"status": "duplicate"}
        with app.app_context():
            assert DpiEvidenceWindow.query.count() == 1
            assert RoleSnapshot.query.count() == 2

    def test_a_database_error_is_500_and_stores_nothing(self, client, app, monkeypatch):
        import live_roles

        def boom(end):
            raise RuntimeError("db down")
        monkeypatch.setattr(live_roles, "_store_snapshot", boom)
        res = client.post(URL, json=window(GNB_TO_AMF), headers=TOKEN)
        assert res.status_code == 500
        with app.app_context():
            assert DpiEvidenceWindow.query.count() == 0


# ── Rolling window and identities ────────────────────────────────────────────


class TestMerging:
    def test_windows_of_the_rolling_period_are_merged(self, client, app):
        now = time.time()
        client.post(URL, json=window(GNB_TO_AMF, end=now - 60), headers=TOKEN)
        last = window(line("10.0.0.3", "10.0.0.4", "udp:pfcp"), end=now)
        client.post(URL, json=last, headers=TOKEN)
        rows = snapshot(app, last["window_end"])
        assert rows["10.0.0.1"].role == "AMF"  # from the earlier window
        assert "10.0.0.3" in rows

    def test_windows_older_than_the_rolling_period_drop_out(self, client, app, monkeypatch):
        monkeypatch.setenv("LIVE_ROLE_WINDOW_MINUTES", "5")
        now = time.time()
        client.post(URL, json=window(GNB_TO_AMF, end=now - 600), headers=TOKEN)
        last = window(line("10.0.0.3", "10.0.0.4", "udp:pfcp"), end=now)
        client.post(URL, json=last, headers=TOKEN)
        assert "10.0.0.1" not in snapshot(app, last["window_end"])

    def test_a_late_window_gets_the_snapshot_of_its_own_time(self, client, app):
        """A window re-sent after an outage is merged with the windows before
        it, not with later ones."""
        now = time.time()
        client.post(URL, json=window(GNB_TO_AMF, end=now), headers=TOKEN)
        late = window(line("10.0.0.3", "10.0.0.4", "udp:pfcp"), end=now - 120)
        client.post(URL, json=late, headers=TOKEN)
        rows = snapshot(app, late["window_end"])
        assert "10.0.0.3" in rows and "10.0.0.1" not in rows

    def test_a_registered_nf_keeps_its_role_while_quiet(self, client, app, monkeypatch):
        monkeypatch.setenv("LIVE_ROLE_WINDOW_MINUTES", "5")
        now = time.time()
        client.post(URL, json=window(NRF_PROFILE, end=now - 3600), headers=TOKEN)
        last = window(GNB_TO_AMF, end=now)
        client.post(URL, json=last, headers=TOKEN)
        ausf = snapshot(app, last["window_end"])["10.0.0.11"]
        assert ausf.role == "AUSF"
        assert "NRF profile type 'AUSF'" in ausf.reasoning

    def test_names_of_quiet_ips_are_not_brought_back(self, client, app, monkeypatch):
        """Only NRF profile types make an IP appear on their own; a setup name
        only adds to the reasoning of an IP seen in the rolling period."""
        monkeypatch.setenv("LIVE_ROLE_WINDOW_MINUTES", "5")
        now = time.time()
        client.post(URL, json=window(GNB_TO_AMF, AMF_TO_GNB, end=now - 3600), headers=TOKEN)
        mid = window(line("10.0.0.2", "10.0.0.1", "sctp:ngap", "9487", "38412", ngap="15"),
                     end=now - 60)
        client.post(URL, json=mid, headers=TOKEN)
        rows = snapshot(app, mid["window_end"])
        assert "NG Setup RAN name 'cu-01'" in rows["10.0.0.2"].reasoning
        last = window(line("10.0.0.3", "10.0.0.4", "udp:pfcp"), end=now + 600)
        client.post(URL, json=last, headers=TOKEN)
        assert "10.0.0.2" not in snapshot(app, last["window_end"])

    def test_identities_expire(self, client, app, monkeypatch):
        monkeypatch.setenv("LIVE_ROLE_IDENTITY_HOURS", "1")
        now = time.time()
        client.post(URL, json=window(NRF_PROFILE, end=now - 7200), headers=TOKEN)
        last = window(GNB_TO_AMF, end=now)
        client.post(URL, json=last, headers=TOKEN)
        assert "10.0.0.11" not in snapshot(app, last["window_end"])

    def test_identity_rows_track_first_and_last_sighting(self, client, app):
        now = time.time()
        client.post(URL, json=window(NRF_PROFILE, end=now - 300), headers=TOKEN)
        client.post(URL, json=window(NRF_PROFILE, end=now), headers=TOKEN)
        with app.app_context():
            row = db.session.get(DpiIdentity, ("10.0.0.11", "nrf_nf_type", "AUSF"))
            assert (row.last_seen - row.first_seen).total_seconds() == pytest.approx(300, abs=1)

    def test_old_rows_are_pruned(self, client, app, monkeypatch):
        monkeypatch.setenv("SNAPSHOT_RETENTION_HOURS", "1")
        now = time.time()
        client.post(URL, json=window(NRF_PROFILE, end=now - 7200), headers=TOKEN)
        client.post(URL, json=window(GNB_TO_AMF, end=now), headers=TOKEN)
        with app.app_context():
            assert DpiEvidenceWindow.query.count() == 1
            assert DpiIdentity.query.filter_by(kind="nrf_nf_type").count() == 0
            assert RoleSnapshot.query.filter(RoleSnapshot.ts < now - 3600).count() == 0


# ── Which snapshot GET /v1/network/roles/latest serves ───────────────────────


def _rows(app, ts, source, ip="9.9.9.9", role="AMF"):
    with app.app_context():
        db.session.add(RoleSnapshot(ts=ts, ip_address=ip, role=role, confidence=0.9,
                                    reasoning="r", source=source))
        db.session.commit()


class TestLatestSource:
    LATEST = "/v1/network/roles/latest?format=json"

    def test_fresh_dpi_snapshot_wins(self, client, app, admin_headers):
        now = time.time()
        _rows(app, now - 30, "dpi", role="SMF")
        _rows(app, now - 10, "pcap", role="AMF")
        data = client.get(self.LATEST, headers=admin_headers).get_json()
        assert [(r["role"], r["source"]) for r in data] == [("SMF", "dpi")]

    def test_stale_dpi_falls_back_to_pcap(self, client, app, admin_headers):
        now = time.time()
        _rows(app, now - 600, "dpi", role="SMF")
        _rows(app, now - 900, "pcap", role="AMF")
        data = client.get(self.LATEST, headers=admin_headers).get_json()
        assert [(r["role"], r["source"]) for r in data] == [("AMF", "pcap")]

    def test_stale_dpi_is_still_served_without_pcap(self, client, app, admin_headers):
        _rows(app, time.time() - 600, "dpi", role="SMF")
        data = client.get(self.LATEST, headers=admin_headers).get_json()
        assert [r["source"] for r in data] == ["dpi"]

    def test_freshness_is_configurable(self, client, app, admin_headers, monkeypatch):
        monkeypatch.setenv("DPI_FRESH_SECONDS", "1000")
        now = time.time()
        _rows(app, now - 600, "dpi", role="SMF")
        _rows(app, now - 10, "pcap", role="AMF")
        data = client.get(self.LATEST, headers=admin_headers).get_json()
        assert [r["source"] for r in data] == ["dpi"]

    @pytest.mark.parametrize("source, role", [("pcap", "AMF"), ("dpi", "SMF")])
    def test_source_parameter_picks_that_source(self, client, app, admin_headers, source, role):
        now = time.time()
        _rows(app, now - 30, "dpi", role="SMF")
        _rows(app, now - 10, "pcap", role="AMF")
        data = client.get(f"{self.LATEST}&source={source}", headers=admin_headers).get_json()
        assert [(r["role"], r["source"]) for r in data] == [(role, source)]

    def test_source_without_snapshots_is_empty(self, client, app, admin_headers):
        _rows(app, time.time(), "pcap")
        data = client.get(f"{self.LATEST}&source=dpi", headers=admin_headers).get_json()
        assert data == []

    def test_unknown_source_is_400(self, client, admin_headers):
        res = client.get(f"{self.LATEST}&source=zeek", headers=admin_headers)
        assert res.status_code == 400

    def test_rows_of_the_same_ts_from_the_other_source_are_not_mixed_in(
        self, client, app, admin_headers
    ):
        ts = time.time()
        _rows(app, ts, "dpi", ip="1.1.1.1")
        _rows(app, ts, "pcap", ip="2.2.2.2")
        data = client.get(self.LATEST, headers=admin_headers).get_json()
        assert [r["id.orig_h"] for r in data] == ["1.1.1.1"]


# ── End to end: fixture -> agent -> ingest -> latest roles ───────────────────


_AGENT = os.path.join(os.path.dirname(__file__), "..", "..", "Host Files", "dpi_agent.py")
FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "ppc_5g_and_oran.pcap")


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_live_dpi_gives_the_roles_of_the_capture(client, app, admin_headers):
    """The fixture's tshark lines, fed to the agent in two windows as live
    tshark would print them, give the same roles as the role engine on the
    capture."""
    import packet_table
    import role_evidence
    from role_engine import assess_pcap

    spec = importlib.util.spec_from_file_location("dpi_agent_e2e", _AGENT)
    agent_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent_mod)

    def post(url, json, headers, timeout):
        return client.post(URL, json=json, headers=headers)

    clock = iter([time.time() - 120, time.time() - 60, time.time()])
    agent = agent_mod.DpiAgent("http://backend" + URL, os.environ["SECRET_TOKEN"],
                               post=post, clock=lambda: next(clock))
    lines = packet_table.lines(FIXTURE, role_evidence._TSHARK_FIELDS).splitlines()
    half = len(lines) // 2
    for ln in lines[:half]:
        agent.feed(ln)
    agent.rotate()
    for ln in lines[half:]:
        agent.feed(ln)
    agent.rotate()
    agent.flush()
    assert not agent.pending

    expected = {ip: a.role for ip, a in assess_pcap(FIXTURE).items()}
    data = client.get("/v1/network/roles/latest?format=json&source=dpi",
                      headers=admin_headers).get_json()
    assert {r["id.orig_h"]: r["role"] for r in data} == expected
