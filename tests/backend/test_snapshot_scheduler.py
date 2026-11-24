"""
Live role snapshots (server/snapshot_scheduler.py). conftest.py replaces the
module with a stub for the app tests, so these tests load the real file.
"""
import importlib.util
import os
import threading
from unittest.mock import MagicMock, patch

import pytest
import requests

from conftest import FIXTURE_PCAP

_SERVER = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "server"))


@pytest.fixture()
def sched(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location(
        "real_snapshot_scheduler", os.path.join(_SERVER, "snapshot_scheduler.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    import settings

    monkeypatch.setattr(settings, "RESULTS_OUTPUT_DIR", str(tmp_path))
    return module


def _sensor_response(data: bytes):
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.iter_content.return_value = [data[i:i + 4096] for i in range(0, len(data), 4096)]
    return response


def test_fetch_saves_a_trimmed_snapshot(sched, tmp_path):
    sample = open(FIXTURE_PCAP, "rb").read()
    with patch.object(sched.requests, "get", return_value=_sensor_response(sample + bytes(3952))) as get:
        path = sched.fetch_snapshot(300)
    assert path == str(tmp_path / "latest_snapshot.pcap")
    assert open(path, "rb").read() == sample  # zero tail trimmed
    assert list(tmp_path.iterdir()) == [tmp_path / "latest_snapshot.pcap"]  # no .part left
    params = get.call_args.kwargs["params"]
    assert params["end_time"] - params["start_time"] == pytest.approx(300)
    assert "X-Internal-Token" in get.call_args.kwargs["headers"]


def test_store_roles_writes_rows_and_prunes_old_ones(sched, app, fresh_db, monkeypatch):
    from models import RoleSnapshot, db
    from role_engine import RoleAssessment

    roles = {
        "10.0.0.1": RoleAssessment("10.0.0.1", "AMF", 0.9, "NGAP listener"),
        "10.0.0.2": RoleAssessment("10.0.0.2", "gNB", 0.8, "NGAP client"),
    }
    monkeypatch.setattr(sched, "assess_pcap", lambda path, warnings=None: roles)
    monkeypatch.setenv("SNAPSHOT_RETENTION_HOURS", "1")
    with app.app_context():
        db.session.add(RoleSnapshot(ts=1_000.0, ip_address="10.9.9.9", role="old"))
        db.session.commit()
        assert sched.store_roles("x.pcap", taken_at=1_000.0 + 7200) == 2
        rows = RoleSnapshot.query.order_by(RoleSnapshot.ip_address).all()
        assert [(r.ip_address, r.role, r.confidence) for r in rows] == [
            ("10.0.0.1", "AMF", 0.9),
            ("10.0.0.2", "gNB", 0.8),
        ]


def test_latest_roles_serves_the_stored_snapshot(sched, app, client, admin_headers, monkeypatch):
    from role_engine import RoleAssessment

    monkeypatch.setattr(
        sched, "assess_pcap",
        lambda path, warnings=None: {"10.0.0.1": RoleAssessment("10.0.0.1", "AMF", 0.9, "x")},
    )
    with app.app_context():
        sched.store_roles("x.pcap", taken_at=1_800_000_000.0)
    body = client.get("/v1/network/roles/latest?format=json", headers=admin_headers).get_json()
    assert [(r["id.orig_h"], r["role"]) for r in body] == [("10.0.0.1", "AMF")]


def test_unreachable_sensor_is_logged_not_raised(sched, app, caplog):
    with patch.object(sched.requests, "get", side_effect=requests.exceptions.ConnectionError("refused")):
        sched.run_role_snapshot(app)
    assert "could not fetch a slice from the sensor" in caplog.text


def test_disabled_scheduler_does_not_start(sched, app, monkeypatch):
    monkeypatch.setenv("SNAPSHOT_ENABLED", "false")
    assert sched.start_scheduler(app) is None


def test_scheduler_starts_once_and_runs_a_tick(sched, app, monkeypatch):
    monkeypatch.setenv("SNAPSHOT_ENABLED", "true")
    ticked = threading.Event()
    monkeypatch.setattr(sched, "run_role_snapshot", lambda a: ticked.set())
    stop = threading.Event()
    thread = sched.start_scheduler(app, stop=stop)
    try:
        assert thread is not None
        assert ticked.wait(5)
        assert sched.start_scheduler(app) is None  # second call: already running
    finally:
        stop.set()
        thread.join(5)


def test_analyze_live_keeps_the_snapshot(client, admin_headers, monkeypatch, tmp_path):
    import blueprints.monitoring as monitoring

    snapshot = tmp_path / "latest_snapshot.pcap"
    snapshot.write_bytes(open(FIXTURE_PCAP, "rb").read())
    monkeypatch.setattr(monitoring, "RESULTS_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setattr(
        monitoring, "run_ip_role_pipeline",
        lambda path, model, selected_ips=None: {"status": "success", "ip_roles": {}},
    )
    for _ in range(2):
        res = client.post("/v1/analyze_live", headers=admin_headers)
        assert res.status_code == 200
    assert snapshot.exists()


@pytest.mark.skipif(__import__("shutil").which("tshark") is None and not os.environ.get("TSHARK_PATH"),
                    reason="needs tshark")
def test_full_tick_with_the_real_role_engine(sched, app, fresh_db):
    """Fake sensor, real tshark and role engine: sample.pcap holds a gNB and an AMF."""
    from models import RoleSnapshot

    sample = open(FIXTURE_PCAP, "rb").read()
    with patch.object(sched.requests, "get", return_value=_sensor_response(sample)):
        sched.run_role_snapshot(app)
    with app.app_context():
        roles = {r.ip_address: r.role for r in RoleSnapshot.query.all()}
    assert roles["192.168.100.5"] == "gNB"
    assert roles["192.168.100.21"] == "AMF"
