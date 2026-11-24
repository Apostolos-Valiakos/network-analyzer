"""
Fixes for the open bugs from the architecture review (24 Nov):
shared-token checks, the empty role snapshot in CSV, and ingest of a body
that is not JSON.
"""
import importlib.util
import os
import re

import pytest

_HOST_FILES = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "Host Files"))


# ── settings.token_matches ───────────────────────────────────────────────────


class TestTokenMatches:
    def test_right_token(self, monkeypatch):
        import settings

        monkeypatch.setenv("SECRET_TOKEN", "s3cret")
        assert settings.token_matches("s3cret") is True

    def test_wrong_or_missing_token(self, monkeypatch):
        import settings

        monkeypatch.setenv("SECRET_TOKEN", "s3cret")
        assert settings.token_matches("nope") is False
        assert settings.token_matches("") is False
        assert settings.token_matches(None) is False

    def test_unset_secret_never_matches(self, monkeypatch):
        import settings

        monkeypatch.delenv("SECRET_TOKEN", raising=False)
        assert settings.token_matches("") is False
        monkeypatch.setenv("SECRET_TOKEN", "")
        assert settings.token_matches("") is False


# ── POST /v1/ingest/zeek ─────────────────────────────────────────────────────


class TestIngest:
    def test_empty_header_refused_when_secret_is_unset(self, client, monkeypatch):
        monkeypatch.delenv("SECRET_TOKEN", raising=False)
        res = client.post("/v1/ingest/zeek", json={"flows": []}, headers={"X-Internal-Token": ""})
        assert res.status_code == 401

    @pytest.mark.parametrize("body, content_type", [
        ("not json", "text/plain"),
        ("[1, 2]", "application/json"),
        ('{"flows": "x"}', "application/json"),
    ])
    def test_body_that_is_not_a_flow_object_is_400(self, client, body, content_type):
        res = client.post(
            "/v1/ingest/zeek",
            data=body,
            headers={"X-Internal-Token": os.environ["SECRET_TOKEN"], "Content-Type": content_type},
        )
        assert res.status_code == 400
        assert "flows" in res.get_json()["error"]

    def test_empty_flow_list_is_still_fine(self, client):
        res = client.post(
            "/v1/ingest/zeek",
            json={"flows": []},
            headers={"X-Internal-Token": os.environ["SECRET_TOKEN"]},
        )
        assert res.status_code == 200
        assert res.get_json() == {"status": "empty"}


# ── GET /v1/network/roles/latest with no snapshots ───────────────────────────


class TestLatestRolesEmpty:
    def test_csv_without_snapshots(self, client, admin_headers):
        res = client.get("/v1/network/roles/latest?format=csv", headers=admin_headers)
        assert res.status_code == 200
        assert res.get_data(as_text=True) == "No data available"

    def test_json_without_snapshots(self, client, admin_headers):
        res = client.get("/v1/network/roles/latest?format=json", headers=admin_headers)
        assert res.status_code == 200
        assert res.get_json() == []

    def test_limit_that_is_not_a_number_is_400(self, client, admin_headers):
        res = client.get("/v1/network/roles/latest?limit=ten", headers=admin_headers)
        assert res.status_code == 400


# ── Sensor (Host Files/pcap_server.py) without a token ───────────────────────


def _load_sensor(monkeypatch, tmp_path, token):
    if token is None:
        monkeypatch.delenv("SECRET_TOKEN", raising=False)
    else:
        monkeypatch.setenv("SECRET_TOKEN", token)
    monkeypatch.setattr(os, "makedirs", lambda *a, **k: None)
    spec = importlib.util.spec_from_file_location(
        "sensor_pcap_server_auth", os.path.join(_HOST_FILES, "pcap_server.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.undo()
    monkeypatch.setattr(module, "PCAP_DIR", str(tmp_path))
    return module


class TestSensorToken:
    def test_no_token_configured_refuses_everything(self, monkeypatch, tmp_path):
        sensor = _load_sensor(monkeypatch, tmp_path, None)
        client = sensor.app.test_client()
        assert client.get("/get-pcap").status_code == 401
        assert client.get("/get-pcap", headers={"X-Internal-Token": ""}).status_code == 401
        # The old built-in default is no longer accepted either.
        assert client.get(
            "/get-pcap", headers={"X-Internal-Token": "change_me_internal_token"}
        ).status_code == 401

    def test_right_token_passes(self, monkeypatch, tmp_path):
        sensor = _load_sensor(monkeypatch, tmp_path, "sensor-secret")
        client = sensor.app.test_client()
        assert client.get("/get-pcap", headers={"X-Internal-Token": "nope"}).status_code == 401
        # Past the token check: no captures yet, so 404 from the route itself.
        assert client.get("/get-pcap", headers={"X-Internal-Token": "sensor-secret"}).status_code == 404


def test_sensor_scripts_have_no_built_in_token():
    """start_sensor.sh must require SECRET_TOKEN instead of falling back to a
    hard-coded value, and the Python sensors must not default to one."""
    with open(os.path.join(_HOST_FILES, "start_sensor.sh"), encoding="utf-8") as f:
        script = f.read()
    assert not re.search(r"SECRET_TOKEN:-[0-9a-fA-F]{16,}", script)
    assert 'if [ -z "${SECRET_TOKEN:-}" ]' in script
    for name in ("pcap_server.py", "zeek_agent.py"):
        with open(os.path.join(_HOST_FILES, name), encoding="utf-8") as f:
            assert 'os.environ.get("SECRET_TOKEN", "")' in f.read()
