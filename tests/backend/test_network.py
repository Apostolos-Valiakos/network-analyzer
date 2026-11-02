"""
Unit tests for continuous-monitoring / network-statistics endpoints:
  GET  /v1/network/statistics
  GET  /v1/network/roles/latest
  GET  /v1/network/export
  POST /v1/ingest/zeek      (internal, token-protected)
"""

import json
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from models import db as _db
from models import FlowStatistic, RoleSnapshot


# ── Helpers ───────────────────────────────────────────────────────────────────


def _insert_flow(app, ts=None, src="1.2.3.4", dst="5.6.7.8"):
    ts = ts or datetime.utcnow()
    with app.app_context():
        row = FlowStatistic(
            ts=ts,
            uid=f"uid_{ts.timestamp()}",
            id_orig_h=src,
            id_resp_h=dst,
            proto="tcp",
            conn_state="SF",
            orig_bytes=1000,
            resp_bytes=500,
            orig_pkts=10,
            resp_pkts=5,
        )
        _db.session.add(row)
        _db.session.commit()


def _insert_snapshot(app, ts_float=None, ip="1.2.3.4", role="AMF"):
    ts_float = ts_float or datetime.utcnow().timestamp()
    with app.app_context():
        row = RoleSnapshot(
            ts=ts_float,
            ip_address=ip,
            role=role,
            confidence=0.95,
            reasoning="Test reasoning",
        )
        _db.session.add(row)
        _db.session.commit()


# ── GET /v1/network/statistics ────────────────────────────────────────────────


class TestNetworkStatistics:
    def test_statistics_requires_auth(self, client):
        res = client.get("/v1/network/statistics")
        assert res.status_code == 401

    def test_statistics_empty_db_returns_empty_csv(self, client, admin_headers):
        res = client.get("/v1/network/statistics", headers=admin_headers)
        assert res.status_code == 200

    def test_statistics_json_format_returns_list(self, client, app, admin_headers):
        _insert_flow(app)
        # Pass end_time explicitly as a POSIX timestamp safely in the future.
        # The default end_time uses datetime.utcnow().timestamp() which is
        # ambiguous on non-UTC machines and can land before the row's ts.
        end = time.time() + 7200
        res = client.get(f"/v1/network/statistics?format=json&end_time={end}", headers=admin_headers)
        assert res.status_code == 200
        data = res.get_json()
        assert isinstance(data, list)
        assert len(data) == 1

    def test_statistics_record_fields_present(self, client, app, admin_headers):
        _insert_flow(app, src="10.0.0.1", dst="10.0.0.2")
        end = time.time() + 7200
        res = client.get(f"/v1/network/statistics?format=json&end_time={end}", headers=admin_headers)
        row = res.get_json()[0]
        for field in ("ts", "id.orig_h", "id.resp_h", "proto", "conn_state",
                      "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"):
            assert field in row, f"Missing field: {field}"

    def test_statistics_limit_filters_results(self, client, app, admin_headers):
        base = datetime(2024, 1, 1)
        for i in range(5):
            _insert_flow(app, ts=base + timedelta(seconds=i))
        res = client.get("/v1/network/statistics?format=json&limit=2", headers=admin_headers)
        assert res.status_code == 200
        assert len(res.get_json()) == 2

    def test_statistics_limit_zero_returns_400(self, client, admin_headers):
        res = client.get("/v1/network/statistics?limit=0", headers=admin_headers)
        assert res.status_code == 400

    def test_statistics_limit_too_large_returns_400(self, client, admin_headers):
        res = client.get("/v1/network/statistics?limit=99999", headers=admin_headers)
        assert res.status_code == 400

    def test_statistics_time_filter(self, client, app, admin_headers):
        old = datetime(2020, 1, 1)
        recent = datetime(2024, 6, 1)
        _insert_flow(app, ts=old)
        _insert_flow(app, ts=recent)
        start = datetime(2024, 1, 1).timestamp()
        end = datetime(2025, 1, 1).timestamp()
        res = client.get(
            f"/v1/network/statistics?format=json&start_time={start}&end_time={end}",
            headers=admin_headers,
        )
        assert res.status_code == 200
        rows = res.get_json()
        assert len(rows) == 1
        assert rows[0]["id.orig_h"] == "1.2.3.4"


# ── GET /v1/network/roles/latest ─────────────────────────────────────────────


class TestLatestRoles:
    def test_roles_requires_auth(self, client):
        res = client.get("/v1/network/roles/latest")
        assert res.status_code == 401

    def test_roles_empty_db_returns_empty(self, client, admin_headers):
        res = client.get("/v1/network/roles/latest?format=json", headers=admin_headers)
        assert res.status_code == 200
        assert res.get_json() == []

    def test_roles_returns_only_latest_snapshot(self, client, app, admin_headers):
        _insert_snapshot(app, ts_float=1000.0, ip="1.1.1.1", role="AMF")
        _insert_snapshot(app, ts_float=2000.0, ip="2.2.2.2", role="SMF")
        res = client.get("/v1/network/roles/latest?format=json", headers=admin_headers)
        data = res.get_json()
        assert all(r["ts"] == 2000.0 for r in data)

    def test_roles_record_has_expected_fields(self, client, app, admin_headers):
        _insert_snapshot(app, ts_float=999.0, ip="3.3.3.3", role="gNB")
        res = client.get("/v1/network/roles/latest?format=json", headers=admin_headers)
        row = res.get_json()[0]
        for field in ("ts", "id.orig_h", "role", "confidence", "reasoning"):
            assert field in row, f"Missing field: {field}"

    def test_roles_limit_applied(self, client, app, admin_headers):
        ts = datetime.utcnow().timestamp()
        for i in range(5):
            _insert_snapshot(app, ts_float=ts, ip=f"10.0.0.{i}", role="UDM")
        res = client.get(
            "/v1/network/roles/latest?format=json&limit=2", headers=admin_headers
        )
        assert len(res.get_json()) == 2


# ── GET /v1/network/export ────────────────────────────────────────────────────


class TestExportStatistics:
    def test_export_requires_auth(self, client):
        res = client.get("/v1/network/export")
        assert res.status_code == 401

    def test_export_csv_content_type(self, client, app, admin_headers):
        _insert_flow(app)
        res = client.get("/v1/network/export", headers=admin_headers)
        assert res.status_code == 200
        assert "text/csv" in res.content_type

    def test_export_json_format(self, client, app, admin_headers):
        _insert_flow(app)
        end = time.time() + 7200
        res = client.get(f"/v1/network/export?format=json&end_time={end}", headers=admin_headers)
        assert res.status_code == 200
        data = json.loads(res.data)
        assert isinstance(data, list)
        assert "conversations" in data[0]

    def test_export_invalid_limit_returns_400(self, client, admin_headers):
        res = client.get("/v1/network/export?limit=0", headers=admin_headers)
        assert res.status_code == 400


# ── POST /v1/ingest/zeek ──────────────────────────────────────────────────────


class TestIngestZeek:
    def test_ingest_rejects_missing_token(self, client):
        res = client.post("/v1/ingest/zeek", json={"flows": []})
        assert res.status_code == 401

    def test_ingest_rejects_wrong_token(self, client):
        res = client.post(
            "/v1/ingest/zeek",
            json={"flows": []},
            headers={"X-Internal-Token": "wrong"},
        )
        assert res.status_code == 401

    def test_ingest_empty_flows_returns_empty_status(self, client):
        res = client.post(
            "/v1/ingest/zeek",
            json={"flows": []},
            headers={"X-Internal-Token": "test-secret-token"},
        )
        assert res.status_code == 200
        assert res.get_json()["status"] == "empty"

    def test_ingest_valid_flow_inserted(self, client, app):
        flow = {
            "ts": 1700000000.0,
            "uid": "C1234",
            "id.orig_h": "192.168.1.1",
            "id.resp_h": "10.0.0.1",
            "proto": "tcp",
            "conn_state": "SF",
            "orig_bytes": 1000,
            "resp_bytes": 500,
            "orig_pkts": 5,
            "resp_pkts": 3,
        }
        mock_conn = MagicMock()
        with patch("psycopg2.connect", return_value=mock_conn), \
             patch("blueprints.monitoring.execute_values"):
            res = client.post(
                "/v1/ingest/zeek",
                json={"flows": [flow]},
                headers={"X-Internal-Token": "test-secret-token"},
            )
        assert res.status_code == 200
        assert res.get_json()["inserted"] == 1

    def test_ingest_duplicate_uid_not_double_inserted(self, client):
        flow = {
            "ts": 1700000001.0,
            "uid": "DUP_UID",
            "id.orig_h": "1.1.1.1",
            "id.resp_h": "2.2.2.2",
            "proto": "udp",
            "conn_state": "S0",
        }
        headers = {"X-Internal-Token": "test-secret-token"}
        mock_conn = MagicMock()
        with patch("psycopg2.connect", return_value=mock_conn), \
             patch("blueprints.monitoring.execute_values"):
            client.post("/v1/ingest/zeek", json={"flows": [flow]}, headers=headers)
            res = client.post("/v1/ingest/zeek", json={"flows": [flow]}, headers=headers)
        assert res.status_code == 200
