"""
Unit tests for pipeline and websocket-trigger endpoints:
  POST /run_pipeline
  POST /start-analysis-from-websocket
"""

import json
import os
from unittest.mock import patch

import pytest
from app import db as _db, PCAP_GEN_OUTPUT_DIR
from models import PcapFile


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_pcap(app, user_id, filename="pipeline_test.pcap", create_file=False):
    file_path = os.path.join(PCAP_GEN_OUTPUT_DIR, filename)
    if create_file:
        with open(file_path, "wb") as f:
            f.write(b"\xa1\xb2\xc3\xd4" + b"\x00" * 20)
    with app.app_context():
        r = PcapFile(
            filename=filename,
            original_filename=filename,
            file_path=file_path,
            file_size=24 if create_file else 0,
            status="COMPLETED",
            source="generated",
            user_id=user_id,
        )
        _db.session.add(r)
        _db.session.commit()
        _db.session.refresh(r)
        return {"id": r.id, "filename": r.filename}


MOCK_PIPELINE_REPORT = {
    "status": "success",
    "ip_roles": {
        "1.2.3.4": "AMF",
        "5.6.7.8": "gNB",
    },
    "ip_role_details": {
        "1.2.3.4": {
            "role": "AMF",
            "confidence": 0.95,
            "reasoning": "Terminates NGAP on SCTP 38412 (18 pkts)",
        },
        # 5.6.7.8 intentionally missing — endpoint must default to 0.0 / ""
    },
}


# ── POST /run_pipeline ────────────────────────────────────────────────────────


class TestRunPipeline:
    def test_run_pipeline_requires_auth(self, client):
        res = client.post("/run_pipeline", json={"pcap_file_path": "x.pcap"})
        assert res.status_code == 401

    def test_run_pipeline_pcap_not_in_db_returns_404(self, client, admin_headers):
        res = client.post(
            "/run_pipeline",
            data=json.dumps({"pcap_file_path": "ghost.pcap", "model_name": "rule_based"}),
            headers=admin_headers,
        )
        assert res.status_code == 404

    def test_run_pipeline_wrong_owner_returns_403(self, client, app, admin_user, regular_user, user_headers):
        _make_pcap(app, admin_user["id"], filename="pipeline_admin.pcap")
        res = client.post(
            "/run_pipeline",
            data=json.dumps({"pcap_file_path": "pipeline_admin.pcap", "model_name": "rule_based"}),
            headers=user_headers,
        )
        assert res.status_code == 403

    def test_run_pipeline_file_not_on_disk_returns_404(self, client, app, admin_user, admin_headers):
        _make_pcap(app, admin_user["id"], filename="in_db_no_disk.pcap", create_file=False)
        res = client.post(
            "/run_pipeline",
            data=json.dumps({"pcap_file_path": "in_db_no_disk.pcap", "model_name": "rule_based"}),
            headers=admin_headers,
        )
        assert res.status_code == 404

    def test_run_pipeline_success_returns_roles(self, client, app, admin_user, admin_headers):
        _make_pcap(app, admin_user["id"], filename="pipeline_real.pcap", create_file=True)
        with patch("app.run_ip_role_pipeline", return_value=MOCK_PIPELINE_REPORT):
            res = client.post(
                "/run_pipeline",
                data=json.dumps({"pcap_file_path": "pipeline_real.pcap", "model_name": "rule_based"}),
                headers=admin_headers,
            )
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "success"
        assert "ip_roles" in data
        path = os.path.join(PCAP_GEN_OUTPUT_DIR, "pipeline_real.pcap")
        if os.path.exists(path):
            os.remove(path)

    def test_run_pipeline_wraps_roles_with_confidence(self, client, app, admin_user, admin_headers):
        """run_pipeline_endpoint enriches ip_roles with the engine's real
        confidence/reasoning; IPs missing from details default to 0.0."""
        _make_pcap(app, admin_user["id"], filename="pipeline_conf.pcap", create_file=True)
        with patch("app.run_ip_role_pipeline", return_value=MOCK_PIPELINE_REPORT):
            res = client.post(
                "/run_pipeline",
                data=json.dumps({"pcap_file_path": "pipeline_conf.pcap", "model_name": "rule_based"}),
                headers=admin_headers,
            )
        roles = res.get_json()["ip_roles"]
        for ip, info in roles.items():
            assert "role" in info
            assert "confidence" in info
            assert "reasoning" in info
        assert roles["1.2.3.4"]["confidence"] == 0.95
        assert roles["1.2.3.4"]["reasoning"].startswith("Terminates NGAP")
        assert roles["5.6.7.8"]["confidence"] == 0.0
        assert roles["5.6.7.8"]["reasoning"] == ""
        path = os.path.join(PCAP_GEN_OUTPUT_DIR, "pipeline_conf.pcap")
        if os.path.exists(path):
            os.remove(path)

    def test_run_pipeline_error_from_service_returns_500(self, client, app, admin_user, admin_headers):
        _make_pcap(app, admin_user["id"], filename="pipeline_err.pcap", create_file=True)
        with patch("app.run_ip_role_pipeline", side_effect=RuntimeError("oops")):
            res = client.post(
                "/run_pipeline",
                data=json.dumps({"pcap_file_path": "pipeline_err.pcap", "model_name": "rule_based"}),
                headers=admin_headers,
            )
        assert res.status_code == 500
        path = os.path.join(PCAP_GEN_OUTPUT_DIR, "pipeline_err.pcap")
        if os.path.exists(path):
            os.remove(path)


# ── POST /start-analysis-from-websocket ──────────────────────────────────────


class TestStartAnalysisFromWebsocket:
    def test_ws_requires_auth(self, client):
        res = client.post("/start-analysis-from-websocket", json={"ws_url": "ws://x", "seconds": 10})
        assert res.status_code == 401

    def test_ws_missing_ws_url_returns_400(self, client, admin_headers):
        res = client.post(
            "/start-analysis-from-websocket",
            data=json.dumps({"seconds": 10}),
            headers=admin_headers,
        )
        assert res.status_code == 400

    def test_ws_missing_seconds_returns_400(self, client, admin_headers):
        res = client.post(
            "/start-analysis-from-websocket",
            data=json.dumps({"ws_url": "ws://localhost:5002"}),
            headers=admin_headers,
        )
        assert res.status_code == 400

    def test_ws_seconds_not_integer_returns_400(self, client, admin_headers):
        res = client.post(
            "/start-analysis-from-websocket",
            data=json.dumps({"ws_url": "ws://localhost:5002", "seconds": "notanumber"}),
            headers=admin_headers,
        )
        assert res.status_code == 400

    def test_ws_seconds_zero_returns_400(self, client, admin_headers):
        res = client.post(
            "/start-analysis-from-websocket",
            data=json.dumps({"ws_url": "ws://localhost:5002", "seconds": 0}),
            headers=admin_headers,
        )
        assert res.status_code == 400

    def test_ws_seconds_too_large_returns_400(self, client, admin_headers):
        res = client.post(
            "/start-analysis-from-websocket",
            data=json.dumps({"ws_url": "ws://localhost:5002", "seconds": 3601}),
            headers=admin_headers,
        )
        assert res.status_code == 400

    def test_ws_success_returns_202(self, client, admin_headers):
        with patch("app.startWebSocketClient", return_value=True):
            res = client.post(
                "/start-analysis-from-websocket",
                data=json.dumps({"ws_url": "ws://localhost:5002", "seconds": 30}),
                headers=admin_headers,
            )
        assert res.status_code == 202

    def test_ws_client_failure_returns_500(self, client, admin_headers):
        with patch("app.startWebSocketClient", return_value=False):
            res = client.post(
                "/start-analysis-from-websocket",
                data=json.dumps({"ws_url": "ws://localhost:5002", "seconds": 30}),
                headers=admin_headers,
            )
        assert res.status_code == 500

    def test_ws_seconds_boundary_1_accepted(self, client, admin_headers):
        with patch("app.startWebSocketClient", return_value=True):
            res = client.post(
                "/start-analysis-from-websocket",
                data=json.dumps({"ws_url": "ws://localhost:5002", "seconds": 1}),
                headers=admin_headers,
            )
        assert res.status_code == 202

    def test_ws_seconds_boundary_3600_accepted(self, client, admin_headers):
        with patch("app.startWebSocketClient", return_value=True):
            res = client.post(
                "/start-analysis-from-websocket",
                data=json.dumps({"ws_url": "ws://localhost:5002", "seconds": 3600}),
                headers=admin_headers,
            )
        assert res.status_code == 202
