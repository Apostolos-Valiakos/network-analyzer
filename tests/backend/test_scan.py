"""
Unit tests for scan endpoints and input-sanitisation helpers:
  _is_safe_scan_param  (internal helper)
  POST /v1/scan/start
  GET  /v1/scan/results
"""

import json
from unittest.mock import patch, MagicMock

import pytest

# Import the helper directly so we can unit-test it in isolation
from blueprints.scan import _is_safe_scan_param


# ── _is_safe_scan_param ───────────────────────────────────────────────────────


class TestIsSafeScanParam:
    """Pure-function tests — no HTTP involved."""

    # Valid inputs
    def test_valid_ipv4(self):
        assert _is_safe_scan_param("192.168.1.1") is True

    def test_valid_ipv6(self):
        assert _is_safe_scan_param("2001:db8::1") is True

    def test_valid_cidr_ipv4(self):
        assert _is_safe_scan_param("10.0.0.0/24") is True

    def test_valid_cidr_ipv6(self):
        assert _is_safe_scan_param("::1/128") is True

    def test_valid_simple_hostname(self):
        assert _is_safe_scan_param("myhost") is True

    def test_valid_hostname_with_dots(self):
        assert _is_safe_scan_param("host.local.net") is True

    def test_valid_alphanumeric_flag(self):
        assert _is_safe_scan_param("sV") is True

    # Invalid / dangerous inputs
    def test_empty_string_rejected(self):
        assert _is_safe_scan_param("") is False

    def test_none_rejected(self):
        assert _is_safe_scan_param(None) is False

    def test_integer_rejected(self):
        assert _is_safe_scan_param(42) is False

    def test_semicolon_injection_rejected(self):
        assert _is_safe_scan_param("192.168.1.1;rm -rf /") is False

    def test_pipe_injection_rejected(self):
        assert _is_safe_scan_param("192.168.1.1|id") is False

    def test_backtick_injection_rejected(self):
        assert _is_safe_scan_param("`whoami`") is False

    def test_dollar_sign_rejected(self):
        assert _is_safe_scan_param("$(cat /etc/passwd)") is False

    def test_ampersand_rejected(self):
        assert _is_safe_scan_param("192.168.1.1 & nc -e /bin/sh") is False

    def test_angle_bracket_redirect_rejected(self):
        assert _is_safe_scan_param("host > /tmp/out") is False

    def test_newline_in_param_rejected(self):
        assert _is_safe_scan_param("host\necho pwned") is False


# ── POST /v1/scan/start ───────────────────────────────────────────────────────


class TestStartScan:
    def test_start_scan_requires_auth(self, client):
        res = client.post("/v1/scan/start", json={"target": "10.0.0.1"})
        assert res.status_code == 401

    def test_start_scan_unsafe_param_returns_400(self, client, admin_headers):
        res = client.post(
            "/v1/scan/start",
            data=json.dumps({"target": "10.0.0.1;id", "ports": "22"}),
            headers=admin_headers,
        )
        assert res.status_code == 400
        assert "Invalid value" in res.get_json()["error"]

    def test_start_scan_multiple_unsafe_params_rejected(self, client, admin_headers):
        res = client.post(
            "/v1/scan/start",
            data=json.dumps({"target": "10.0.0.1", "ports": "22 & echo foo"}),
            headers=admin_headers,
        )
        assert res.status_code == 400

    def test_start_scan_vm_unreachable_returns_500(self, client, admin_headers):
        with patch("blueprints.monitoring.requests.post", side_effect=ConnectionError("VM down")):
            res = client.post(
                "/v1/scan/start",
                data=json.dumps({"target": "10.0.0.1"}),
                headers=admin_headers,
            )
        assert res.status_code == 500
        assert "error" in res.get_json()

    def test_start_scan_forwards_vm_response(self, client, admin_headers):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"task_id": "abc123", "status": "queued"}
        mock_resp.status_code = 202
        with patch("blueprints.monitoring.requests.post", return_value=mock_resp):
            res = client.post(
                "/v1/scan/start",
                data=json.dumps({"target": "10.0.0.1"}),
                headers=admin_headers,
            )
        assert res.status_code == 202
        assert res.get_json()["task_id"] == "abc123"

    def test_start_scan_empty_body_allowed(self, client, admin_headers):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"status": "queued"}
        mock_resp.status_code = 202
        with patch("blueprints.monitoring.requests.post", return_value=mock_resp):
            res = client.post(
                "/v1/scan/start",
                data=json.dumps({}),
                headers=admin_headers,
            )
        assert res.status_code == 202


# ── GET /v1/scan/results ──────────────────────────────────────────────────────


class TestGetScanResults:
    def test_get_results_requires_auth(self, client):
        res = client.get("/v1/scan/results")
        assert res.status_code == 401

    def test_get_results_vm_unreachable_returns_500(self, client, admin_headers):
        with patch("blueprints.monitoring.requests.get", side_effect=ConnectionError("VM down")):
            res = client.get("/v1/scan/results", headers=admin_headers)
        assert res.status_code == 500
        assert "error" in res.get_json()

    def test_get_results_forwards_vm_response(self, client, admin_headers):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"results": [{"host": "10.0.0.1", "ports": [22]}]}
        mock_resp.status_code = 200
        with patch("blueprints.monitoring.requests.get", return_value=mock_resp):
            res = client.get("/v1/scan/results", headers=admin_headers)
        assert res.status_code == 200
        assert "results" in res.get_json()

    def test_get_results_vm_returns_404(self, client, admin_headers):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"error": "no results yet"}
        mock_resp.status_code = 404
        with patch("blueprints.monitoring.requests.get", return_value=mock_resp):
            res = client.get("/v1/scan/results", headers=admin_headers)
        assert res.status_code == 404
