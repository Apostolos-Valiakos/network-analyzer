"""
Failures that used to be swallowed: each is now logged, and where the rest of
the request still succeeds, it is reported in a "warnings" list instead of
looking like a clean result. Server errors in the monitoring routes are 500,
bad parameters 400.
"""
import io
import json
import logging
from unittest.mock import MagicMock

import pytest

from conftest import FIXTURE_PCAP
from snapshot_utils import tshark_version


def _boom(*args, **kwargs):
    raise ValueError("broken capture")


# ── Role engine ───────────────────────────────────────────────────────────────


class TestRoleEngineWarnings:
    def test_read_error_becomes_a_warning(self, monkeypatch):
        import role_engine

        monkeypatch.setattr(role_engine.packet_table, "lines", _boom)
        warnings = []
        roles = role_engine.assess_pcap("x.pcap", warnings=warnings)

        assert roles == {}
        assert warnings == [
            "Role detection failed while reading the capture (ValueError); roles may be incomplete."
        ]

    def test_missing_tshark_becomes_a_warning(self, monkeypatch):
        import role_engine

        def _missing(*a, **k):
            raise FileNotFoundError("tshark")

        monkeypatch.setattr(role_engine.packet_table, "lines", _missing)
        obs = role_engine.collect_evidence("x.pcap")
        assert obs.warnings == ["Role detection unavailable: tshark was not found on the server."]

    @pytest.mark.skipif(tshark_version() is None, reason="needs tshark on PATH")
    def test_clean_read_has_no_warnings(self):
        import role_engine

        warnings = []
        role_engine.assess_pcap(FIXTURE_PCAP, warnings=warnings)
        assert warnings == []

    def test_partial_roles_are_not_cached(self, app, pcap_in_db, monkeypatch):
        import role_engine
        from models import IpRole

        partial = {"10.0.0.1": role_engine.RoleAssessment("10.0.0.1", "AMF", 0.9, "x")}

        def _partial(path, warnings=None):
            warnings.append("Role detection timed out reading the capture; roles may be incomplete.")
            return partial

        monkeypatch.setattr(role_engine, "assess_pcap", _partial)
        with app.app_context():
            warnings = []
            result = role_engine.get_or_compute_roles(pcap_in_db["path"], warnings=warnings)
            assert result == partial
            assert len(warnings) == 1
            assert IpRole.query.filter_by(pcap_id=pcap_in_db["id"]).count() == 0


# ── Pipeline report and core analysis ────────────────────────────────────────


class TestCoreAnalysisWarnings:
    _TRAFFIC = ({"total_packets": 3, "conversations": {}}, None)

    def test_pipeline_warnings_reach_the_result(self, monkeypatch):
        import analysis_service

        monkeypatch.setattr(analysis_service, "summarize_traffic", lambda p: self._TRAFFIC)
        monkeypatch.setattr(
            analysis_service,
            "run_ip_role_pipeline",
            lambda p, m: {"status": "success", "ip_roles": {}, "warnings": ["partial roles"]},
        )
        result = analysis_service.run_core_analysis("x.pcap", "rule_based", "Pipeline")
        assert result["warnings"] == ["partial roles"]

    def test_no_warnings_key_when_everything_worked(self, monkeypatch):
        import analysis_service

        monkeypatch.setattr(analysis_service, "summarize_traffic", lambda p: self._TRAFFIC)
        monkeypatch.setattr(
            analysis_service,
            "run_ip_role_pipeline",
            lambda p, m: {"status": "success", "ip_roles": {"10.0.0.1": "AMF"}},
        )
        result = analysis_service.run_core_analysis("x.pcap", "rule_based", "Pipeline")
        assert "warnings" not in result

    def test_worker_report_carries_processor_warnings(self, app, fresh_db, tmp_path, monkeypatch):
        import Preprocess
        import settings

        monkeypatch.setattr(settings, "RESULTS_OUTPUT_DIR", str(tmp_path))
        monkeypatch.setattr(Preprocess.packet_table, "ensure", lambda p: None)

        def _roles(path, warnings=None):
            warnings.append("partial roles")
            return {}

        monkeypatch.setattr(Preprocess, "get_or_compute_roles", _roles)

        class _Queue(list):
            put = list.append

        queue = _Queue()
        Preprocess._pipeline_worker(str(tmp_path / "x.pcap"), "rule_based", queue)
        assert queue[0]["status"] == "success"
        assert queue[0]["warnings"] == ["partial roles"]


# ── Upload ────────────────────────────────────────────────────────────────────


class TestUploadWarnings:
    @pytest.fixture()
    def upload(self, client, admin_headers, tmp_path, monkeypatch):
        import blueprints.pcaps as pcaps

        monkeypatch.setattr(pcaps, "PCAP_GEN_OUTPUT_DIR", str(tmp_path))
        monkeypatch.setattr(
            pcaps,
            "run_core_analysis",
            lambda p, m, label: {"total_packets": 3, "graph": {}, "roles": {"10.0.0.1": "AMF"}},
        )
        headers = {"Authorization": admin_headers["Authorization"]}

        def _post():
            with open(FIXTURE_PCAP, "rb") as f:
                data = {"file": (io.BytesIO(f.read()), "sample.pcap")}
            return client.post("/automated-analysis", data=data, headers=headers,
                               content_type="multipart/form-data")

        return _post

    def test_ue_and_privacy_failures_are_reported(self, upload, monkeypatch, caplog):
        import blueprints.pcaps as pcaps

        monkeypatch.setattr(pcaps, "initialize_analysis_for_ue", _boom)
        monkeypatch.setattr(pcaps, "records_from_pcap", _boom)
        with caplog.at_level(logging.ERROR):
            res = upload()

        assert res.status_code == 200
        body = res.get_json()
        assert body["roles"] == {"10.0.0.1": "AMF"}
        assert body["privacy_records"] == []
        assert body["warnings"] == [
            "UE identity extraction failed; no UE sessions were stored.",
            "Privacy record extraction failed; privacy records are empty.",
        ]
        assert "UE analysis failed" in caplog.text
        assert "Privacy records failed" in caplog.text

    def test_clean_upload_has_no_warnings(self, upload, monkeypatch):
        import blueprints.pcaps as pcaps

        monkeypatch.setattr(pcaps, "initialize_analysis_for_ue", lambda p: [])
        monkeypatch.setattr(pcaps, "records_from_pcap", lambda p: [])
        res = upload()
        assert res.status_code == 200
        assert "warnings" not in res.get_json()


def test_ue_extraction_raises_instead_of_returning_nothing(monkeypatch):
    import ueAnalysis

    monkeypatch.setattr(ueAnalysis.packet_table, "row_dicts", _boom)
    with pytest.raises(ValueError):
        ueAnalysis.initialize_analysis_for_ue("x.pcap")


# ── Clustering result that cannot be saved ───────────────────────────────────


def test_clustering_save_failure_returns_result_with_warning(
    client, admin_headers, pcap_in_db, monkeypatch, caplog
):
    import blueprints.clustering as clustering
    from models import db

    result = {"clusters": [], "graphData": {}, "clusterSummary": []}
    monkeypatch.setattr(clustering, "analyze_pcap_for_clustering", lambda *a, **k: dict(result))

    def _commit_fails():
        raise RuntimeError("database is locked")

    monkeypatch.setattr(db.session, "commit", _commit_fails)
    with caplog.at_level(logging.ERROR):
        res = client.post(
            "/clustering",
            data=json.dumps({"file": pcap_in_db["filename"], "clusters": 3}),
            headers=admin_headers,
        )

    assert res.status_code == 200
    body = res.get_json()
    assert body["clusters"] == []
    assert body["warnings"] == [
        "The clustering result could not be saved, so it will not appear in History."
    ]
    assert "Could not save the clustering result" in caplog.text


# ── Monitoring: 400 for bad parameters, 500 for server errors ────────────────


@pytest.mark.parametrize("route", ["/v1/network/statistics", "/v1/network/export"])
class TestMonitoringStatusCodes:
    @pytest.mark.parametrize("query", ["start_time=abc", "end_time=1e400", "limit=ten"])
    def test_bad_parameters_are_400(self, client, admin_headers, route, query):
        res = client.get(f"{route}?{query}&format=json", headers=admin_headers)
        assert res.status_code == 400
        assert "Unix timestamps" in res.get_json()["error"]

    def test_database_error_is_500(self, client, admin_headers, route, monkeypatch):
        import blueprints.monitoring as monitoring

        broken = MagicMock()
        broken.query.filter.side_effect = RuntimeError("database down")
        monkeypatch.setattr(monitoring, "FlowStatistic", broken)
        res = client.get(f"{route}?format=json", headers=admin_headers)
        assert res.status_code == 500
        assert res.get_json() == {"error": "Internal server error"}


# ── Live packet chunks ────────────────────────────────────────────────────────


class TestPcapChunkErrors:
    @pytest.fixture(autouse=True)
    def _out_dir(self, tmp_path, monkeypatch):
        import pcap_generator_service as svc

        monkeypatch.setattr(svc, "PCAP_OUTPUT_DIR", str(tmp_path))
        self.dir = tmp_path

    def test_invalid_base64_packet_is_skipped_and_logged(self, caplog):
        import base64
        from pcap_generator_service import handle_pcap_chunk

        good = base64.b64encode(b"\x00" * 60).decode()
        with caplog.at_level(logging.WARNING):
            ok, name, err = handle_pcap_chunk("s1", ["not base64!", good])
        assert (ok, err) == (True, None)
        assert "not valid base64" in caplog.text
        # global header (24) + one packet header (16) + 60 bytes
        assert (self.dir / name).stat().st_size == 24 + 16 + 60

    def test_write_error_is_reported(self, monkeypatch):
        import base64
        import pcap_generator_service as svc

        def _no_space(n):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(svc, "_pcap_packet_header", _no_space)
        ok, name, err = svc.handle_pcap_chunk("s2", [base64.b64encode(b"\x00" * 60).decode()])
        assert ok is False
        assert "No space left" in err
