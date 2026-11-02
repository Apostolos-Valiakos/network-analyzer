"""
Unit tests for file-history endpoints:
  GET    /v1/history/pcaps
  GET    /v1/history/generated
  GET    /v1/history/clusters
  GET    /v1/history/pcap/<id>/result
  GET    /v1/history/cluster/<id>/result
  POST   /v1/history/pcap/<id>/reanalyze
  DELETE /v1/history/pcap/<id>
  DELETE /v1/history/cluster/<id>
"""

import json
import os
import tempfile
from datetime import datetime

import pytest
from app import db as _db, PCAP_GEN_OUTPUT_DIR, CLUSTERING_OUTPUT_DIR
from models import PcapFile, ClusterResult


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_pcap(app, user_id, filename="hist_test.pcap", source="upload",
               file_path=None, analysis_result=None):
    file_path = file_path or os.path.join(PCAP_GEN_OUTPUT_DIR, filename)
    with app.app_context():
        r = PcapFile(
            filename=filename,
            original_filename=filename,
            file_path=file_path,
            file_size=0,
            status="COMPLETED",
            source=source,
            user_id=user_id,
            analysis_result=analysis_result,
        )
        _db.session.add(r)
        _db.session.commit()
        _db.session.refresh(r)
        return {"id": r.id, "filename": r.filename}


def _make_cluster(app, user_id, filename="hist_cluster.json", result_json=None):
    with app.app_context():
        r = ClusterResult(
            user_id=user_id,
            filename=filename,
            result_json=result_json,
            original_filename="test.pcap",
            created_at=datetime.utcnow(),
        )
        _db.session.add(r)
        _db.session.commit()
        _db.session.refresh(r)
        return {"id": r.id, "filename": r.filename}


# ── GET /v1/history/pcaps ─────────────────────────────────────────────────────


class TestHistoryPcaps:
    def test_requires_auth(self, client):
        res = client.get("/v1/history/pcaps")
        assert res.status_code == 401

    def test_empty_db_returns_empty_list(self, client, user_headers):
        res = client.get("/v1/history/pcaps", headers=user_headers)
        assert res.status_code == 200
        assert res.get_json() == []

    def test_returns_only_upload_source(self, client, app, admin_user, admin_headers):
        _make_pcap(app, admin_user["id"], "up1.pcap", source="upload")
        _make_pcap(app, admin_user["id"], "gen1.pcap", source="generated")
        res = client.get("/v1/history/pcaps", headers=admin_headers)
        names = [r["filename"] for r in res.get_json()]
        assert "up1.pcap" in names
        assert "gen1.pcap" not in names

    def test_regular_user_sees_only_own(self, client, app, admin_user, regular_user, user_headers):
        _make_pcap(app, admin_user["id"], "admin_up.pcap", source="upload")
        _make_pcap(app, regular_user["id"], "user_up.pcap", source="upload")
        res = client.get("/v1/history/pcaps", headers=user_headers)
        names = [r["filename"] for r in res.get_json()]
        assert "user_up.pcap" in names
        assert "admin_up.pcap" not in names

    def test_admin_sees_all_users(self, client, app, admin_user, regular_user, admin_headers):
        _make_pcap(app, admin_user["id"], "adm_u.pcap", source="upload")
        _make_pcap(app, regular_user["id"], "usr_u.pcap", source="upload")
        res = client.get("/v1/history/pcaps", headers=admin_headers)
        names = [r["filename"] for r in res.get_json()]
        assert "adm_u.pcap" in names
        assert "usr_u.pcap" in names

    def test_response_contains_expected_fields(self, client, app, admin_user, admin_headers):
        _make_pcap(app, admin_user["id"], "fields_test.pcap", source="upload")
        res = client.get("/v1/history/pcaps", headers=admin_headers)
        row = res.get_json()[0]
        for f in ("id", "filename", "original_filename", "file_size",
                  "upload_time", "status", "source", "has_result"):
            assert f in row, f"Missing field: {f}"


# ── GET /v1/history/generated ────────────────────────────────────────────────


class TestHistoryGenerated:
    def test_requires_auth(self, client):
        assert client.get("/v1/history/generated").status_code == 401

    def test_returns_only_generated_source(self, client, app, admin_user, admin_headers):
        _make_pcap(app, admin_user["id"], "genA.pcap", source="generated")
        _make_pcap(app, admin_user["id"], "upA.pcap", source="upload")
        res = client.get("/v1/history/generated", headers=admin_headers)
        names = [r["filename"] for r in res.get_json()]
        assert "genA.pcap" in names
        assert "upA.pcap" not in names


# ── GET /v1/history/clusters ─────────────────────────────────────────────────


class TestHistoryClusters:
    def test_requires_auth(self, client):
        assert client.get("/v1/history/clusters").status_code == 401

    def test_empty_returns_empty_list(self, client, user_headers):
        res = client.get("/v1/history/clusters", headers=user_headers)
        assert res.status_code == 200
        assert res.get_json() == []

    def test_user_sees_own_clusters_only(self, client, app, admin_user, regular_user, user_headers):
        _make_cluster(app, admin_user["id"], "admin_clus.json")
        _make_cluster(app, regular_user["id"], "user_clus.json")
        res = client.get("/v1/history/clusters", headers=user_headers)
        names = [r["filename"] for r in res.get_json()]
        assert "user_clus.json" in names
        assert "admin_clus.json" not in names

    def test_admin_sees_all_clusters(self, client, app, admin_user, regular_user, admin_headers):
        _make_cluster(app, admin_user["id"], "adm_c.json")
        _make_cluster(app, regular_user["id"], "usr_c.json")
        res = client.get("/v1/history/clusters", headers=admin_headers)
        names = [r["filename"] for r in res.get_json()]
        assert "adm_c.json" in names
        assert "usr_c.json" in names


# ── GET /v1/history/pcap/<id>/result ─────────────────────────────────────────


class TestGetPcapResult:
    def test_requires_auth(self, client):
        assert client.get("/v1/history/pcap/1/result").status_code == 401

    def test_not_found_returns_404(self, client, admin_headers):
        assert client.get("/v1/history/pcap/99999/result", headers=admin_headers).status_code == 404

    def test_no_analysis_returns_404(self, client, app, admin_user, admin_headers):
        rec = _make_pcap(app, admin_user["id"], "noanalyze.pcap", source="upload")
        res = client.get(f"/v1/history/pcap/{rec['id']}/result", headers=admin_headers)
        assert res.status_code == 404

    def test_with_analysis_returns_result(self, client, app, admin_user, admin_headers):
        result_data = {"total_packets": 100, "graph": {}, "roles": {}}
        rec = _make_pcap(app, admin_user["id"], "withanalyze.pcap",
                         source="upload", analysis_result=result_data)
        res = client.get(f"/v1/history/pcap/{rec['id']}/result", headers=admin_headers)
        assert res.status_code == 200
        assert res.get_json()["total_packets"] == 100

    def test_wrong_owner_returns_403(self, client, app, admin_user, regular_user, user_headers):
        result_data = {"total_packets": 10, "graph": {}, "roles": {}}
        rec = _make_pcap(app, admin_user["id"], "restricted.pcap",
                         source="upload", analysis_result=result_data)
        res = client.get(f"/v1/history/pcap/{rec['id']}/result", headers=user_headers)
        assert res.status_code == 403


# ── GET /v1/history/cluster/<id>/result ──────────────────────────────────────


class TestGetClusterResult:
    def test_requires_auth(self, client):
        assert client.get("/v1/history/cluster/1/result").status_code == 401

    def test_not_found_returns_404(self, client, admin_headers):
        assert client.get("/v1/history/cluster/99999/result", headers=admin_headers).status_code == 404

    def test_no_result_json_returns_404(self, client, app, admin_user, admin_headers):
        rec = _make_cluster(app, admin_user["id"], "noresult.json", result_json=None)
        res = client.get(f"/v1/history/cluster/{rec['id']}/result", headers=admin_headers)
        assert res.status_code == 404

    def test_with_result_json_returns_data(self, client, app, admin_user, admin_headers):
        rec = _make_cluster(app, admin_user["id"], "withresult.json",
                            result_json={"clusters": [{"id": 0}]})
        res = client.get(f"/v1/history/cluster/{rec['id']}/result", headers=admin_headers)
        assert res.status_code == 200
        assert "clusters" in res.get_json()

    def test_wrong_owner_returns_403(self, client, app, admin_user, regular_user, user_headers):
        rec = _make_cluster(app, admin_user["id"], "admin_only.json",
                            result_json={"clusters": []})
        res = client.get(f"/v1/history/cluster/{rec['id']}/result", headers=user_headers)
        assert res.status_code == 403


# ── DELETE /v1/history/pcap/<id> ─────────────────────────────────────────────


class TestDeleteHistoryPcap:
    def test_requires_auth(self, client):
        assert client.delete("/v1/history/pcap/1").status_code == 401

    def test_not_found_returns_404(self, client, admin_headers):
        assert client.delete("/v1/history/pcap/nonexistent-uuid", headers=admin_headers).status_code == 404

    def test_wrong_owner_returns_403(self, client, app, admin_user, regular_user, user_headers):
        rec = _make_pcap(app, admin_user["id"], "admin_del.pcap", source="upload")
        res = client.delete(f"/v1/history/pcap/{rec['id']}", headers=user_headers)
        assert res.status_code == 403

    def test_delete_success(self, client, app, admin_user, admin_headers):
        rec = _make_pcap(app, admin_user["id"], "del_me.pcap", source="upload")
        res = client.delete(f"/v1/history/pcap/{rec['id']}", headers=admin_headers)
        assert res.status_code == 200
        # Verify removed from DB
        with app.app_context():
            assert PcapFile.query.get(rec["id"]) is None

    def test_delete_removes_file_from_disk(self, client, app, admin_user, admin_headers):
        fd, tmp_path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        rec = _make_pcap(app, admin_user["id"], "disk_del.pcap",
                         source="upload", file_path=tmp_path)
        client.delete(f"/v1/history/pcap/{rec['id']}", headers=admin_headers)
        assert not os.path.exists(tmp_path)


# ── DELETE /v1/history/cluster/<id> ──────────────────────────────────────────


class TestDeleteHistoryCluster:
    def test_requires_auth(self, client):
        assert client.delete("/v1/history/cluster/1").status_code == 401

    def test_not_found_returns_404(self, client, admin_headers):
        assert client.delete("/v1/history/cluster/99999", headers=admin_headers).status_code == 404

    def test_wrong_owner_returns_403(self, client, app, admin_user, regular_user, user_headers):
        rec = _make_cluster(app, admin_user["id"], "admin_c_del.json")
        res = client.delete(f"/v1/history/cluster/{rec['id']}", headers=user_headers)
        assert res.status_code == 403

    def test_delete_success(self, client, app, admin_user, admin_headers):
        rec = _make_cluster(app, admin_user["id"], "del_cluster.json")
        res = client.delete(f"/v1/history/cluster/{rec['id']}", headers=admin_headers)
        assert res.status_code == 200
        with app.app_context():
            assert ClusterResult.query.get(rec["id"]) is None
