"""
Unit tests for clustering endpoints:
  POST /clustering
  GET  /suggested_clusters
  POST /save-results
  GET  /clustering-output/<filename>
"""

import json
import os
from unittest.mock import patch, MagicMock

import pytest
from app import db as _db, PCAP_GEN_OUTPUT_DIR, CLUSTERING_OUTPUT_DIR
from models import PcapFile, ClusterResult


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_pcap(app, user_id, filename="cluster_test.pcap", create_file=False):
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


def _make_cluster_result(app, user_id, filename="result_test.json"):
    with app.app_context():
        r = ClusterResult(
            user_id=user_id,
            filename=filename,
            result_json={"clusters": []},
            original_filename="test.pcap",
        )
        _db.session.add(r)
        _db.session.commit()
        _db.session.refresh(r)
        return {"id": r.id, "filename": r.filename}


# Minimal mock result returned by analyze_pcap_for_clustering
MOCK_CLUSTER_RESULT = {
    "clusterSummary": {
        "best_k": 2,
        "best_modularity": 0.45,
        "modularity_scores": {2: 0.45, 3: 0.40},
        "cluster_hierarchy": {},
        "mostImportantCluster": 0,
    },
    "clusters": [],
    "anomalies": [],
}


# ── POST /clustering ──────────────────────────────────────────────────────────


class TestClustering:
    def test_clustering_requires_auth(self, client):
        res = client.post("/clustering", json={"file": "x.pcap"})
        assert res.status_code == 401

    def test_clustering_not_json_returns_400(self, client, admin_headers):
        res = client.post(
            "/clustering",
            data="not json",
            headers={
                "Authorization": admin_headers["Authorization"],
                "Content-Type": "text/plain",
            },
        )
        assert res.status_code == 400

    def test_clustering_pcap_not_found_in_db(self, client, admin_headers):
        res = client.post(
            "/clustering",
            data=json.dumps({"file": "ghost.pcap", "clusters": 3}),
            headers=admin_headers,
        )
        assert res.status_code == 404

    def test_clustering_wrong_owner_returns_403(self, client, app, admin_user, regular_user, user_headers):
        _make_pcap(app, admin_user["id"], filename="admin_owned.pcap")
        res = client.post(
            "/clustering",
            data=json.dumps({"file": "admin_owned.pcap", "clusters": 3}),
            headers=user_headers,
        )
        assert res.status_code == 403

    def test_clustering_clusters_too_small_returns_400(self, client, app, admin_user, admin_headers):
        # create_file=True: the endpoint checks file existence BEFORE validating params
        _make_pcap(app, admin_user["id"], filename="param_test.pcap", create_file=True)
        res = client.post(
            "/clustering",
            data=json.dumps({"file": "param_test.pcap", "clusters": 1}),
            headers=admin_headers,
        )
        assert res.status_code == 400
        path = os.path.join(PCAP_GEN_OUTPUT_DIR, "param_test.pcap")
        if os.path.exists(path):
            os.remove(path)

    def test_clustering_clusters_too_large_returns_400(self, client, app, admin_user, admin_headers):
        _make_pcap(app, admin_user["id"], filename="param_test2.pcap", create_file=True)
        res = client.post(
            "/clustering",
            data=json.dumps({"file": "param_test2.pcap", "clusters": 21}),
            headers=admin_headers,
        )
        assert res.status_code == 400
        path = os.path.join(PCAP_GEN_OUTPUT_DIR, "param_test2.pcap")
        if os.path.exists(path):
            os.remove(path)

    def test_clustering_negative_threshold_returns_400(self, client, app, admin_user, admin_headers):
        _make_pcap(app, admin_user["id"], filename="param_test3.pcap", create_file=True)
        res = client.post(
            "/clustering",
            data=json.dumps({"file": "param_test3.pcap", "clusters": 3, "anomaly_threshold": -1}),
            headers=admin_headers,
        )
        assert res.status_code == 400
        path = os.path.join(PCAP_GEN_OUTPUT_DIR, "param_test3.pcap")
        if os.path.exists(path):
            os.remove(path)

    def test_clustering_file_not_on_disk_returns_404(self, client, app, admin_user, admin_headers):
        _make_pcap(app, admin_user["id"], filename="exists_in_db_not_disk.pcap", create_file=False)
        res = client.post(
            "/clustering",
            data=json.dumps({"file": "exists_in_db_not_disk.pcap", "clusters": 3}),
            headers=admin_headers,
        )
        assert res.status_code == 404

    def test_clustering_success_returns_result(self, client, app, admin_user, admin_headers):
        _make_pcap(app, admin_user["id"], filename="real_for_cluster.pcap", create_file=True)
        with patch("app.analyze_pcap_for_clustering", return_value=MOCK_CLUSTER_RESULT):
            res = client.post(
                "/clustering",
                data=json.dumps({"file": "real_for_cluster.pcap", "clusters": 2}),
                headers=admin_headers,
            )
        assert res.status_code == 200
        data = res.get_json()
        assert "clusterSummary" in data
        # Cleanup
        path = os.path.join(PCAP_GEN_OUTPUT_DIR, "real_for_cluster.pcap")
        if os.path.exists(path):
            os.remove(path)

    def test_clustering_persists_result_to_db(self, client, app, admin_user, admin_headers):
        _make_pcap(app, admin_user["id"], filename="persist_test.pcap", create_file=True)
        with patch("app.analyze_pcap_for_clustering", return_value=MOCK_CLUSTER_RESULT):
            client.post(
                "/clustering",
                data=json.dumps({"file": "persist_test.pcap", "clusters": 2}),
                headers=admin_headers,
            )
        with app.app_context():
            # A ClusterResult record should now exist for this pcap
            pcap = PcapFile.query.filter_by(filename="persist_test.pcap").first()
            assert pcap is not None
            result = ClusterResult.query.filter_by(pcap_id=pcap.id).first()
            assert result is not None
            assert result.result_json is not None
        path = os.path.join(PCAP_GEN_OUTPUT_DIR, "persist_test.pcap")
        if os.path.exists(path):
            os.remove(path)


# ── GET /suggested_clusters ───────────────────────────────────────────────────


class TestSuggestedClusters:
    def test_suggested_clusters_requires_auth(self, client):
        res = client.get("/suggested_clusters?file=test.pcap")
        assert res.status_code == 401

    def test_suggested_clusters_missing_file_param(self, client, admin_headers):
        res = client.get("/suggested_clusters", headers=admin_headers)
        assert res.status_code == 400

    def test_suggested_clusters_pcap_not_in_db(self, client, admin_headers):
        res = client.get("/suggested_clusters?file=ghost.pcap", headers=admin_headers)
        assert res.status_code == 404

    def test_suggested_clusters_success(self, client, app, admin_user, admin_headers):
        _make_pcap(app, admin_user["id"], filename="suggest_test.pcap", create_file=True)
        with patch("app.analyze_pcap_for_clustering", return_value=MOCK_CLUSTER_RESULT):
            res = client.get(
                "/suggested_clusters?file=suggest_test.pcap", headers=admin_headers
            )
        assert res.status_code == 200
        data = res.get_json()
        assert "best_k" in data
        assert "modularity_scores" in data
        path = os.path.join(PCAP_GEN_OUTPUT_DIR, "suggest_test.pcap")
        if os.path.exists(path):
            os.remove(path)


# ── POST /save-results ────────────────────────────────────────────────────────


class TestSaveResults:
    def test_save_results_requires_auth(self, client):
        res = client.post("/save-results", json={"filename": "test"})
        assert res.status_code == 401

    def test_save_results_missing_filename_returns_400(self, client, admin_headers):
        res = client.post(
            "/save-results",
            data=json.dumps({"results": []}),
            headers=admin_headers,
        )
        assert res.status_code == 400

    def test_save_results_success(self, client, admin_headers, monkeypatch, tmp_path):
        # keep test_save.csv / .json out of the real server/cluster_analysis
        monkeypatch.setattr("app.CLUSTERING_OUTPUT_DIR", str(tmp_path))
        results = [
            {"ip": "1.2.3.4", "cluster": 0, "bytes_sent": 100},
            {"ip": "5.6.7.8", "cluster": 1, "bytes_sent": 200},
        ]
        res = client.post(
            "/save-results",
            data=json.dumps({"filename": "test_save", "results": results, "type": "json"}),
            headers=admin_headers,
        )
        assert res.status_code == 200
        data = res.get_json()
        assert "download_url" in data


# ── GET /clustering-output/<filename> ────────────────────────────────────────


class TestClusteringOutput:
    def test_clustering_output_requires_auth(self, client):
        res = client.get("/clustering-output/test.json")
        assert res.status_code == 401

    def test_clustering_output_not_found_returns_404(self, client, admin_headers):
        res = client.get("/clustering-output/nonexistent.json", headers=admin_headers)
        assert res.status_code == 404

    def test_clustering_output_wrong_owner_returns_403(self, client, app, admin_user, regular_user, user_headers):
        _make_cluster_result(app, admin_user["id"], filename="admin_cluster.json")
        res = client.get("/clustering-output/admin_cluster.json", headers=user_headers)
        assert res.status_code == 403
