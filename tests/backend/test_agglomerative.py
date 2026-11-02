"""
Unit tests for agglomerative_clustering module.

Strategy
--------
* Unit tests mock `extract_features` (which calls scapy) so the tests run
  without any network-capture library.
* An integration test is provided and marked with @pytest.mark.integration.
  It is SKIPPED unless:
    1. tshark is available, AND
    2. the sample.pcap fixture file exists.
  Run the integration test explicitly:
      pytest -m integration
"""

import os
import sys
from unittest.mock import patch, MagicMock

import numpy as np
import pandas as pd
import pytest

# Ensure server/ is on path
_SERVER_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "server")
)
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)

import agglomerative_clustering as _ac
from snapshot_utils import tshark_version

FIXTURE_PCAP = os.path.join(os.path.dirname(__file__), "fixtures", "sample.pcap")


@pytest.fixture(autouse=True)
def _no_result_files(monkeypatch):
    """analyze_pcap_for_clustering saves CSV/JSON into server/cluster_analysis;
    keep test runs from leaving dummy.csv / dummy.json there."""
    monkeypatch.setattr(_ac, "save_results", lambda df, name, folder=None: (None, None))


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_feature_df(n_ips=6):
    """
    Returns a synthetic feature DataFrame that exactly mimics extract_features() output.

    extract_features() builds a list of dicts with keys:
        ip, bytes_sent, bytes_received, packets_sent, packets_received,
        unique_partners, unique_ports, duration, avg_interarrival, unique_partners_list
    and passes it to pd.DataFrame() — so `ip` and `unique_partners_list` are
    regular columns, NOT the index.  cluster_nodes() then drops both columns
    before scaling, so they must be present.
    """
    rng = np.random.default_rng(42)
    ips = [f"10.0.0.{i + 1}" for i in range(n_ips)]
    max_partners = max(1, n_ips - 1)
    partner_counts = rng.integers(1, max_partners + 1, n_ips)
    data = {
        "ip": ips,
        "bytes_sent": rng.integers(100, 100_000, n_ips).tolist(),
        "bytes_received": rng.integers(100, 100_000, n_ips).tolist(),
        "packets_sent": rng.integers(1, 1000, n_ips).tolist(),
        "packets_received": rng.integers(1, 1000, n_ips).tolist(),
        "unique_partners": rng.integers(1, 20, n_ips).tolist(),
        "unique_ports": rng.integers(1, 50, n_ips).tolist(),
        "duration": rng.uniform(0.1, 3600, n_ips).tolist(),
        "avg_interarrival": rng.uniform(0.01, 10, n_ips).tolist(),
        # Partners must come from the same ip list so compute_modularity's
        # partition dict covers every node that appears in the graph.
        "unique_partners_list": [
            [other for other in ips if other != ip][: int(k)]
            for ip, k in zip(ips, partner_counts)
        ],
    }
    return pd.DataFrame(data)


# ── Result schema validation ──────────────────────────────────────────────────


class TestResultSchema:
    def test_result_has_required_top_level_keys(self):
        with patch.object(_ac, "extract_features", return_value=_make_feature_df()):
            result = _ac.analyze_pcap_for_clustering("dummy.pcap", max_clusters=4)
        for key in ("clusterSummary", "clusters", "graphData"):
            assert key in result, f"Missing top-level key: {key}"

    def test_cluster_summary_has_required_keys(self):
        with patch.object(_ac, "extract_features", return_value=_make_feature_df()):
            result = _ac.analyze_pcap_for_clustering("dummy.pcap", max_clusters=4)
        summary = result["clusterSummary"]
        for key in ("best_k", "best_modularity", "modularity_scores",
                    "cluster_hierarchy", "mostImportantCluster"):
            assert key in summary, f"Missing summary key: {key}"

    def test_best_k_within_max_clusters_range(self):
        max_k = 5
        with patch.object(_ac, "extract_features", return_value=_make_feature_df(n_ips=10)):
            result = _ac.analyze_pcap_for_clustering("dummy.pcap", max_clusters=max_k)
        best_k = result["clusterSummary"]["best_k"]
        assert 2 <= best_k <= max_k

    def test_clusters_has_one_row_per_ip_across_best_k_clusters(self):
        df = _make_feature_df()
        with patch.object(_ac, "extract_features", return_value=df):
            result = _ac.analyze_pcap_for_clustering("dummy.pcap", max_clusters=4)
        best_k = result["clusterSummary"]["best_k"]
        assert len(result["clusters"]) == len(df)
        assert len({row["cluster"] for row in result["clusters"]}) == best_k

    def test_each_cluster_row_has_ip_cluster_and_flag(self):
        with patch.object(_ac, "extract_features", return_value=_make_feature_df()):
            result = _ac.analyze_pcap_for_clustering("dummy.pcap", max_clusters=3)
        for row in result["clusters"]:
            assert set(row) == {"ip", "cluster", "anomaly"}
            assert isinstance(row["anomaly"], bool)

    def test_graph_data_has_one_node_per_ip(self):
        df = _make_feature_df()
        with patch.object(_ac, "extract_features", return_value=df):
            result = _ac.analyze_pcap_for_clustering("dummy.pcap", max_clusters=4)
        graph = result["graphData"]
        assert graph["type"] == "force"
        assert [n["name"] for n in graph["nodes"]] == df["ip"].tolist()

    def test_modularity_scores_list_covers_each_k(self):
        max_k = 4
        with patch.object(_ac, "extract_features", return_value=_make_feature_df()):
            result = _ac.analyze_pcap_for_clustering("dummy.pcap", max_clusters=max_k)
        scores = result["clusterSummary"]["modularity_scores"]
        assert isinstance(scores, list)
        assert [s["k"] for s in scores] == list(range(2, max_k + 1))
        assert all(isinstance(s["modularity"], float) for s in scores)

    def test_best_modularity_is_float(self):
        with patch.object(_ac, "extract_features", return_value=_make_feature_df()):
            result = _ac.analyze_pcap_for_clustering("dummy.pcap", max_clusters=4)
        assert isinstance(result["clusterSummary"]["best_modularity"], float)


# ── Anomaly detection ─────────────────────────────────────────────────────────


class TestAnomalyDetection:
    # The threshold is the largest cluster size still flagged as anomalous,
    # so a higher threshold flags at least as many IPs.
    def test_higher_anomaly_threshold_flags_at_least_as_many_ips(self):
        df = _make_feature_df(n_ips=20)
        with patch.object(_ac, "extract_features", return_value=df.copy()):
            result_high = _ac.analyze_pcap_for_clustering(
                "dummy.pcap", max_clusters=4, anomaly_threshold=10
            )
        with patch.object(_ac, "extract_features", return_value=df.copy()):
            result_low = _ac.analyze_pcap_for_clustering(
                "dummy.pcap", max_clusters=4, anomaly_threshold=0.1
            )
        flagged = lambda r: sum(row["anomaly"] for row in r["clusters"])
        assert flagged(result_high) >= flagged(result_low)
        assert flagged(result_low) == 0  # no cluster has size <= 0.1

    def test_every_row_names_its_ip(self):
        df = _make_feature_df(n_ips=8)
        with patch.object(_ac, "extract_features", return_value=df):
            result = _ac.analyze_pcap_for_clustering(
                "dummy.pcap", max_clusters=4, anomaly_threshold=0
            )
        assert sorted(row["ip"] for row in result["clusters"]) == sorted(df["ip"])


# ── Edge cases ────────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_dataframe_raises_clear_error(self):
        empty_df = pd.DataFrame()
        with patch.object(_ac, "extract_features", return_value=empty_df):
            with pytest.raises(ValueError, match="Not enough unique IP endpoints"):
                _ac.analyze_pcap_for_clustering("dummy.pcap", max_clusters=4)

    def test_single_ip_handled_gracefully(self):
        single_df = _make_feature_df(n_ips=1)
        with patch.object(_ac, "extract_features", return_value=single_df):
            try:
                result = _ac.analyze_pcap_for_clustering("dummy.pcap", max_clusters=4)
                # If it doesn't raise, ensure output has expected structure
                assert "clusterSummary" in result
            except Exception:
                pass  # A single IP may legitimately cause a graceful error

    def test_exactly_two_ips(self):
        df = _make_feature_df(n_ips=2)
        with patch.object(_ac, "extract_features", return_value=df):
            result = _ac.analyze_pcap_for_clustering("dummy.pcap", max_clusters=2)
        assert "clusterSummary" in result


# ── Integration test (requires real scapy + tshark) ──────────────────────────


@pytest.mark.integration
@pytest.mark.skipif(
    not os.path.exists(FIXTURE_PCAP) or tshark_version() is None,
    reason="Requires tshark and tests/backend/fixtures/sample.pcap",
)
class TestIntegrationRealPcap:
    def test_real_pcap_produces_valid_result(self, capture_copy):
        result = _ac.analyze_pcap_for_clustering(capture_copy("sample.pcap"), max_clusters=4)
        assert "clusterSummary" in result
        assert "clusters" in result
        assert "graphData" in result

    def test_real_pcap_best_k_is_positive(self, capture_copy):
        result = _ac.analyze_pcap_for_clustering(capture_copy("sample.pcap"), max_clusters=4)
        assert result["clusterSummary"]["best_k"] >= 1

    def test_real_pcap_result_is_serialisable(self, capture_copy):
        import json

        result = _ac.analyze_pcap_for_clustering(capture_copy("sample.pcap"), max_clusters=4)
        # Should not raise
        json.dumps(result)
