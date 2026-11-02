"""
Characterisation tests: record what each analysis module returns today for
real captures, so refactoring (see docs/architecture-review.html) can prove
it changed nothing.

These run the real libraries (Scapy, tshark, scikit-learn) and are marked
`integration`. Snapshots live in tests/backend/snapshots/.

    pytest -m integration                       # check
    pytest -m integration --update-snapshots    # re-record, then review the diff
"""

import os
import sys
from unittest.mock import MagicMock

import pytest

from snapshot_utils import SNAPSHOT_CAPTURES, scapy_version, tshark_version

_SERVER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "server"))
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)


def _real_scapy():
    try:
        from scapy.all import PcapReader
        return not isinstance(PcapReader, MagicMock)
    except Exception:
        return False


needs_scapy = pytest.mark.skipif(not _real_scapy(), reason="needs the real scapy package")
needs_tshark = pytest.mark.skipif(tshark_version() is None, reason="needs tshark on PATH")

pytestmark = [pytest.mark.integration, pytest.mark.parametrize("capture", SNAPSHOT_CAPTURES)]


def _stem(capture):
    return os.path.splitext(capture)[0]


class _ListQueue:
    """Stands in for multiprocessing.Queue when the worker runs in-process."""

    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)


# ── Scapy-based modules ──────────────────────────────────────────────────────


@needs_scapy
def test_traffic_graph_analysis(capture, capture_copy, snapshot):
    from graph_builder import build_graph_json
    from pcap_analysis import initialize_analysis

    result, err = initialize_analysis(capture_copy(capture))
    assert err is None
    snapshot.assert_match(
        f"analysis__{_stem(capture)}",
        {"result": result, "graph": build_graph_json(result["conversations"])},
        tools={"scapy": scapy_version()},
    )


@needs_tshark
def test_clustering_features(capture, capture_copy, snapshot):
    import agglomerative_clustering as ac

    rows = ac.extract_features(capture_copy(capture)).to_dict(orient="records")
    for row in rows:
        # built from a set, so its order changes between Python processes
        row["unique_partners_list"] = sorted(row["unique_partners_list"])
    snapshot.assert_match(
        f"clustering_features__{_stem(capture)}", rows, tools={"tshark": tshark_version()}
    )


@needs_tshark
@pytest.mark.parametrize("max_clusters, anomaly_threshold", [(4, 2), (10, 2)])
def test_clustering_result(capture, max_clusters, anomaly_threshold, capture_copy, snapshot, monkeypatch):
    import agglomerative_clustering as ac

    monkeypatch.setattr(ac, "save_results", lambda df, name, folder=None: (None, None))
    result = ac.analyze_pcap_for_clustering(
        capture_copy(capture), max_clusters=max_clusters, anomaly_threshold=anomaly_threshold
    )
    snapshot.assert_match(
        f"clustering_result__{_stem(capture)}__k{max_clusters}_t{anomaly_threshold}",
        result,
        tools={"tshark": tshark_version()},
    )


# ── tshark-based modules ─────────────────────────────────────────────────────


@needs_scapy
@needs_tshark
def test_tshark_traffic_summary_matches_scapy(capture, capture_copy):
    """Uploads use summarize_traffic; /analyze-saved-pcap still uses Scapy."""
    from pcap_analysis import initialize_analysis, summarize_traffic

    path = capture_copy(capture)
    scapy_result, _ = initialize_analysis(path)
    table_result, err = summarize_traffic(path)
    assert err is None
    assert table_result["total_packets"] == scapy_result["total_packets"]
    assert table_result["conversations"] == scapy_result["conversations"]


@needs_tshark
def test_role_engine_assessment(capture, capture_copy, snapshot):
    from role_engine import assess_pcap

    assessments = assess_pcap(capture_copy(capture))
    snapshot.assert_match(
        f"roles__{_stem(capture)}",
        {ip: vars(a) for ip, a in assessments.items()},
        tools={"tshark": tshark_version()},
    )


@needs_tshark
def test_feature_records(capture, capture_copy, snapshot):
    from rrc_utils import FEATURE_CACHE_SUFFIX, get_cached_packets

    path = capture_copy(capture)
    first = get_cached_packets(path)
    assert os.path.exists(path + FEATURE_CACHE_SUFFIX)
    assert get_cached_packets(path) == first  # cached read gives the same records
    snapshot.assert_match(
        f"feature_records__{_stem(capture)}", first, tools={"tshark": tshark_version()}
    )


@needs_tshark
def test_privacy_records(capture, capture_copy, snapshot):
    from privacy_records import records_from_pcap

    records = records_from_pcap(capture_copy(capture))
    snapshot.assert_match(
        f"privacy_records__{_stem(capture)}", records, tools={"tshark": tshark_version()}
    )


@needs_tshark
def test_ue_analysis(capture, capture_copy, snapshot):
    """pyshark UE extraction. sample.pcap frame 9 is a Registration Request
    with a null-scheme SUCI (IMSI 999700000000001); later NAS messages are
    ciphered. ppc_5g_and_oran.pcap carries no UE identities."""
    from ueAnalysis import initialize_analysis_for_ue

    records = initialize_analysis_for_ue(capture_copy(capture))
    snapshot.assert_match(f"ue_sessions__{_stem(capture)}", records, tools={"tshark": tshark_version()})


@needs_tshark
def test_role_pipeline_worker(capture, capture_copy, snapshot, app, fresh_db, tmp_path, monkeypatch):
    """The worker that /run_pipeline and /automated-analysis start in a child
    process, run in-process so the test sees exactly what it returns."""
    import settings
    from Preprocess import _pipeline_worker

    pcap = capture_copy(capture)
    results_dir = tmp_path / "results"
    monkeypatch.setattr(settings, "RESULTS_OUTPUT_DIR", str(results_dir))
    queue = _ListQueue()
    _pipeline_worker(pcap, "rule_based", queue)

    assert len(queue.items) == 1
    report = queue.items[0]
    assert report["status"] == "success", report
    report.pop("processing_time")  # wall-clock time

    # The role summary that /save_roles serves, in both formats
    assert (results_dir / f"{_stem(capture)}.json").exists()
    assert (results_dir / f"{_stem(capture)}.csv").exists()

    snapshot.assert_match(
        f"role_pipeline__{_stem(capture)}", report, tools={"tshark": tshark_version()}
    )
