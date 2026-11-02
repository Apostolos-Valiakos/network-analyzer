"""
Route-level characterisation tests: record the JSON each main endpoint
returns today for a real capture, so refactoring the web layer (shared
helpers, blueprints, app factory) can prove responses did not change.

The role pipeline normally runs in a child process; here it runs in-process
(same worker function) so the test database and patches apply to it.

    pytest -m integration                       # check
    pytest -m integration --update-snapshots    # re-record, then review the diff
"""

import io
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from snapshot_utils import FIXTURE_DIR, SNAPSHOT_CAPTURES, scapy_version, tshark_version

_SERVER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "server"))
if _SERVER_DIR not in sys.path:
    sys.path.insert(0, _SERVER_DIR)

from models import db as _db
from settings import PCAP_GEN_OUTPUT_DIR
from models import FlowStatistic, PcapFile, RoleSnapshot
from packet_table import CACHE_SUFFIX as PACKET_CACHE_SUFFIX


def _real_scapy():
    try:
        from scapy.all import PcapReader
        return not isinstance(PcapReader, MagicMock)
    except Exception:
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _real_scapy(), reason="needs the real scapy package"),
    pytest.mark.skipif(tshark_version() is None, reason="needs tshark on PATH"),
]

_UPLOAD_PREFIX = re.compile(r"\d{14}_")


def _tools():
    return {"scapy": scapy_version(), "tshark": tshark_version()}


def _stem(capture):
    return os.path.splitext(capture)[0]


class _ListQueue:
    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)


@pytest.fixture()
def pipeline_in_process(monkeypatch, tmp_path):
    """Runs the role-pipeline worker in this process instead of a child."""
    from Preprocess import _pipeline_worker

    def run(pcap_file_path, model_name, selected_ips=None):
        queue = _ListQueue()
        _pipeline_worker(pcap_file_path, model_name, queue, selected_ips)
        return queue.items[0]

    monkeypatch.setattr("blueprints.analysis.run_ip_role_pipeline", run)
    monkeypatch.setattr("analysis_service.run_ip_role_pipeline", run)
    # the worker writes the role summary into settings.RESULTS_OUTPUT_DIR
    monkeypatch.setattr("settings.RESULTS_OUTPUT_DIR", str(tmp_path))


@pytest.fixture()
def no_cluster_files(monkeypatch):
    import agglomerative_clustering as ac

    monkeypatch.setattr(ac, "save_results", lambda df, name, folder=None: (None, None))


@pytest.fixture(params=SNAPSHOT_CAPTURES)
def registered_capture(request, app, fresh_db, admin_user):
    """A fixture capture copied into generated_pcaps with a pcap_files row."""
    capture = request.param
    filename = f"snapshot_{capture}"
    dest = os.path.join(PCAP_GEN_OUTPUT_DIR, filename)
    shutil.copy2(os.path.join(FIXTURE_DIR, capture), dest)
    with app.app_context():
        record = PcapFile(
            filename=filename,
            original_filename=capture,
            file_path=dest,
            file_size=os.path.getsize(dest),
            status="COMPLETED",
            source="upload",
            user_id=admin_user["id"],
        )
        _db.session.add(record)
        _db.session.commit()
        pcap_id = record.id

    yield {"capture": capture, "stem": _stem(capture), "filename": filename, "id": pcap_id}

    for path in (dest, dest + PACKET_CACHE_SUFFIX):
        if os.path.exists(path):
            os.remove(path)


def _json(res, status=200):
    assert res.status_code == status, res.get_data(as_text=True)[:500]
    return res.get_json()


# ── Analysis routes ──────────────────────────────────────────────────────────


def test_analyze_saved_pcap(client, admin_headers, registered_capture, snapshot):
    body = _json(client.get(f"/analyze-saved-pcap/{registered_capture['filename']}", headers=admin_headers))
    snapshot.assert_match(f"route_analyze_saved_pcap__{registered_capture['stem']}", body, tools=_tools())


def test_suggested_clusters(client, admin_headers, registered_capture, no_cluster_files, snapshot):
    body = _json(client.get(f"/suggested_clusters?file={registered_capture['filename']}", headers=admin_headers))
    snapshot.assert_match(f"route_suggested_clusters__{registered_capture['stem']}", body, tools=_tools())


def test_clustering(client, admin_headers, registered_capture, no_cluster_files, snapshot):
    payload = {"file": registered_capture["filename"], "clusters": 4, "anomaly_threshold": 2}
    body = _json(client.post("/clustering", json=payload, headers=admin_headers))
    snapshot.assert_match(f"route_clustering__{registered_capture['stem']}", body, tools=_tools())


def test_run_pipeline(client, admin_headers, registered_capture, pipeline_in_process, snapshot):
    payload = {"pcap_file_path": registered_capture["filename"], "model_name": "rule_based"}
    body = _json(client.post("/run_pipeline", json=payload, headers=admin_headers))
    body.pop("processing_time")
    snapshot.assert_match(f"route_run_pipeline__{registered_capture['stem']}", body, tools=_tools())


def test_save_roles_downloads_json_and_csv(client, admin_headers, registered_capture,
                                           pipeline_in_process, snapshot):
    """The upload response links to /save_roles?file=<name without .pcap>&type=json|csv."""
    payload = {"pcap_file_path": registered_capture["filename"], "model_name": "rule_based"}
    _json(client.post("/run_pipeline", json=payload, headers=admin_headers))

    base = registered_capture["filename"][:-5]
    as_json = client.get(f"/save_roles?file={base}&type=json", headers=admin_headers)
    as_csv = client.get(f"/save_roles?file={base}&type=csv", headers=admin_headers)
    assert as_json.status_code == 200
    assert as_csv.status_code == 200

    summary = json.loads(as_json.get_data(as_text=True))
    csv_text = as_csv.get_data(as_text=True).replace("\r\n", "\n")
    # Same rows in both formats
    assert csv_text.splitlines()[1:] == [
        f"{r['class_name']},{r['count']},{';'.join(r['ips'])}" for r in summary
    ]
    snapshot.assert_match(
        f"route_save_roles__{registered_capture['stem']}",
        {"json": summary, "csv": csv_text},
        tools=_tools(),
    )


def test_reanalyze(client, admin_headers, registered_capture, pipeline_in_process, snapshot):
    res = client.post(f"/v1/history/pcap/{registered_capture['id']}/reanalyze", headers=admin_headers)
    body = _json(res)
    stored = _json(client.get(f"/v1/history/pcap/{registered_capture['id']}/result", headers=admin_headers))
    assert stored == body  # what the route returns is what it stored
    snapshot.assert_match(f"route_reanalyze__{registered_capture['stem']}", body, tools=_tools())


def test_automated_analysis_upload(client, admin_headers, app, admin_user, pipeline_in_process, snapshot):
    """Upload flow, run once per capture (not through registered_capture,
    because the route creates its own file and database row)."""
    headers = {"Authorization": admin_headers["Authorization"]}
    for capture in SNAPSHOT_CAPTURES:
        with open(os.path.join(FIXTURE_DIR, capture), "rb") as f:
            data = {"file": (io.BytesIO(f.read()), capture), "model_name": "rule_based"}
        res = client.post("/automated-analysis", data=data, headers=headers,
                          content_type="multipart/form-data")
        body = _json(res)

        saved_name = body["filename"]
        try:
            assert _UPLOAD_PREFIX.match(saved_name)
            with app.app_context():
                record = PcapFile.query.filter_by(filename=saved_name).one()
                assert record.status == "COMPLETED"
                assert record.analysis_result["roles"] == body["roles"]
        finally:
            for path in (os.path.join(PCAP_GEN_OUTPUT_DIR, saved_name),
                         os.path.join(PCAP_GEN_OUTPUT_DIR, saved_name) + PACKET_CACHE_SUFFIX):
                if os.path.exists(path):
                    os.remove(path)

        # The saved name starts with the upload time; replace it with a marker.
        body = json.loads(_UPLOAD_PREFIX.sub("<timestamp>_", json.dumps(body)))
        snapshot.assert_match(f"route_automated_analysis__{_stem(capture)}", body, tools=_tools())


# ── Privacy routes ───────────────────────────────────────────────────────────


def test_privacy_records_and_metrics(client, admin_headers, registered_capture, snapshot):
    records_body = _json(client.get(f"/privacy-records/{registered_capture['filename']}", headers=admin_headers))
    snapshot.assert_match(f"route_privacy_records__{registered_capture['stem']}", records_body, tools=_tools())

    payload = {
        "records": records_body["records"],
        "identifiers": ["role", "scope", "service_port"],
        "sensitive_attribute": "protocols",
        "transformations": {
            "pseudonymize": ["ip", "mac"],
            "pseudonymization_mode": "deterministic",
            "pseudonymization_technique": "hmac_sha256",
            "generalize": ["subnet"],
            "suppress": ["mac_vendor"],
            "record_suppression_k": 0,
        },
    }
    metrics_body = _json(client.post("/privacy-metrics", json=payload, headers=admin_headers))
    snapshot.assert_match(f"route_privacy_metrics__{registered_capture['stem']}", metrics_body, tools=_tools())


# ── Live-monitoring routes (database only, no capture) ───────────────────────

_FLOWS = [
    # (ts, uid, src, dst, proto, state, orig_bytes, resp_bytes, orig_pkts, resp_pkts)
    (datetime(2026, 10, 22, 9, 0, 0), "C1", "10.0.0.1", "10.0.0.2", "tcp", "SF", 1200, 800, 10, 8),
    (datetime(2026, 10, 22, 9, 0, 5), "C2", "10.0.0.3", "10.0.0.2", "udp", "S0", 90, 0, 1, 0),
    (datetime(2026, 10, 22, 9, 1, 0), "C3", "10.0.0.1", "10.0.0.4", "tcp", "REJ", 60, 40, 1, 1),
]


def _seed_monitoring(app):
    with app.app_context():
        for ts, uid, src, dst, proto, state, ob, rb, op, rp in _FLOWS:
            _db.session.add(FlowStatistic(
                ts=ts, uid=uid, id_orig_h=src, id_resp_h=dst, proto=proto, conn_state=state,
                orig_bytes=ob, resp_bytes=rb, orig_pkts=op, resp_pkts=rp,
            ))
        for ip, role, conf in [("10.0.0.2", "AMF", 0.9), ("10.0.0.1", "gNB", 0.8)]:
            _db.session.add(RoleSnapshot(ts=1792659700.0, ip_address=ip, role=role,
                                         confidence=conf, reasoning="seeded"))
        _db.session.commit()


def _window():
    # Wide fixed window around the seeded flows, as epoch seconds.
    start = datetime(2026, 10, 22, 0, 0, 0)
    end = datetime(2026, 10, 23, 0, 0, 0)
    epoch = datetime(1970, 1, 1)
    return f"start_time={(start - epoch).total_seconds()}&end_time={(end - epoch).total_seconds()}"


def test_network_statistics_and_export(client, admin_headers, app, snapshot):
    _seed_monitoring(app)
    window = _window()
    stats = _json(client.get(f"/v1/network/statistics?format=json&{window}", headers=admin_headers))
    export_json = client.get(f"/v1/network/export?format=json&{window}", headers=admin_headers)
    export_csv = client.get(f"/v1/network/export?format=csv&{window}", headers=admin_headers)
    roles = _json(client.get("/v1/network/roles/latest?format=json", headers=admin_headers))

    assert export_json.status_code == 200 and export_csv.status_code == 200
    # "ts" is the real epoch of the stored UTC time, whatever the server's time zone.
    expected_ts = sorted(
        (ts.replace(tzinfo=timezone.utc).timestamp() for ts, *_ in _FLOWS), reverse=True
    )
    assert [row["ts"] for row in stats] == expected_ts
    assert [row["ts"] for row in export_json.get_json(force=True)] == expected_ts
    snapshot.assert_match("route_network_monitoring", {
        "statistics": stats,
        "export_json": export_json.get_json(force=True),
        "export_json_disposition": export_json.headers.get("Content-Disposition"),
        "export_csv": export_csv.get_data(as_text=True).replace("\r\n", "\n"),
        "export_csv_type": export_csv.content_type,
        "roles_latest": roles,
    })
