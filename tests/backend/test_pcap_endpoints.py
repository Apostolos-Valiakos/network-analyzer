"""
Unit tests for PCAP management endpoints:
  POST /save-pcap
  GET  /generated_pcaps/<filename>
  POST /automated-analysis
"""

import base64
import json
import os
import struct
import tempfile
from io import BytesIO

import pytest
from models import db as _db
from settings import PCAP_GEN_OUTPUT_DIR
from models import PcapFile


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_pcap_record(app, user_id, filename="test.pcap", source="generated",
                      file_path=None, status="COMPLETED"):
    file_path = file_path or os.path.join(PCAP_GEN_OUTPUT_DIR, filename)
    with app.app_context():
        record = PcapFile(
            filename=filename,
            original_filename=filename,
            file_path=file_path,
            file_size=0,
            status=status,
            source=source,
            user_id=user_id,
        )
        _db.session.add(record)
        _db.session.commit()
        _db.session.refresh(record)
        return {"id": record.id, "filename": record.filename}


def _minimal_pcap_bytes():
    """Returns a valid minimal PCAP binary (global header + no packets)."""
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


# ── POST /save-pcap ──────────────────────────────────────────────────────────


class TestSavePcap:
    def test_save_pcap_requires_auth(self, client):
        res = client.post("/save-pcap", json={"session_id": "s1", "packets": []})
        assert res.status_code == 401

    def test_save_pcap_missing_session_id_returns_400(self, client, admin_headers):
        res = client.post(
            "/save-pcap",
            data=json.dumps({"packets": []}),
            headers=admin_headers,
        )
        assert res.status_code == 400

    def test_save_pcap_packets_not_list_returns_400(self, client, admin_headers):
        res = client.post(
            "/save-pcap",
            data=json.dumps({"session_id": "s1", "packets": "not-a-list"}),
            headers=admin_headers,
        )
        assert res.status_code == 400

    def test_save_pcap_not_json_returns_400(self, client, admin_headers):
        res = client.post(
            "/save-pcap",
            data="not json",
            headers={
                "Authorization": admin_headers["Authorization"],
                "Content-Type": "text/plain",
            },
        )
        assert res.status_code == 400

    def test_save_pcap_empty_chunk_creates_file(self, client, admin_headers):
        res = client.post(
            "/save-pcap",
            data=json.dumps({"session_id": "test_session_001", "packets": [], "is_final_chunk": False}),
            headers=admin_headers,
        )
        assert res.status_code == 200
        assert res.get_json()["success"] is True

    def test_save_pcap_with_valid_packets(self, client, admin_headers):
        pkt_bytes = b"\x00" * 60
        b64_pkt = base64.b64encode(pkt_bytes).decode()
        res = client.post(
            "/save-pcap",
            data=json.dumps({
                "session_id": "test_session_002",
                "packets": [b64_pkt],
                "is_final_chunk": False,
            }),
            headers=admin_headers,
        )
        assert res.status_code == 200
        assert res.get_json()["success"] is True

    def test_save_pcap_final_chunk_returns_filename(self, client, admin_headers):
        b64_pkt = base64.b64encode(b"\x00" * 14).decode()
        res = client.post(
            "/save-pcap",
            data=json.dumps({
                "session_id": "test_final_session",
                "packets": [b64_pkt],
                "is_final_chunk": True,
            }),
            headers=admin_headers,
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["filename"] is not None
        assert data["filename"].endswith(".pcap")

    def test_save_pcap_cleanup(self, app, admin_user):
        """Clean up the generated PCAP files created by the tests above."""
        for session_id in ("test_session_001", "test_session_002", "test_final_session"):
            path = os.path.join(PCAP_GEN_OUTPUT_DIR, f"{session_id}.pcap")
            if os.path.exists(path):
                os.remove(path)


# ── GET /generated_pcaps/<filename> ──────────────────────────────────────────


class TestGetGeneratedPcap:
    def test_get_pcap_requires_auth(self, client):
        res = client.get("/generated_pcaps/some_file.pcap")
        assert res.status_code == 401

    def test_get_pcap_not_in_db_returns_404(self, client, admin_headers):
        res = client.get("/generated_pcaps/nonexistent.pcap", headers=admin_headers)
        assert res.status_code == 404

    def test_get_pcap_wrong_owner_returns_403(self, client, app, admin_user, regular_user, user_headers):
        _make_pcap_record(app, admin_user["id"], filename="owned_by_admin.pcap")
        res = client.get("/generated_pcaps/owned_by_admin.pcap", headers=user_headers)
        assert res.status_code == 403

    def test_get_pcap_file_missing_on_disk_returns_404(self, client, app, admin_headers, admin_user):
        _make_pcap_record(
            app, admin_user["id"],
            filename="in_db_not_on_disk.pcap",
            file_path=os.path.join(PCAP_GEN_OUTPUT_DIR, "in_db_not_on_disk.pcap"),
        )
        res = client.get("/generated_pcaps/in_db_not_on_disk.pcap", headers=admin_headers)
        assert res.status_code == 404

    def test_get_pcap_success(self, client, admin_headers, pcap_in_db):
        res = client.get(
            f"/generated_pcaps/{pcap_in_db['filename']}",
            headers=admin_headers,
        )
        assert res.status_code == 200
        assert res.content_type in (
            "application/octet-stream",
            "application/vnd.tcpdump.pcap",
        )


# ── POST /automated-analysis ──────────────────────────────────────────────────


class TestAutomatedAnalysis:
    def test_automated_analysis_requires_auth(self, client):
        res = client.post("/automated-analysis")
        assert res.status_code == 401

    def test_automated_analysis_missing_file_part(self, client, admin_headers):
        res = client.post(
            "/automated-analysis",
            headers={"Authorization": admin_headers["Authorization"]},
            data={},
            content_type="multipart/form-data",
        )
        assert res.status_code == 400

    def test_automated_analysis_wrong_extension(self, client, admin_headers):
        res = client.post(
            "/automated-analysis",
            headers={"Authorization": admin_headers["Authorization"]},
            data={"file": (BytesIO(b"data"), "test.txt")},
            content_type="multipart/form-data",
        )
        assert res.status_code == 400
        assert "pcap" in res.get_json()["error"].lower()

    def test_automated_analysis_no_selected_file(self, client, admin_headers):
        from io import BytesIO

        res = client.post(
            "/automated-analysis",
            headers={"Authorization": admin_headers["Authorization"]},
            data={"file": (BytesIO(b""), "")},
            content_type="multipart/form-data",
        )
        assert res.status_code == 400
