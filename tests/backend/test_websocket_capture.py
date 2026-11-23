"""
Server-side capture from a sensor's packet stream (connectToWebsocket.py,
POST /start-analysis-from-websocket): per-run state, saving as /save-pcap
does, analysing as re-analyze does, and the status sent back.
"""
import base64
import json
import os
import shutil
import struct
import subprocess
from unittest.mock import patch

import pytest

import connectToWebsocket as cw
from conftest import FIXTURE_PCAP


def _frames(path):
    """Raw frames of a classic pcap, base64-encoded as publisher.py sends them."""
    data = open(path, "rb").read()
    endian = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    off, frames = 24, []
    while off + 16 <= len(data):
        incl = struct.unpack(endian + "I", data[off + 8:off + 12])[0]
        frames.append(base64.b64encode(data[off + 16:off + 16 + incl]).decode())
        off += 16 + incl
    return frames


FRAMES = _frames(FIXTURE_PCAP)


def _packet(b64):
    return json.dumps({"type": "PACKET_DATA", "packet": b64})


class _FakeSocket:
    connected = True


class _FakeWebSocket:
    def __init__(self):
        self.sock = _FakeSocket()
        self.sent = []
        self.closed = False

    def send(self, text):
        self.sent.append(json.loads(text))

    def close(self):
        self.closed = True


@pytest.fixture()
def out_dir(tmp_path, monkeypatch):
    import pcap_generator_service

    monkeypatch.setattr(pcap_generator_service, "PCAP_OUTPUT_DIR", str(tmp_path))
    return tmp_path


def _run(app, user_id=None):
    return cw.CaptureRun(app, "ws://sensor:5002", 1, user_id)


class TestCollecting:
    def test_only_valid_packet_messages_are_kept(self, app):
        run = _run(app)
        run.on_message(None, _packet(FRAMES[0]))
        run.on_message(None, json.dumps({"type": "STATUS", "status": "CAPTURE_STARTED"}))
        run.on_message(None, "not json")
        run.on_message(None, _packet("!!not base64!!"))
        run.on_message(None, _packet(base64.b64encode(b"ab").decode()))  # too short
        assert run.packets == [FRAMES[0]]

    def test_runs_do_not_share_state(self, app):
        first, second = _run(app), _run(app)
        first.on_message(None, _packet(FRAMES[0]))
        assert second.packets == []
        assert first.session_id != second.session_id

    def test_open_starts_the_capture(self, app):
        run = _run(app)
        run.ws = _FakeWebSocket()
        run.on_open(run.ws)
        assert run.ws.sent[0]["command"] == "START_CAPTURE"


class TestFinish:
    def test_no_packets_fails(self, app):
        status = _run(app).finish()
        assert status["status"] == "FAILED"
        assert status["message"] == "No packets were captured."

    def test_packets_are_saved_and_analysed(self, app, fresh_db, admin_user, out_dir):
        from models import PcapFile

        run = _run(app, admin_user["id"])
        for frame in FRAMES:
            run.on_message(None, _packet(frame))
        result = {"total_packets": len(FRAMES), "graph": {}, "roles": {"192.168.100.21": "AMF"}}
        with patch.object(cw, "run_core_analysis", return_value=result) as analyse:
            status = run.finish()

        assert status["type"] == "ANALYSIS_STATUS"
        assert status["status"] == "COMPLETE"
        assert status["roles"] == {"192.168.100.21": "AMF"}
        assert "warnings" not in status
        path = out_dir / status["filename"]
        assert analyse.call_args.args[0] == str(path)
        with app.app_context():
            record = PcapFile.query.filter_by(filename=status["filename"]).one()
            assert record.user_id == admin_user["id"]
            assert record.status == "COMPLETED"
            assert record.source == "generated"
            assert record.analysis_result == result
            assert record.file_size == os.path.getsize(path)

    @pytest.mark.skipif(shutil.which("tshark") is None, reason="needs tshark")
    def test_saved_pcap_holds_every_packet(self, app, fresh_db, admin_user, out_dir):
        run = _run(app, admin_user["id"])
        for frame in FRAMES:
            run.on_message(None, _packet(frame))
        with patch.object(cw, "run_core_analysis", return_value={"total_packets": 0, "graph": {}, "roles": {}}):
            status = run.finish()
        frames = subprocess.run(
            ["tshark", "-r", str(out_dir / status["filename"]), "-T", "fields", "-e", "frame.number"],
            capture_output=True, text=True,
        ).stdout.split()
        assert len(frames) == len(FRAMES) == 58

    def test_analysis_warnings_are_reported(self, app, fresh_db, admin_user, out_dir):
        run = _run(app, admin_user["id"])
        run.on_message(None, _packet(FRAMES[0]))
        result = {"total_packets": 1, "graph": {}, "roles": {}, "warnings": ["partial roles"]}
        with patch.object(cw, "run_core_analysis", return_value=result):
            status = run.finish()
        assert status["warnings"] == ["partial roles"]

    def test_failed_analysis_marks_the_pcap_error(self, app, fresh_db, admin_user, out_dir):
        from analysis_service import AnalysisFailed
        from models import PcapFile

        run = _run(app, admin_user["id"])
        run.on_message(None, _packet(FRAMES[0]))
        with patch.object(cw, "run_core_analysis", side_effect=AnalysisFailed("Role pipeline failed: boom")):
            status = run.finish()
        assert status["status"] == "FAILED"
        assert status["message"] == "Role pipeline failed: boom"
        with app.app_context():
            assert PcapFile.query.filter_by(filename=status["filename"]).one().status == "ERROR"


def test_run_stops_capture_reports_and_closes(app, monkeypatch):
    run = _run(app)
    run.ws = _FakeWebSocket()
    monkeypatch.setattr(cw.time, "sleep", lambda s: None)
    monkeypatch.setattr(run, "finish", lambda: {"type": "ANALYSIS_STATUS", "status": "COMPLETE"})
    run.run()
    assert [m.get("command") or m.get("status") for m in run.ws.sent] == ["STOP_CAPTURE", "COMPLETE"]
    assert run.ws.closed


def test_route_starts_a_capture_for_the_caller(client, admin_headers, admin_user):
    with patch("blueprints.analysis.startWebSocketClient", return_value=True) as start:
        res = client.post(
            "/start-analysis-from-websocket",
            data=json.dumps({"ws_url": "ws://sensor:5002", "seconds": 5}),
            headers=admin_headers,
        )
    assert res.status_code == 202
    args, kwargs = start.call_args
    assert args == ("ws://sensor:5002", 5)
    assert kwargs["user_id"] == admin_user["id"]
    assert kwargs["app"] is not None


def test_start_without_app_is_refused():
    assert cw.startWebSocketClient("ws://sensor:5002", 5) is False
