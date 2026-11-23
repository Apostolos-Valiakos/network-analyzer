"""
Server-side capture from a sensor's live packet stream (publisher.py, the
WebSocket the Real Time page also uses), started by
POST /start-analysis-from-websocket.

Each request starts one CaptureRun with its own packets, session and
WebSocket, so runs never share state. A run:
  1. connects and sends START_CAPTURE, collecting PACKET_DATA messages;
  2. after the requested number of seconds sends STOP_CAPTURE;
  3. writes the packets as a pcap and a pcap_files row owned by the requesting
     user, as /save-pcap does (in-process, no HTTP call back to this server);
  4. analyses it as History's re-analyze does (traffic graph + roles) and
     stores the result;
  5. reports ANALYSIS_STATUS (COMPLETE or FAILED) on the WebSocket, then closes.
"""
import base64
import json
import logging
import os
import threading
import time
import uuid

import websocket

import pcap_generator_service
from analysis_service import AnalysisFailed, mark_pcap_error, run_core_analysis
from models import db, PcapFile
from pcap_repair import trim_incomplete_tail

logger = logging.getLogger(__name__)

CHUNK_SIZE = 1000  # packets written per append, as the browser sends them


class CaptureRun:
    """One capture: its own packet list, session id and WebSocket."""

    def __init__(self, app, ws_url: str, duration: int, user_id):
        self.app = app
        self.ws_url = ws_url
        self.duration = duration
        self.user_id = user_id
        self.session_id = f"pcap_{uuid.uuid4().hex}"
        self.packets = []
        self._lock = threading.Lock()
        self.ws = None

    # ── WebSocket callbacks ──────────────────────────────────────────────────

    def on_open(self, ws):
        logger.info("Capture %s connected to %s", self.session_id, self.ws_url)
        self.send_command("START_CAPTURE")

    def on_message(self, ws, message):
        try:
            msg = json.loads(message)
        except (json.JSONDecodeError, TypeError):
            return
        if msg.get("type") != "PACKET_DATA" or not isinstance(msg.get("packet"), str):
            return
        try:
            if len(base64.b64decode(msg["packet"])) < 4:
                return
        except ValueError:
            logger.warning("Capture %s: skipping a packet that is not valid base64", self.session_id)
            return
        with self._lock:
            self.packets.append(msg["packet"])

    def on_error(self, ws, error):
        logger.warning("Capture %s: WebSocket error: %s", self.session_id, error)

    def on_close(self, ws, status_code, message):
        logger.info("Capture %s: WebSocket closed (%s %s)", self.session_id, status_code, message)

    def send_command(self, command: str) -> None:
        self._send({"command": command, "timestamp": int(time.time() * 1000)})

    def _send(self, payload: dict) -> None:
        if self.ws is not None and self.ws.sock and self.ws.sock.connected:
            self.ws.send(json.dumps(payload))

    # ── The run ──────────────────────────────────────────────────────────────

    def start(self) -> None:
        self.ws = websocket.WebSocketApp(
            self.ws_url,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
        )
        threading.Thread(target=self.ws.run_forever, daemon=True).start()
        threading.Thread(target=self.run, daemon=True).start()

    def run(self) -> None:
        time.sleep(self.duration)
        self.send_command("STOP_CAPTURE")
        time.sleep(0.5)  # packets already in flight
        try:
            self._send(self.finish())
        finally:
            if self.ws is not None:
                self.ws.close()

    def finish(self) -> dict:
        """Saves and analyses the captured packets; returns the notification."""
        with self._lock:
            packets = list(self.packets)
        if not packets:
            logger.warning("Capture %s: no packets received", self.session_id)
            return _status("FAILED", "No packets were captured.")

        with self.app.app_context():
            try:
                record = self._save(packets)
            except Exception as exc:
                logger.exception("Capture %s: saving the pcap failed", self.session_id)
                db.session.rollback()
                return _status("FAILED", f"PCAP generation failed: {exc}")

            try:
                result = run_core_analysis(record.file_path, "rule_based", "Role pipeline")
                record.analysis_result = result
                record.status = "COMPLETED"
                db.session.commit()
            except Exception as exc:
                db.session.rollback()
                mark_pcap_error(record.id)
                if isinstance(exc, AnalysisFailed):
                    logger.error("Capture %s: %s", self.session_id, exc)
                    message = str(exc)
                else:
                    logger.exception("Capture %s: analysis failed", self.session_id)
                    message = "Analysis failed"
                return _status("FAILED", message, filename=record.filename)

            notification = _status(
                "COMPLETE",
                f"Analysis complete for {record.filename}.",
                filename=record.filename,
                total_packets=result["total_packets"],
                roles=result["roles"],
            )
            if result.get("warnings"):
                notification["warnings"] = result["warnings"]
            return notification

    def _save(self, packets) -> PcapFile:
        """Writes the pcap and its pcap_files row, as /save-pcap does."""
        filename = None
        for start in range(0, len(packets), CHUNK_SIZE):
            chunk = packets[start:start + CHUNK_SIZE]
            ok, filename, error = pcap_generator_service.handle_pcap_chunk(self.session_id, chunk)
            if not ok:
                raise RuntimeError(error)
        file_path = os.path.join(pcap_generator_service.PCAP_OUTPUT_DIR, filename)
        trim_incomplete_tail(file_path)
        record = PcapFile(
            filename=filename,
            original_filename=self.session_id,
            file_path=file_path,
            file_size=os.path.getsize(file_path),
            status="PROCESSING",
            source="generated",
            user_id=self.user_id,
        )
        db.session.add(record)
        db.session.commit()
        logger.info("Capture %s: saved %d packets as %s", self.session_id, len(packets), filename)
        return record


def _status(status: str, message: str, **extra) -> dict:
    return {"type": "ANALYSIS_STATUS", "status": status, "message": message, **extra}


def startWebSocketClient(ws_url: str, capture_duration: int, app=None, user_id=None) -> bool:
    """Starts a capture in the background and returns at once."""
    if app is None:
        logger.error("startWebSocketClient needs the Flask app")
        return False
    try:
        CaptureRun(app, ws_url, capture_duration, user_id).start()
    except Exception:
        logger.exception("Could not start the capture from %s", ws_url)
        return False
    return True
