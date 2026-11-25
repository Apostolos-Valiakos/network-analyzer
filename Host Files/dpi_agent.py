"""
Live DPI at the sensor: decodes the 5G protocols with tshark as traffic
passes and sends the role engine's stage-1 evidence to the backend once per
window (POST /v1/ingest/dpi), where live_roles turns it into role snapshots.

Two tshark processes, both with the capture exclusions dumpcap and Zeek use:
  - control plane (NGAP, E2AP, PFCP, SBI): full packets, which SBI needs;
  - user plane (GTP-U): the first DPI_SNAPLEN_UP bytes (default 128), enough
    for the outer header, GTP-U and the inner IP header.
Their field lines are parsed with role_evidence, the code the backend's role
engine uses on captures, into the current window.

Only evidence leaves the sensor: IPs, counters, SBI API prefixes, NF types
and node names. No subscriber identifiers and no payloads.

A window the backend did not accept stays queued and is sent again, oldest
first, with the next one; at most DPI_MAX_PENDING windows (default 60) are
kept, then the oldest are dropped. A window the backend rejects as invalid
(400) is dropped, so it cannot block the queue.

Environment:
  CAPTURE_INTERFACE     interface (default "any")
  CAPTURE_EXCLUDE       BPF expression of traffic to leave out (the sensor's
                        exclusion filter), optional
  DPI_API_URL           ingest URL; default: HOST_API_URL with the path
                        /v1/ingest/dpi
  SECRET_TOKEN          required, the backend's SECRET_TOKEN
  DPI_WINDOW_SECONDS    window length (default 60)
  DPI_SNAPLEN_UP        bytes kept per GTP-U packet (default 128)
  DPI_MAX_PENDING       windows kept while the backend is unreachable (default 60)
  DPI_TSHARK_RESET_PACKETS  tshark -M: reset tshark's state after this many
                        packets to bound its memory (default 0 = never). A reset
                        loses HTTP/2 header state, so SBI paths on connections
                        open at that moment cannot be read afterwards.
  TSHARK_PATH           tshark binary (default: "tshark" on PATH)
"""
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from typing import Callable, List, Optional
from urllib.parse import urlsplit, urlunsplit

import requests

try:
    import role_evidence
except ImportError:  # bare-metal sensor: run from a repository checkout
    sys.path.insert(
        0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "server")
    )
    import role_evidence

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("dpi_agent")

INGEST_PATH = "/v1/ingest/dpi"
CP_FILTER = "sctp or udp port 8805 or tcp"
UP_FILTER = "udp port 2152"
_SEND_TIMEOUT = 10
_RESTART_DELAY = 5


def ingest_url(env=os.environ) -> str:
    """DPI_API_URL, or HOST_API_URL (zeek_agent's ingest URL) with its path
    replaced by /v1/ingest/dpi."""
    if env.get("DPI_API_URL"):
        return env["DPI_API_URL"]
    base = env.get("HOST_API_URL", "")
    if not base:
        raise SystemExit("Set DPI_API_URL or HOST_API_URL (the backend's ingest URL)")
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, INGEST_PATH, "", ""))


def capture_filter(base: str, exclude: str = "") -> str:
    return f"({base}) and ({exclude})" if exclude.strip() else base


def tshark_command(
    tshark: str,
    interface: str,
    bpf: str,
    snaplen: Optional[int] = None,
    reset_packets: int = 0,
) -> List[str]:
    """Live capture printing one tab-separated line per frame with
    role_evidence's fields, every occurrence comma-joined (like the
    backend's packet table). -l flushes each line at once."""
    cmd = [tshark, "-i", interface, "-n", "-l", "-f", bpf]
    if snaplen:
        cmd += ["-s", str(snaplen)]
    if reset_packets:
        cmd += ["-M", str(reset_packets)]
    cmd += ["-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]
    for name in role_evidence._TSHARK_FIELDS:
        cmd += ["-e", name]
    return cmd


class DpiAgent:
    """Collects evidence into the current window and sends finished windows."""

    def __init__(
        self,
        url: str,
        token: str,
        max_pending: int = 60,
        post: Callable = requests.post,
        clock: Callable[[], float] = time.time,
    ):
        self.url = url
        self.token = token
        self.post = post
        self.clock = clock
        self.max_pending = max_pending
        self.pending = deque()
        self.dropped = 0
        self.parse_errors = 0
        self._lock = threading.Lock()
        self._window = role_evidence.PcapObservations()
        self._window_start = clock()
        self._notes: List[str] = []

    def feed(self, line: str) -> None:
        """Adds one tshark field line to the current window."""
        line = line.rstrip("\r\n")
        if not line:
            return
        with self._lock:
            try:
                role_evidence._parse_line(line, self._window)
            except Exception:
                self.parse_errors += 1
                if self.parse_errors == 1 or self.parse_errors % 1000 == 0:
                    logger.exception("Could not parse a tshark line (%d so far)", self.parse_errors)

    def note(self, message: str) -> None:
        """A user-readable warning sent with the current window."""
        with self._lock:
            if message not in self._notes:
                self._notes.append(message)

    def rotate(self) -> dict:
        """Closes the current window, queues it and starts the next one."""
        now = self.clock()
        with self._lock:
            obs, start, notes = self._window, self._window_start, self._notes
            self._window = role_evidence.PcapObservations()
            self._window_start = now
            self._notes = []
        obs.warnings.extend(notes)
        payload = {
            "window_id": uuid.uuid4().hex,
            "window_start": start,
            "window_end": now,
            "observations": obs.to_dict(),
        }
        if len(self.pending) >= self.max_pending:
            self.pending.popleft()
            self.dropped += 1
            logger.warning(
                "Backend unreachable for %d windows: dropped the oldest (%d dropped so far)",
                self.max_pending, self.dropped,
            )
        self.pending.append(payload)
        return payload

    def flush(self) -> None:
        """Sends queued windows oldest first; stops at the first failure."""
        while self.pending:
            if not self._send(self.pending[0]):
                return
            self.pending.popleft()

    def _send(self, payload: dict) -> bool:
        """True when the window can leave the queue (accepted, or rejected as
        invalid); False to keep it for the next attempt."""
        headers = {"X-Internal-Token": self.token}
        try:
            response = self.post(self.url, json=payload, headers=headers, timeout=_SEND_TIMEOUT)
        except requests.exceptions.RequestException as exc:
            logger.warning("Backend unreachable, window kept for retry: %s", exc)
            return False
        if response.status_code == 200:
            return True
        if response.status_code == 400:
            logger.error("Backend rejected a window as invalid, dropped: %s", response.text[:500])
            return True
        logger.warning(
            "Backend answered %s, window kept for retry: %s",
            response.status_code, response.text[:200],
        )
        return False


class TsharkRunner(threading.Thread):
    """Runs one tshark process, feeds its lines to the agent, and restarts it
    when it exits."""

    def __init__(self, name: str, cmd: List[str], agent: DpiAgent, stop: threading.Event):
        super().__init__(name=f"tshark-{name}", daemon=True)
        self.label = name
        self.cmd = cmd
        self.agent = agent
        self.stop = stop
        self.process = None

    def terminate(self) -> None:
        process = self.process
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

    def run(self) -> None:
        while not self.stop.is_set():
            logger.info("Starting %s capture: %s", self.label, " ".join(self.cmd[:8]))
            try:
                process = subprocess.Popen(
                    self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, bufsize=1, errors="replace",
                )
            except OSError:
                logger.exception("Could not start tshark for the %s capture", self.label)
            else:
                self.process = process
                threading.Thread(
                    target=self._log_stderr, args=(process,), daemon=True
                ).start()
                for line in process.stdout:
                    self.agent.feed(line)
                code = process.wait()
                if self.stop.is_set():
                    return
                logger.warning("tshark (%s capture) exited with %s; restarting", self.label, code)
            self.agent.note(
                f"Live DPI: the {self.label} capture restarted; evidence for this window "
                "may be incomplete."
            )
            self.stop.wait(_RESTART_DELAY)

    def _log_stderr(self, process) -> None:
        for line in process.stderr:
            line = line.strip()
            if line:
                logger.info("tshark (%s): %s", self.label, line)


def main() -> None:
    token = os.environ.get("SECRET_TOKEN", "")
    if not token:
        raise SystemExit("SECRET_TOKEN is not set (use the backend's SECRET_TOKEN)")
    tshark = os.environ.get("TSHARK_PATH") or shutil.which("tshark")
    if not tshark:
        raise SystemExit("tshark not found (install it or set TSHARK_PATH)")

    interface = os.environ.get("CAPTURE_INTERFACE", "any")
    exclude = os.environ.get("CAPTURE_EXCLUDE", "")
    window = max(10, int(os.environ.get("DPI_WINDOW_SECONDS", "60")))
    snaplen_up = int(os.environ.get("DPI_SNAPLEN_UP", "128"))
    reset = int(os.environ.get("DPI_TSHARK_RESET_PACKETS", "0"))
    agent = DpiAgent(ingest_url(), token, max_pending=int(os.environ.get("DPI_MAX_PENDING", "60")))

    stop = threading.Event()
    runners = [
        TsharkRunner("control-plane", tshark_command(
            tshark, interface, capture_filter(CP_FILTER, exclude), reset_packets=reset), agent, stop),
        TsharkRunner("user-plane", tshark_command(
            tshark, interface, capture_filter(UP_FILTER, exclude), snaplen=snaplen_up,
            reset_packets=reset), agent, stop),
    ]
    for runner in runners:
        runner.start()
    logger.info("Live DPI on %s, %d s windows, sending to %s", interface, window, agent.url)

    def _terminate(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _terminate)

    try:
        next_rotation = time.time() + window
        while True:
            stop.wait(max(0.0, next_rotation - time.time()))
            agent.rotate()
            agent.flush()
            # After a slow send, start a full window from now rather than
            # closing several short windows back to back.
            next_rotation += window
            if next_rotation <= time.time():
                next_rotation = time.time() + window
    except KeyboardInterrupt:
        logger.info("Shutting down DPI agent...")
    finally:
        stop.set()
        for runner in runners:
            runner.terminate()


if __name__ == "__main__":
    main()
