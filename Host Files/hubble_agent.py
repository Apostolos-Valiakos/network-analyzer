"""
Kubernetes identities from Hubble: which pod or Service owned each IP.

Runs `hubble observe --follow -o jsonpb` against Hubble Relay, reads every
flow, and sends to the backend (POST /v1/ingest/hubble) every
HUBBLE_INTERVAL_SECONDS (default 60):
  - sightings: IP -> namespace, pod, workload, app labels, security
    identity, node, with the first and last time seen in the interval;
  - services: Service (ClusterIP) address -> namespace/name, when a flow
    went to a Service address that Cilium had not yet translated to a pod;
  - flows: counts per minute and (src, dst, dst port, protocol, verdict,
    src pod, dst pod).
Flows to or from PENM's own pods (label app.kubernetes.io/part-of=penm) are
left out, as in the capture. Host-network endpoints (the node's own address,
which several pods share) give no pod sighting.

A batch the backend did not accept is kept and sent again, oldest first, up
to HUBBLE_MAX_PENDING (default 30); a batch rejected as invalid (400) is
dropped.

Environment:
  HUBBLE_SERVER          Hubble Relay address (default
                         hubble-relay.kube-system.svc.cluster.local:80)
  HUBBLE_API_URL         ingest URL; default: HOST_API_URL with the path
                         /v1/ingest/hubble
  SECRET_TOKEN           required, the backend's SECRET_TOKEN
  HUBBLE_INTERVAL_SECONDS  batch interval (default 60)
  HUBBLE_MAX_PENDING     batches kept while the backend is unreachable (default 30)
  HUBBLE_PATH            hubble binary (default: "hubble" on PATH)
"""
import json
import logging
import os
import shutil
import signal
import subprocess
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import urlsplit, urlunsplit

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("hubble_agent")

INGEST_PATH = "/v1/ingest/hubble"
DEFAULT_SERVER = "hubble-relay.kube-system.svc.cluster.local:80"
PENM_LABEL = "k8s:app.kubernetes.io/part-of=penm"
# Labels that say what a pod is; everything else (pod-template-hash, ...) is noise.
_LABEL_PREFIX = "k8s:app"
_HOST_LABELS = {"reserved:host", "reserved:remote-node", "reserved:kube-apiserver"}
_HOST_IDENTITIES = {1, 6, 7}  # host, remote-node, kube-apiserver
_SEND_TIMEOUT = 10
_RESTART_DELAY = 5


def ingest_url(env=os.environ) -> str:
    if env.get("HUBBLE_API_URL"):
        return env["HUBBLE_API_URL"]
    base = env.get("HOST_API_URL", "")
    if not base:
        raise SystemExit("Set HUBBLE_API_URL or HOST_API_URL (the backend's ingest URL)")
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, INGEST_PATH, "", ""))


def hubble_command(hubble: str, server: str) -> List[str]:
    return [hubble, "observe", "--server", server, "--follow", "-o", "jsonpb"]


# ── Reading one flow ──────────────────────────────────────────────────────────


def _get(obj: Any, *names: str, default=None):
    """The first of `names` present in a dict: hubble prints protobuf field
    names (pod_name), some versions their JSON names (podName)."""
    if isinstance(obj, dict):
        for name in names:
            if name in obj and obj[name] is not None:
                return obj[name]
    return default


def parse_time(value: Any) -> Optional[float]:
    """RFC 3339 (nanoseconds allowed) to epoch seconds."""
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    if "." in text:
        # Python 3.10's fromisoformat takes 3 or 6 fraction digits only;
        # Hubble prints nanoseconds (9).
        head, rest = text.split(".", 1)
        digits = rest[: len(rest) - len(rest.lstrip("0123456789"))]
        zone = rest[len(digits):]
        text = f"{head}.{digits[:6].ljust(6, '0')}{zone}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _endpoint(raw: Any) -> Dict[str, Any]:
    labels = [l for l in _get(raw, "labels", default=[]) if isinstance(l, str)]
    workloads = _get(raw, "workloads", default=[]) or []
    workload = workloads[0] if workloads and isinstance(workloads[0], dict) else {}
    identity = _get(raw, "identity")
    return {
        "namespace": _get(raw, "namespace", default=""),
        "pod": _get(raw, "pod_name", "podName", default=""),
        "workload": _get(workload, "name", default=""),
        "workload_kind": _get(workload, "kind", default=""),
        "labels": labels,
        "identity": identity if isinstance(identity, int) else None,
    }


def _is_host(endpoint: Dict[str, Any]) -> bool:
    return bool(_HOST_LABELS & set(endpoint["labels"])) or endpoint["identity"] in _HOST_IDENTITIES


def _app_labels(labels: Iterable[str]) -> Dict[str, str]:
    out = {}
    for label in labels:
        if label.startswith(_LABEL_PREFIX) and "=" in label:
            key, value = label[len("k8s:"):].split("=", 1)
            out[key] = value
    return out


def parse_flow(line: str) -> Optional[Dict[str, Any]]:
    """The parts of one `hubble observe -o jsonpb` line this agent uses, or
    None for lines that are not IP flows."""
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    flow = _get(obj, "flow", default=obj)
    ip = _get(flow, "IP", "ip", default={})
    src_ip, dst_ip = _get(ip, "source"), _get(ip, "destination")
    if not src_ip or not dst_ip:
        return None
    l4 = _get(flow, "l4", default={}) or {}
    protocol, ports = "", {}
    for name in ("TCP", "UDP", "SCTP", "ICMPv4", "ICMPv6"):
        if name in l4:
            protocol, ports = name, l4[name] or {}
            break
    port = _get(ports, "destination_port", "destinationPort", default=0)
    service = _get(flow, "destination_service", "destinationService", default={}) or {}
    return {
        "time": parse_time(_get(flow, "time") or _get(obj, "time")),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src": _endpoint(_get(flow, "source", default={})),
        "dst": _endpoint(_get(flow, "destination", default={})),
        "protocol": protocol,
        "dst_port": port if isinstance(port, int) else 0,
        "verdict": _get(flow, "verdict", default=""),
        "node": _get(flow, "node_name", "nodeName") or _get(obj, "node_name", "nodeName", default=""),
        "service_name": _get(service, "name", default=""),
        "service_namespace": _get(service, "namespace", default=""),
    }


# ── Aggregation and sending ──────────────────────────────────────────────────


class HubbleAgent:
    def __init__(
        self,
        url: str,
        token: str,
        max_pending: int = 30,
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
        self.skipped_penm = 0
        self._lock = threading.Lock()
        self._reset()

    def _reset(self) -> None:
        self._pods: Dict[tuple, Dict[str, Any]] = {}
        self._services: Dict[tuple, Dict[str, Any]] = {}
        self._flows: Dict[tuple, int] = {}

    def feed(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        flow = parse_flow(line)
        if flow is None:
            return
        ts = flow["time"] if flow["time"] is not None else self.clock()
        src, dst = flow["src"], flow["dst"]
        if PENM_LABEL in src["labels"] or PENM_LABEL in dst["labels"]:
            self.skipped_penm += 1
            return
        with self._lock:
            for ip, endpoint in ((flow["src_ip"], src), (flow["dst_ip"], dst)):
                self._sight_pod(ip, endpoint, flow["node"], ts)
            # A Service name with no pod on the destination: the address is
            # still the Service's (not yet translated to a backend pod).
            if flow["service_name"] and not dst["pod"]:
                key = (flow["dst_ip"], flow["service_namespace"], flow["service_name"])
                self._extend(self._services, key, ts, {
                    "ip": key[0], "namespace": key[1], "service": key[2],
                })
            minute = float(int(ts // 60) * 60)
            flow_key = (
                minute, flow["src_ip"], flow["dst_ip"], flow["dst_port"], flow["protocol"],
                flow["verdict"], self._pod_name(src), self._pod_name(dst),
            )
            self._flows[flow_key] = self._flows.get(flow_key, 0) + 1

    @staticmethod
    def _pod_name(endpoint) -> str:
        return f"{endpoint['namespace']}/{endpoint['pod']}" if endpoint["pod"] else ""

    def _sight_pod(self, ip, endpoint, node, ts) -> None:
        if not endpoint["pod"] or not endpoint["namespace"] or _is_host(endpoint):
            return
        key = (ip, endpoint["namespace"], endpoint["pod"])
        self._extend(self._pods, key, ts, {
            "ip": ip,
            "namespace": endpoint["namespace"],
            "pod": endpoint["pod"],
            "workload": endpoint["workload"] or None,
            "workload_kind": endpoint["workload_kind"] or None,
            "labels": _app_labels(endpoint["labels"]),
            "identity": endpoint["identity"],
            "node": node or None,
        })

    @staticmethod
    def _extend(table, key, ts, item) -> None:
        current = table.get(key)
        if current is None:
            table[key] = {**item, "first_seen": ts, "last_seen": ts}
        else:
            current["first_seen"] = min(current["first_seen"], ts)
            current["last_seen"] = max(current["last_seen"], ts)

    def rotate(self) -> Dict[str, Any]:
        """Queues what was seen since the last batch and starts afresh."""
        with self._lock:
            pods, services, flows = self._pods, self._services, self._flows
            self._reset()
        batch = {
            "batch_id": uuid.uuid4().hex,
            "sightings": list(pods.values()),
            "services": list(services.values()),
            "flows": [
                {
                    "minute": k[0], "src_ip": k[1], "dst_ip": k[2], "dst_port": k[3],
                    "protocol": k[4], "verdict": k[5], "src_pod": k[6], "dst_pod": k[7],
                    "count": n,
                }
                for k, n in flows.items()
            ],
        }
        if len(self.pending) >= self.max_pending:
            self.pending.popleft()
            self.dropped += 1
            logger.warning("Backend unreachable for %d batches: dropped the oldest (%d so far)",
                           self.max_pending, self.dropped)
        self.pending.append(batch)
        return batch

    def flush(self) -> None:
        while self.pending:
            if not self._send(self.pending[0]):
                return
            self.pending.popleft()

    def _send(self, batch) -> bool:
        try:
            response = self.post(self.url, json=batch, headers={"X-Internal-Token": self.token},
                                 timeout=_SEND_TIMEOUT)
        except requests.exceptions.RequestException as exc:
            logger.warning("Backend unreachable, batch kept for retry: %s", exc)
            return False
        if response.status_code == 200:
            return True
        if response.status_code == 400:
            logger.error("Backend rejected a batch as invalid, dropped: %s", response.text[:500])
            return True
        logger.warning("Backend answered %s, batch kept for retry", response.status_code)
        return False


class HubbleRunner(threading.Thread):
    """Runs `hubble observe --follow` and restarts it when it exits (Relay
    restarts, network blips)."""

    def __init__(self, cmd: List[str], agent: HubbleAgent, stop: threading.Event):
        super().__init__(name="hubble-observe", daemon=True)
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
            logger.info("Starting: %s", " ".join(self.cmd))
            try:
                self.process = subprocess.Popen(
                    self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, bufsize=1, errors="replace",
                )
            except OSError:
                logger.exception("Could not start hubble")
            else:
                threading.Thread(target=self._log_stderr, daemon=True).start()
                for line in self.process.stdout:
                    self.agent.feed(line)
                code = self.process.wait()
                if self.stop.is_set():
                    return
                logger.warning("hubble observe exited with %s; restarting", code)
            self.stop.wait(_RESTART_DELAY)

    def _log_stderr(self) -> None:
        for line in self.process.stderr:
            if line.strip():
                logger.info("hubble: %s", line.strip())


def main() -> None:
    token = os.environ.get("SECRET_TOKEN", "")
    if not token:
        raise SystemExit("SECRET_TOKEN is not set (use the backend's SECRET_TOKEN)")
    hubble = os.environ.get("HUBBLE_PATH") or shutil.which("hubble")
    if not hubble:
        raise SystemExit("hubble CLI not found (install it or set HUBBLE_PATH)")
    server = os.environ.get("HUBBLE_SERVER", DEFAULT_SERVER)
    interval = max(10, int(os.environ.get("HUBBLE_INTERVAL_SECONDS", "60")))
    agent = HubbleAgent(ingest_url(), token,
                        max_pending=int(os.environ.get("HUBBLE_MAX_PENDING", "30")))
    stop = threading.Event()
    runner = HubbleRunner(hubble_command(hubble, server), agent, stop)
    runner.start()
    logger.info("Hubble identities from %s every %d s to %s", server, interval, agent.url)

    def _terminate(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _terminate)

    try:
        while True:
            stop.wait(interval)
            agent.rotate()
            agent.flush()
    except KeyboardInterrupt:
        logger.info("Shutting down Hubble agent...")
    finally:
        stop.set()
        runner.terminate()


if __name__ == "__main__":
    main()
