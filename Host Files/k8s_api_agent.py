"""
Kubernetes identities from the Kubernetes API: which pod or Service owns
each IP, for clusters where Hubble Relay cannot be reached (SMTEC's
XTRUST-6G cluster, where PENM is admin of its own namespaces only).

Every K8S_API_INTERVAL_SECONDS (default 60) it lists the pods and Services
of each namespace in K8S_NAMESPACES with the pod's ServiceAccount token and
posts what it found to the backend's /v1/ingest/hubble, the endpoint
hubble_agent.py uses, with "source": "k8s-api":
  - one sighting per running pod IP (not host-network pods: their IP is the
    node's), with namespace, pod, workload (the Deployment behind a
    ReplicaSet, else the owner), app labels and node;
  - one Service sighting per ClusterIP.
PENM's own pods (label app.kubernetes.io/part-of=penm) are left out. The
API gives no flows; those come from Hubble only.

Permissions: in each listed namespace, a Role allowing get/list on pods and
services, bound to the sensor's ServiceAccount
(deploy/k8s/20-penm/sensor-rbac.yaml). No cluster-wide rights.

Environment:
  K8S_NAMESPACES        comma-separated namespaces (default "team-5g")
  K8S_API_URL           API server (default: https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT)
  K8S_TOKEN_FILE        default /var/run/secrets/kubernetes.io/serviceaccount/token
  K8S_CA_FILE           default /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  K8S_API_INTERVAL_SECONDS  listing interval (default 60)
  HUBBLE_API_URL        ingest URL; default: HOST_API_URL with the path
                        /v1/ingest/hubble
  SECRET_TOKEN          required, the backend's SECRET_TOKEN
"""
import logging
import os
import signal
import threading
import time
import uuid
from collections import deque
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("k8s_api_agent")

INGEST_PATH = "/v1/ingest/hubble"
SOURCE = "k8s-api"
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
PENM_LABEL = ("app.kubernetes.io/part-of", "penm")
_API_TIMEOUT = 15
_SEND_TIMEOUT = 10


def ingest_url(env=os.environ) -> str:
    if env.get("HUBBLE_API_URL"):
        return env["HUBBLE_API_URL"]
    base = env.get("HOST_API_URL", "")
    if not base:
        raise SystemExit("Set HUBBLE_API_URL or HOST_API_URL (the backend's ingest URL)")
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, INGEST_PATH, "", ""))


def api_url(env=os.environ) -> str:
    if env.get("K8S_API_URL"):
        return env["K8S_API_URL"].rstrip("/")
    host, port = env.get("KUBERNETES_SERVICE_HOST"), env.get("KUBERNETES_SERVICE_PORT", "443")
    if not host:
        raise SystemExit("Not in a Kubernetes pod: set K8S_API_URL")
    if ":" in host:  # IPv6
        host = f"[{host}]"
    return f"https://{host}:{port}"


def namespaces(env=os.environ) -> List[str]:
    return [n.strip() for n in env.get("K8S_NAMESPACES", "team-5g").split(",") if n.strip()]


def _app_labels(labels: Dict[str, str]) -> Dict[str, str]:
    return {k: str(v) for k, v in (labels or {}).items() if k.startswith("app")}


def _workload(pod: Dict[str, Any]):
    """(name, kind) of what runs the pod: the Deployment behind a ReplicaSet
    (its name minus the pod-template-hash), else the owner itself."""
    meta = pod.get("metadata", {})
    owners = [o for o in meta.get("ownerReferences", []) if o.get("controller")] or \
        meta.get("ownerReferences", [])
    if not owners:
        return None, None
    owner = owners[0]
    name, kind = owner.get("name"), owner.get("kind")
    template_hash = (meta.get("labels") or {}).get("pod-template-hash")
    if kind == "ReplicaSet" and template_hash and name and name.endswith("-" + template_hash):
        return name[: -len(template_hash) - 1], "Deployment"
    return name, kind


def pod_sightings(pods: List[Dict[str, Any]], now: float) -> List[Dict[str, Any]]:
    out = []
    for pod in pods:
        meta, spec, status = pod.get("metadata", {}), pod.get("spec", {}), pod.get("status", {})
        labels = meta.get("labels") or {}
        if labels.get(PENM_LABEL[0]) == PENM_LABEL[1]:
            continue
        if spec.get("hostNetwork") or status.get("phase") != "Running":
            continue
        ips = [p.get("ip") for p in status.get("podIPs") or [] if p.get("ip")]
        if not ips and status.get("podIP"):
            ips = [status["podIP"]]
        workload, kind = _workload(pod)
        for ip in ips:
            out.append({
                "ip": ip,
                "namespace": meta.get("namespace"),
                "pod": meta.get("name"),
                "workload": workload,
                "workload_kind": kind,
                "labels": _app_labels(labels),
                "identity": None,
                "node": spec.get("nodeName"),
                "first_seen": now,
                "last_seen": now,
            })
    return out


def service_sightings(services: List[Dict[str, Any]], now: float) -> List[Dict[str, Any]]:
    out = []
    for svc in services:
        meta, spec = svc.get("metadata", {}), svc.get("spec", {})
        ips = spec.get("clusterIPs") or ([spec["clusterIP"]] if spec.get("clusterIP") else [])
        for ip in ips:
            if ip and ip != "None":  # headless Services have no address of their own
                out.append({"ip": ip, "namespace": meta.get("namespace"),
                            "service": meta.get("name"), "first_seen": now, "last_seen": now})
    return out


class K8sApiAgent:
    def __init__(
        self,
        api: str,
        namespaces: List[str],
        url: str,
        token: str,
        token_file: str = os.path.join(SA_DIR, "token"),
        ca_file: str = os.path.join(SA_DIR, "ca.crt"),
        get: Callable = requests.get,
        post: Callable = requests.post,
        clock: Callable[[], float] = time.time,
        max_pending: int = 30,
    ):
        self.api, self.namespaces, self.url, self.token = api, namespaces, url, token
        self.token_file, self.ca_file = token_file, ca_file
        self.get, self.post, self.clock = get, post, clock
        self.max_pending = max_pending
        self.pending = deque()
        self.dropped = 0

    def _list(self, namespace: str, kind: str) -> List[Dict[str, Any]]:
        # Re-read the token every time: projected ServiceAccount tokens rotate.
        with open(self.token_file, encoding="utf-8") as f:
            bearer = f.read().strip()
        response = self.get(
            f"{self.api}/api/v1/namespaces/{namespace}/{kind}",
            headers={"Authorization": f"Bearer {bearer}"},
            verify=self.ca_file if os.path.exists(self.ca_file) else True,
            timeout=_API_TIMEOUT,
        )
        if response.status_code == 403:
            raise PermissionError(
                f"no permission to list {kind} in {namespace} (apply sensor-rbac.yaml there)"
            )
        response.raise_for_status()
        return response.json().get("items", [])

    def collect(self) -> Optional[Dict[str, Any]]:
        """One batch of all listed namespaces, queued for sending. Namespaces
        that fail are logged and skipped; the others are still sent."""
        now = self.clock()
        pods, services, failed = [], [], []
        for namespace in self.namespaces:
            try:
                pods += pod_sightings(self._list(namespace, "pods"), now)
                services += service_sightings(self._list(namespace, "services"), now)
            except (OSError, ValueError, requests.exceptions.RequestException) as exc:
                failed.append(namespace)
                logger.warning("Listing namespace %s failed: %s", namespace, exc)
        if failed and len(failed) == len(self.namespaces):
            return None
        batch = {"batch_id": uuid.uuid4().hex, "source": SOURCE,
                 "sightings": pods, "services": services, "flows": []}
        if len(self.pending) >= self.max_pending:
            self.pending.popleft()
            self.dropped += 1
            logger.warning("Backend unreachable for %d batches: dropped the oldest", self.max_pending)
        self.pending.append(batch)
        return batch

    def flush(self) -> None:
        while self.pending:
            batch = self.pending[0]
            try:
                response = self.post(self.url, json=batch, headers={"X-Internal-Token": self.token},
                                     timeout=_SEND_TIMEOUT)
            except requests.exceptions.RequestException as exc:
                logger.warning("Backend unreachable, batch kept for retry: %s", exc)
                return
            if response.status_code == 400:
                logger.error("Backend rejected a batch as invalid, dropped: %s", response.text[:500])
            elif response.status_code != 200:
                logger.warning("Backend answered %s, batch kept for retry", response.status_code)
                return
            self.pending.popleft()


def main() -> None:
    token = os.environ.get("SECRET_TOKEN", "")
    if not token:
        raise SystemExit("SECRET_TOKEN is not set (use the backend's SECRET_TOKEN)")
    agent = K8sApiAgent(
        api_url(), namespaces(), ingest_url(), token,
        token_file=os.environ.get("K8S_TOKEN_FILE", os.path.join(SA_DIR, "token")),
        ca_file=os.environ.get("K8S_CA_FILE", os.path.join(SA_DIR, "ca.crt")),
    )
    interval = max(10, int(os.environ.get("K8S_API_INTERVAL_SECONDS", "60")))
    logger.info("Pods and Services of %s from %s every %d s to %s",
                ", ".join(agent.namespaces), agent.api, interval, agent.url)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda signum, frame: stop.set())
    try:
        while not stop.is_set():
            agent.collect()
            agent.flush()
            stop.wait(interval)
    except KeyboardInterrupt:
        pass
    logger.info("Shutting down Kubernetes API agent...")


if __name__ == "__main__":
    main()
