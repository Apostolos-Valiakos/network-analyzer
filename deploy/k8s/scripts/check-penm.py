#!/usr/bin/env python3
"""
Checks that PENM sees the Kubernetes testbed: run it on the VM.

  PENM_PASSWORD=... ./check-penm.py --api http://<VM_IP>:30555
  ./check-penm.py --api http://<VM_IP>:30555 --trigger      # make setup traffic first
  ./check-penm.py --api http://<VM_IP>:30555 --analyze-live --evaluate

What it checks (each line PASS, WARN or FAIL; exit code 1 on any FAIL):
  pods       team-5g and team-penm pods are Running and ready
  sensor     the sensor's agents (DPI, Hubble, Kubernetes API, Zeek shipper)
             logged no restarts or delivery failures in the last 20 minutes
  flows      Zeek flows of the last 15 minutes reached the database, include
             team-5g pods, and none involve PENM's own pods
  roles      the latest pcap and DPI role snapshots are recent, and each
             team-5g pod (or its Service address) got the role it should have
  k8s        role rows carry the pod behind the IP (Hubble or the API agent),
             and no row is flagged k8s_mismatch
Optional:
  --trigger       restarts the gNB pod, the SMF and the NFs that register with
                  the NRF, so NG Setup, E2 Setup, PFCP association and NRF
                  registrations happen again, then waits for snapshots taken
                  after that. Without a UE, NGAP and E2AP are silent after
                  setup, so a 5-minute snapshot only sees them right after one.
                  The AMF, NRF, SCP, UPF and FlexRIC are not restarted (the CU
                  does not reconnect to a restarted AMF or RIC).
  --analyze-live  POST /v1/analyze_live (the full pipeline on the latest
                  snapshot; unidentified devices become WP5 notices)
  --evaluate      runs evaluate_roles.py in the backend pod for the last hour

Needs python3 and kubectl with access to both namespaces. No third-party
packages. The password is read from PENM_PASSWORD or asked for.
"""
import argparse
import getpass
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

NS_5G = "team-5g"
NS_PENM = "team-penm"

# Pod/Service name token -> roles PENM may report for it (the first is the
# role the testbed guide lists; the others agree with it, e.g. an SMF seen
# only through PFCP heartbeats is a PFCP_NODE).
EXPECTED = [
    ("amf", {"AMF"}),
    ("smf", {"SMF", "PFCP_NODE"}),
    ("upf", {"UPF", "PFCP_NODE"}),
    ("nrf", {"NRF"}),
    ("scp", {"SCP"}),
    ("ausf", {"AUSF"}),
    ("udm", {"UDM"}),
    ("udr", {"UDR"}),
    ("pcf", {"PCF"}),
    ("nssf", {"NSSF"}),
    ("bsf", {"BSF"}),
    ("gnb", {"gNB", "E2_NODE"}),
    ("flexric", {"NEAR_RT_RIC", "E2T", "REDIS"}),
    ("mongodb", {"OPEN5GS_INFRA"}),
    ("webui", {"OPEN5GS_INFRA"}),
]

# Restarted by --trigger (see the module docstring for what is left alone).
TRIGGER = ["srsran-gnb", "open5gs-smf", "open5gs-ausf", "open5gs-udm", "open5gs-udr",
           "open5gs-pcf", "open5gs-nssf", "open5gs-bsf"]

# Sensor log lines that mean trouble (agent restarts, lost deliveries).
SENSOR_PROBLEMS = [
    r"hubble observe exited",
    r"tshark \(.*\) exited",
    r"Backend unreachable",
    r"Backend answered \d+",
    r"rejected a batch",
    r"Listing namespace .* failed",
    r"Traceback",
]

results = {"PASS": 0, "WARN": 0, "FAIL": 0}


def report(status, check, message):
    results[status] += 1
    print(f"{status:<4}  {check:<7} {message}")


# ── kubectl ──────────────────────────────────────────────────────────────────


def kubectl(*args, check=True):
    proc = subprocess.run(["kubectl", *args], capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout


def pods(namespace):
    items = json.loads(kubectl("-n", namespace, "get", "pods", "-o", "json"))["items"]
    out = []
    for p in items:
        statuses = p["status"].get("containerStatuses", [])
        out.append({
            "name": p["metadata"]["name"],
            "ip": p["status"].get("podIP"),
            "phase": p["status"].get("phase"),
            "ready": bool(statuses) and all(s.get("ready") for s in statuses),
            "restarts": sum(s.get("restartCount", 0) for s in statuses),
            "containers": [c["name"] for c in p["spec"]["containers"]],
            "host_network": p["spec"].get("hostNetwork", False),
        })
    return out


def services(namespace):
    items = json.loads(kubectl("-n", namespace, "get", "svc", "-o", "json"))["items"]
    return {s["spec"]["clusterIP"]: s["metadata"]["name"]
            for s in items if s["spec"].get("clusterIP") not in (None, "None", "")}


def expected_roles(name):
    words = set(re.split(r"[^a-z0-9]+", name.lower()))
    for token, roles in EXPECTED:
        if token in words or (token == "gnb" and "srsran" in words):
            return token, roles
    return None, None


# ── PENM API ─────────────────────────────────────────────────────────────────


class Api:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.token = None

    def call(self, method, path, body=None, timeout=60):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"null")
            except ValueError:
                return e.code, None

    def login(self, user, password):
        status, body = self.call("POST", "/auth/login", {"username": user, "password": password})
        if status != 200:
            raise SystemExit(f"Login failed ({status}): {body}")
        self.token = body["access_token"]


# ── Checks ───────────────────────────────────────────────────────────────────


def check_pods():
    five_g, penm = pods(NS_5G), pods(NS_PENM)
    for ns, items in ((NS_5G, five_g), (NS_PENM, penm)):
        bad = [p["name"] for p in items if p["phase"] != "Running" or not p["ready"]]
        if bad:
            report("FAIL", "pods", f"{ns}: not running/ready: {', '.join(bad)}")
        else:
            report("PASS", "pods", f"{ns}: {len(items)} pods running")
        restarting = [f"{p['name']} ({p['restarts']})" for p in items if p["restarts"]]
        if restarting:
            report("WARN", "pods", f"{ns}: containers restarted: {', '.join(restarting)}")
    gnb = next((p for p in five_g if p["name"].startswith("srsran-gnb")), None)
    if gnb:
        variant = "CU only" if gnb["containers"] == ["cu"] else "+".join(gnb["containers"])
        report("PASS", "pods", f"gNB pod {gnb['name']}: {variant}")
    else:
        report("WARN", "pods", "no srsran-gnb pod: no NGAP/E2 node traffic")
    return five_g, penm


def check_sensor():
    logs = kubectl("-n", NS_PENM, "logs", "deploy/penm-sensor", "--since=20m", check=False)
    if not logs:
        report("FAIL", "sensor", "no sensor log in the last 20 minutes")
        return
    problems = {}
    for line in logs.splitlines():
        for pattern in SENSOR_PROBLEMS:
            if re.search(pattern, line):
                problems.setdefault(pattern, line.strip())
    # dpi_agent logs tshark's memory every 5 minutes; the other agents only
    # log at start-up and on problems, so their silence is normal.
    if "dpi_agent" not in logs:
        report("WARN", "sensor", "no dpi_agent lines in the last 20 minutes (DPI_ENABLED?)")
    if problems:
        for line in problems.values():
            report("WARN", "sensor", line[:160])
    else:
        report("PASS", "sensor", "no agent restarts or delivery failures in the last 20 minutes")


def check_flows(api, five_g, penm):
    now = time.time()
    status, flows = api.call("GET", f"/v1/network/statistics?format=json&limit=10000&start_time={now - 900}")
    if status != 200:
        report("FAIL", "flows", f"/v1/network/statistics answered {status}")
        return
    if not flows:
        report("FAIL", "flows", "no Zeek flows in the last 15 minutes (zeek_agent, HOST_API_URL, SECRET_TOKEN?)")
        return
    ips = {f.get("id.orig_h") for f in flows} | {f.get("id.resp_h") for f in flows}
    seen_5g = sorted(p["name"] for p in five_g if p["ip"] in ips)
    report("PASS", "flows", f"{len(flows)} flows in 15 min; team-5g pods seen: {len(seen_5g)}/{len(five_g)}")
    own = sorted(p["name"] for p in penm if p["ip"] in ips and not p["host_network"])
    if own:
        report("FAIL", "flows", f"PENM's own pods are being captured: {', '.join(own)}")
    else:
        report("PASS", "flows", "no flows of PENM's own pods (capture exclusion works)")


def latest_roles(api, source):
    status, rows = api.call("GET", f"/v1/network/roles/latest?format=json&source={source}")
    if status != 200:
        report("FAIL", "roles", f"latest {source} roles answered {status}")
        return []
    return rows or []


def check_roles(api, five_g, source, max_age):
    rows = latest_roles(api, source)
    if not rows:
        report("FAIL" if source == "pcap" else "WARN", "roles",
               f"no {source} role snapshot yet" + (" (DPI_ENABLED?)" if source == "dpi" else ""))
        return {}
    age = time.time() - float(rows[0]["ts"])
    report("PASS" if age <= max_age else "WARN", "roles",
           f"{source}: {len(rows)} IPs, snapshot {age:.0f} s old")
    by_ip = {r["id.orig_h"]: r for r in rows}

    with_k8s = [r for r in rows if r.get("k8s")]
    mismatched = [r for r in rows if (r.get("k8s") or {}).get("k8s_mismatch")]
    if with_k8s:
        report("PASS", "k8s", f"{source}: {len(with_k8s)}/{len(rows)} rows name their pod or Service")
    else:
        report("WARN", "k8s", f"{source}: no row carries a pod (Hubble / k8s_api_agent not reporting?)")
    for r in mismatched:
        k = r["k8s"]
        report("WARN", "k8s", f"{source}: {r['id.orig_h']} is {r['role']} but pod {k.get('pod')} "
                              f"suggests {k.get('hint_role')}")
    return by_ip


def role_table(five_g, svc, pcap, dpi):
    """One line per team-5g pod: its expected role and what each source says.
    A pod's traffic may land on its Service address (pre-DNAT capture), so
    that address counts for the pod too."""
    svc_by_name = {}
    for ip, name in svc.items():
        svc_by_name.setdefault(name, []).append(ip)
    print()
    print(f"{'pod':<34} {'expected':<14} {'pcap':<16} {'dpi':<16}")
    for p in sorted(five_g, key=lambda x: x["name"]):
        token, roles = expected_roles(p["name"])
        if roles is None:
            continue
        addresses = [p["ip"]] + [ip for name, ips in svc_by_name.items()
                                 if expected_roles(name)[0] == token for ip in ips]
        got = {}
        for label, rows in (("pcap", pcap), ("dpi", dpi)):
            found = [rows[a]["role"] for a in addresses if a in rows]
            got[label] = found[0] if found else "-"
        print(f"{p['name']:<34} {'/'.join(sorted(roles)):<14} {got['pcap']:<16} {got['dpi']:<16}")
        wrong = {s: g for s, g in got.items() if g not in roles and g not in ("-", "Unidentified")}
        expected = "/".join(sorted(roles))
        if wrong:
            report("FAIL", "roles", f"{p['name']}: expected {expected}, got "
                                    + ", ".join(f"{g} ({s})" for s, g in wrong.items()))
        elif not any(g in roles for g in got.values()):
            why = "Unidentified" if "Unidentified" in got.values() else "no traffic in the snapshots"
            report("WARN", "roles", f"{p['name']}: expected {expected}, {why} (try --trigger)")
        else:
            report("PASS", "roles", f"{p['name']}: {expected}")
    print()


def trigger():
    started = time.time()
    deployments = {line.split("/", 1)[1] for line in
                   kubectl("-n", NS_5G, "get", "deploy", "-o", "name").split()}
    names = [n for n in TRIGGER if n in deployments]
    for name in names:
        kubectl("-n", NS_5G, "rollout", "restart", f"deploy/{name}")
    for name in names:
        kubectl("-n", NS_5G, "rollout", "status", f"deploy/{name}", "--timeout=180s", check=False)
    print(f"Restarted {', '.join(names)}; waiting for snapshots taken after that.")
    return started


def wait_for_snapshots(api, since, timeout):
    deadline = time.time() + timeout
    pending = {"pcap", "dpi"}
    while pending and time.time() < deadline:
        for source in list(pending):
            status, rows = api.call("GET", f"/v1/network/roles/latest?format=json&source={source}&limit=1")
            if status == 200 and rows and float(rows[0]["ts"]) > since + 30:
                pending.discard(source)
        if pending:
            time.sleep(20)
    if pending:
        report("WARN", "roles", f"no new {'/'.join(sorted(pending))} snapshot within {timeout // 60} min")


def analyze_live(api):
    status, body = api.call("POST", "/v1/analyze_live", timeout=600)
    if status != 200:
        report("FAIL", "live", f"/v1/analyze_live answered {status}: {body}")
        return
    roles = body.get("ip_roles") or {}
    unidentified = sorted(ip for ip, r in roles.items() if r == "Unidentified")
    report("PASS", "live", f"analyze_live: {len(roles)} IPs; unidentified (WP5 notices): "
                          f"{', '.join(unidentified) or 'none'}")
    for w in body.get("warnings", []):
        report("WARN", "live", w)


def evaluate():
    out = kubectl("-n", NS_PENM, "exec", "deploy/penm-backend", "--",
                  "python", "evaluate_roles.py", "--hours", "1", check=False)
    print(out or "evaluate_roles.py printed nothing")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--api", default=os.environ.get("PENM_API", "http://127.0.0.1:30555"),
                        help="backend address (NodePort 30555), default $PENM_API")
    parser.add_argument("--user", default=os.environ.get("PENM_USER", "admin"))
    parser.add_argument("--trigger", action="store_true", help="restart setup-traffic pods first")
    parser.add_argument("--wait-minutes", type=int, default=12,
                        help="with --trigger: how long to wait for new snapshots (default 12)")
    parser.add_argument("--analyze-live", action="store_true")
    parser.add_argument("--evaluate", action="store_true")
    args = parser.parse_args()

    api = Api(args.api)
    api.login(args.user, os.environ.get("PENM_PASSWORD") or getpass.getpass(f"PENM password for {args.user}: "))

    if args.trigger:
        since = trigger()
        wait_for_snapshots(api, since, args.wait_minutes * 60)

    five_g, penm = check_pods()
    check_sensor()
    check_flows(api, five_g, penm)
    interval = int(os.environ.get("SNAPSHOT_INTERVAL_SECONDS", "300"))
    pcap = check_roles(api, five_g, "pcap", max_age=2 * interval + 120)
    dpi = check_roles(api, five_g, "dpi", max_age=300)
    role_table(five_g, services(NS_5G), pcap, dpi)
    if args.analyze_live:
        analyze_live(api)
    if args.evaluate:
        evaluate()

    print(f"{results['PASS']} passed, {results['WARN']} warnings, {results['FAIL']} failed")
    sys.exit(1 if results["FAIL"] else 0)


if __name__ == "__main__":
    main()
