"""
Build per-host privacy records from a PCAP for the privacy-metrics module.

One tshark pass extracts the header fields we need; we then aggregate one
record per IP address. IPs carried inside GTP-U tunnels are attributed to the
UE that owns them, so subscriber addresses show up as their own rows.

Record schema (one row per host):
    ip, mac               direct identifiers
    mac_vendor, subnet,
    scope, service_port,
    first_seen_s,
    duration_s            quasi-identifiers
    role, protocols,
    protocol_count        candidate sensitive attributes
    packets, bytes,
    tx_share, peer_count  traffic volume (QI or SA, depending on the release)
    pilot                 pilot label used for per-pilot pseudonymisation
"""

import ipaddress
import os
import subprocess
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "eth.src",
    "eth.src.oui_resolved",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "sctp.srcport",
    "sctp.dstport",
    "gtp.teid",
    "_ws.col.Protocol",
]

# Well-known ports and the role of the host that listens on them.
SERVICE_ROLES = {
    "38412": "AMF (NGAP)",
    "38472": "CU (F1AP)",
    "36421": "Near-RT RIC (E2)",
    "36422": "Near-RT RIC (E2)",
    "8805": "SMF/UPF (PFCP)",
    "2152": "GTP-U endpoint",
    "53": "DNS server",
    "3478": "STUN/TURN server",
    "19302": "STUN/TURN server",
    "443": "TLS/QUIC server",
    "80": "Web server",
    "123": "NTP server",
    "67": "DHCP server",
    "5555": "OCPP charger",
}

# Ports whose client side also tells us something about the node.
CLIENT_ROLES = {
    "38412": "gNB (NGAP client)",
    "38472": "DU (F1AP client)",
    "36421": "E2 node",
    "36422": "E2 node",
}

ROLE_PRIORITY = [
    "AMF (NGAP)",
    "gNB (NGAP client)",
    "CU (F1AP)",
    "DU (F1AP client)",
    "Near-RT RIC (E2)",
    "E2 node",
    "SMF/UPF (PFCP)",
    "UE (GTP-U inner)",
    "GTP-U endpoint",
    "DNS server",
    "STUN/TURN server",
    "TLS/QUIC server",
    "Web server",
    "NTP server",
    "DHCP server",
    "OCPP charger",
]


def _routable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_loopback
        or addr.is_multicast
        or addr.is_unspecified
        or ip == "255.255.255.255"
    )


def _scope(ip: str, ue: bool) -> str:
    if ue:
        return "ue_pool"
    return "private" if ipaddress.ip_address(ip).is_private else "public"


def _split(value: str) -> List[str]:
    return [v for v in value.split(",") if v] if value else []


def run_tshark(pcap_path: str) -> str:
    """Run tshark once. A capture cut off mid-packet makes tshark exit
    non-zero, but every complete packet is still printed, so we keep stdout."""
    cmd = ["tshark", "-r", pcap_path, "-n", "-T", "fields", "-Y", "ip"]
    for field in FIELDS:
        cmd += ["-e", field]
    cmd += ["-E", "separator=\t", "-E", "aggregator=,", "-E", "occurrence=a"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if out.returncode != 0 and not out.stdout:
        raise RuntimeError(f"tshark failed: {out.stderr[:300]}")
    return out.stdout


def load_rows(pcap_path: str, cache_path: Optional[str] = None) -> str:
    if cache_path and os.path.exists(cache_path):
        if os.path.getmtime(cache_path) >= os.path.getmtime(pcap_path):
            with open(cache_path) as f:
                return f.read()
    text = run_tshark(pcap_path)
    if cache_path:
        with open(cache_path, "w") as f:
            f.write(text)
    return text


def _new_host() -> Dict[str, Any]:
    return {
        "macs": Counter(),
        "vendors": Counter(),
        "protocols": set(),
        "own_ports": Counter(),
        "client_ports": set(),
        "tx_packets": 0,
        "rx_packets": 0,
        "tx_bytes": 0,
        "rx_bytes": 0,
        "peers": set(),
        "first": None,
        "last": None,
        "inner_peers": set(),
        "ue": False,
    }


def _touch(host: Dict[str, Any], ts: float) -> None:
    if host["first"] is None or ts < host["first"]:
        host["first"] = ts
    if host["last"] is None or ts > host["last"]:
        host["last"] = ts


def aggregate_hosts(tshark_text: str) -> Dict[str, Dict[str, Any]]:
    hosts: Dict[str, Dict[str, Any]] = defaultdict(_new_host)
    for line in tshark_text.splitlines():
        cols = line.split("\t")
        if len(cols) < len(FIELDS):
            continue
        (ts, flen, mac, vendor, srcs, dsts, tsp, tdp, usp, udp_, ssp, sdp,
         teid, proto) = cols[: len(FIELDS)]
        try:
            ts_f = float(ts)
            size = int(flen)
        except ValueError:
            continue
        src_list, dst_list = _split(srcs), _split(dsts)
        if not src_list or not dst_list:
            continue
        sports = _split(tsp) + _split(usp) + _split(ssp)
        dports = _split(tdp) + _split(udp_) + _split(sdp)

        pairs = [(src_list[0], dst_list[0], sports[:1], dports[:1], True)]
        if teid and len(src_list) > 1 and len(dst_list) > 1:
            # Inner header of a GTP-U packet: the UE side of the tunnel.
            # Inner ports exist only when the payload is TCP/UDP; otherwise
            # the last port seen is the outer GTP-U port (2152).
            inner_ports = len(sports) > 1
            pairs.append((
                src_list[-1], dst_list[-1],
                sports[-1:] if inner_ports else [],
                dports[-1:] if inner_ports else [],
                False,
            ))

        for src, dst, sp, dp, outer in pairs:
            inner = not outer
            for ip, is_src in ((src, True), (dst, False)):
                if not _routable(ip):
                    continue
                h = hosts[ip]
                _touch(h, ts_f)
                if proto:
                    h["protocols"].add(proto.strip().upper())
                if is_src:
                    h["tx_packets"] += 1
                    h["tx_bytes"] += size
                    h["peers"].add(dst)
                    if outer and mac and ipaddress.ip_address(ip).is_private:
                        h["macs"][mac] += 1
                        if vendor:
                            h["vendors"][vendor] += 1
                    if sp:
                        h["own_ports"][sp[0]] += 1
                    if dp and dp[0] in CLIENT_ROLES:
                        h["client_ports"].add(dp[0])
                else:
                    h["rx_packets"] += 1
                    h["rx_bytes"] += size
                    h["peers"].add(src)
                    if dp:
                        h["own_ports"][dp[0]] += 1
                if inner:
                    h["inner_peers"].add(dst if is_src else src)
    # The UE is the private inner address that talks to several inner
    # peers (e.g. 10.45.0.4 in the Open5GS pool); a LAN server reached
    # through the tunnel only ever talks to the UE.
    for ip, h in hosts.items():
        if len(h["inner_peers"]) >= 2 and ipaddress.ip_address(ip).is_private:
            h["ue"] = True
    return hosts


def _role(ip: str, h: Dict[str, Any]) -> str:
    candidates = set()
    if h["ue"]:
        candidates.add("UE (GTP-U inner)")
    for port in h["client_ports"]:
        candidates.add(CLIENT_ROLES[port])
    for port, count in h["own_ports"].items():
        if port in SERVICE_ROLES and count >= 2:
            candidates.add(SERVICE_ROLES[port])
    if {"gNB (NGAP client)", "CU (F1AP)"} <= candidates:
        return "gNB-CU"
    if {"AMF (NGAP)", "GTP-U endpoint"} <= candidates:
        return "5GC (AMF+UPF)"
    for role in ROLE_PRIORITY:
        if role in candidates:
            return role
    if ipaddress.ip_address(ip).is_private:
        return "LAN host"
    return "Internet peer"


def _service_port(h: Dict[str, Any]) -> str:
    known = [(c, p) for p, c in h["own_ports"].items() if p in SERVICE_ROLES]
    if known:
        return max(known)[1]
    if h["own_ports"]:
        return "ephemeral"
    return "none"


def build_records(
    tshark_text: str, pilot: str = "PUC4-R10"
) -> List[Dict[str, Any]]:
    hosts = aggregate_hosts(tshark_text)
    if not hosts:
        return []
    t0 = min(h["first"] for h in hosts.values())
    records = []
    for ip, h in sorted(hosts.items(), key=lambda kv: kv[0]):
        mac = h["macs"].most_common(1)[0][0] if h["macs"] else ""
        vendor = h["vendors"].most_common(1)[0][0] if h["vendors"] else ""
        total_bytes = h["tx_bytes"] + h["rx_bytes"]
        protocols = sorted(h["protocols"])
        records.append(
            {
                "ip": ip,
                "mac": mac or "routed",
                "mac_vendor": vendor or ("unregistered" if mac else "routed"),
                "subnet": ".".join(ip.split(".")[:3]) + ".0/24",
                "scope": _scope(ip, h["ue"]),
                "role": _role(ip, h),
                "service_port": _service_port(h),
                "protocols": ",".join(protocols),
                "protocol_count": len(protocols),
                "packets": h["tx_packets"] + h["rx_packets"],
                "bytes": total_bytes,
                "tx_share": round(h["tx_bytes"] / total_bytes, 2) if total_bytes else 0.0,
                "peer_count": len(h["peers"]),
                "first_seen_s": round(h["first"] - t0, 1),
                "duration_s": round(h["last"] - h["first"], 1),
                "pilot": pilot,
            }
        )
    return records


def records_from_pcap(
    pcap_path: str, pilot: str = "PUC4-R10", cache_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    return build_records(load_rows(pcap_path, cache_path), pilot)
