"""
Per-IP evidence for the role engine: what one tshark field line says about
the IPs in it, collected without Flask or the database so the same code runs
in the backend (role_engine, over a capture's packet table) and at the sensor
(dpi_agent, over live tshark output).

Stage 1 (_parse_line) only adds counters, so observations from separate
windows can be serialized (to_dict / from_dict) and merged before stage 2
(_infer_cross_ip), which needs the whole set at once. Observations are not
merged or serialized after stage 2: its counters would be counted twice.
See role_engine for the direction rules behind the counters.
"""

from collections import Counter
from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Set

# Version of the to_dict() layout. Bump it when a change would make an older
# backend read newer sensor output wrongly (adding a counter does not:
# from_dict ignores unknown counters and defaults missing ones).
EVIDENCE_FORMAT = 1

NGAP_PORT = "38412"                 # SCTP, AMF listens
E2AP_PORTS = {"36421", "36422"}     # SCTP, Near-RT RIC (E2 Termination) listens
GTPU_PORT = "2152"                  # UDP, GTP-U user plane

# PFCP message-type direction semantics (TS 29.244). Only session-level
# messages are direction-safe; heartbeat/association can be initiated by
# either side and only prove "PFCP node".
PFCP_CP_SENDS = {"50", "52", "54", "57"}  # Session Est/Mod/Del Request, Session Report Response
PFCP_UP_SENDS = {"51", "53", "55", "56"}  # Session Est/Mod/Del Response, Session Report Request

SBI_PREFIXES = {
    "/namf": "AMF",
    "/nsmf": "SMF",
    "/nudm": "UDM",
    "/nnrf": "NRF",
    "/nausf": "AUSF",
    "/npcf": "PCF",
    "/nnef": "NEF",
    "/nscp": "SCP",
    "/nbsf": "BSF",
    "/nudr": "UDR",
    "/nudsf": "UDSF",
}
# Served by every Open5GS NF (NRF subscription callback) — not a role signal.
SBI_NOTIFY_MARKER = "nf-status-notify"

REDIS_PORT = "6379"
E2T_PORT = "38000"
MONGODB_PORT = "27017"
WEBUI_PORTS = {"9999", "3000"}

# Layers too generic to mention in "Unidentified" reasoning.
_BORING_LAYERS = {"sll", "eth", "ethertype", "ip", "ipv6", "frame", "data"}
# Layers that count as core-network signalling for the External/DN rule.
_SIGNAL_LAYERS = {"ngap", "e2ap", "pfcp", "http2", "gtp", "nr-rrc", "nas-5gs"}


@dataclass
class IpEvidence:
    """Direction-aware observation counters for one IP address."""

    ip: str
    ngap_amf_side: int = 0      # NGAP endpoint owning SCTP 38412
    ngap_ran_side: int = 0      # NGAP peer of the 38412 owner
    ngap_ue_assoc: int = 0      # RAN-side packets carrying a RAN_UE_NGAP_ID
    e2_ric_side: int = 0        # E2AP endpoint owning SCTP 36421/36422
    e2_node_side: int = 0
    pfcp_smf_side: int = 0      # sender of CP-only / receiver of UP-only msgs
    pfcp_upf_side: int = 0
    pfcp_peer: int = 0          # heartbeat/association only — side unknown
    sbi_prefixes_served: Set[str] = field(default_factory=set)
    sbi_client: int = 0
    gtpu_outer: int = 0         # outer endpoint of GTP-U tunnels
    gtpu_ran_side: int = 0      # stage 2: GTP-U peer of a PFCP-confirmed UPF
    inner_src_count: int = 0    # seen as inner src of a GTP-U packet
    inner_dst_count: int = 0
    inner_uplink_src: int = 0   # stage 2: inner IP on the UE side of a UPF tunnel
    seen_as_outer: bool = False
    ric_client: bool = False    # stage 2: talks to both RIC Redis and E2T
    rrc_raw: int = 0            # endpoint of NR-RRC *not* encapsulated in NGAP
    server_ports: Counter = field(default_factory=Counter)  # tcp dst-ports seen
    protocols: Set[str] = field(default_factory=set)
    peers: Set[str] = field(default_factory=set)
    total_pkts: int = 0

    @property
    def inner_only(self) -> bool:
        return not self.seen_as_outer and (self.inner_src_count + self.inner_dst_count) > 0

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe form: sets become sorted lists, Counters plain dicts."""
        out: Dict[str, Any] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if isinstance(value, Counter):
                value = dict(sorted(value.items()))
            elif isinstance(value, set):
                value = sorted(value)
            out[f.name] = value
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IpEvidence":
        ev = cls(ip=data["ip"])
        for f in fields(ev):
            if f.name == "ip" or f.name not in data:
                continue
            current = getattr(ev, f.name)
            value = data[f.name]
            if isinstance(current, Counter):
                value = Counter({str(k): int(v) for k, v in value.items()})
            elif isinstance(current, set):
                value = set(value)
            elif isinstance(current, bool):
                value = bool(value)
            else:
                value = int(value)
            setattr(ev, f.name, value)
        return ev

    def merge(self, other: "IpEvidence") -> None:
        """Add another observation of the same IP: counters add up, sets and
        flags combine."""
        if other.ip != self.ip:
            raise ValueError(f"cannot merge evidence of {other.ip} into {self.ip}")
        for f in fields(self):
            if f.name == "ip":
                continue
            mine, theirs = getattr(self, f.name), getattr(other, f.name)
            if isinstance(mine, Counter):
                mine.update(theirs)
            elif isinstance(mine, set):
                mine.update(theirs)
            elif isinstance(mine, bool):
                setattr(self, f.name, mine or theirs)
            else:
                setattr(self, f.name, mine + theirs)


@dataclass
class PcapObservations:
    """Everything collect_evidence() learned about one pcap (or, at the
    sensor, about one window of live traffic)."""

    evidence: Dict[str, IpEvidence] = field(default_factory=dict)
    # Packets per (outer_src, outer_dst, inner_src, inner_dst) GTP-U flow.
    # A count rather than one entry per packet keeps live windows small.
    gtpu_flows: Counter = field(default_factory=Counter)
    redis_clients: Set[str] = field(default_factory=set)
    e2t_clients: Set[str] = field(default_factory=set)
    # User-safe messages when the capture could not be read completely; the
    # roles are then based on partial (or no) evidence.
    warnings: List[str] = field(default_factory=list)
    # Set by _infer_cross_ip. Inferred observations are final: merging or
    # serializing them would count the stage-2 counters twice.
    inferred: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe form of stage-1 observations (see EVIDENCE_FORMAT)."""
        if self.inferred:
            raise ValueError("serialize observations before _infer_cross_ip, not after")
        return {
            "format": EVIDENCE_FORMAT,
            "evidence": {ip: e.to_dict() for ip, e in self.evidence.items()},
            "gtpu_flows": [[*key, n] for key, n in self.gtpu_flows.items()],
            "redis_clients": sorted(self.redis_clients),
            "e2t_clients": sorted(self.e2t_clients),
            "warnings": list(self.warnings),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PcapObservations":
        if data.get("format") != EVIDENCE_FORMAT:
            raise ValueError(
                f"unsupported evidence format {data.get('format')!r} "
                f"(this side reads format {EVIDENCE_FORMAT})"
            )
        obs = cls()
        for ip, e in data.get("evidence", {}).items():
            obs.evidence[ip] = IpEvidence.from_dict({**e, "ip": ip})
        for outer_src, outer_dst, inner_src, inner_dst, n in data.get("gtpu_flows", []):
            obs.gtpu_flows[(outer_src, outer_dst, inner_src, inner_dst)] += int(n)
        obs.redis_clients = set(data.get("redis_clients", []))
        obs.e2t_clients = set(data.get("e2t_clients", []))
        obs.warnings = list(data.get("warnings", []))
        return obs

    def merge(self, other: "PcapObservations") -> None:
        """Add another window's stage-1 observations to this one."""
        if self.inferred or other.inferred:
            raise ValueError("merge observations before _infer_cross_ip, not after")
        for ip, e in other.evidence.items():
            if ip in self.evidence:
                self.evidence[ip].merge(e)
            else:
                self.evidence[ip] = IpEvidence.from_dict(e.to_dict())  # a copy
        self.gtpu_flows.update(other.gtpu_flows)
        self.redis_clients |= other.redis_clients
        self.e2t_clients |= other.e2t_clients
        self.warnings.extend(w for w in other.warnings if w not in self.warnings)

    def ev(self, ip: str) -> IpEvidence:
        if ip not in self.evidence:
            self.evidence[ip] = IpEvidence(ip=ip)
        return self.evidence[ip]

    @property
    def has_e2_context(self) -> bool:
        """True when the capture contains any O-RAN E2 activity."""
        return bool(self.e2t_clients) or any(
            e.e2_ric_side or e.e2_node_side for e in self.evidence.values()
        )

    @property
    def upf_ips(self) -> Set[str]:
        return {ip for ip, e in self.evidence.items() if e.pfcp_upf_side > 0}


# ---------------------------------------------------------------------------
# Stage 1: evidence from one tshark field line
# ---------------------------------------------------------------------------

_TSHARK_FIELDS = [
    "ip.src",               # 0  (comma-joined "outer,inner" on tunneled frames)
    "ip.dst",               # 1
    "frame.protocols",      # 2
    "sctp.srcport",         # 3
    "sctp.dstport",         # 4
    "udp.srcport",          # 5
    "udp.dstport",          # 6
    "tcp.dstport",          # 7
    "ngap.procedureCode",   # 8
    "ngap.RAN_UE_NGAP_ID",  # 9
    "e2ap.procedureCode",   # 10
    "pfcp.msg_type",        # 11
    "http2.headers.path",   # 12
]
_N_FIELDS = len(_TSHARK_FIELDS)



def _tokens(col: str) -> List[str]:
    return [t for t in col.split(",") if t] if col else []



def _parse_line(line: str, obs: PcapObservations) -> None:
    parts = line.split("\t")
    if len(parts) < _N_FIELDS:
        parts += [""] * (_N_FIELDS - len(parts))

    src_tokens = _tokens(parts[0])
    dst_tokens = _tokens(parts[1])
    if not src_tokens or not dst_tokens:
        return  # non-IPv4 frame

    protocols = set(parts[2].split(":")) if parts[2] else set()
    if "icmp" in protocols or "icmpv6" in protocols:
        # ICMP errors quote the offending packet: the quoted headers appear
        # as extra, direction-reversed tokens. No reliable evidence here.
        return

    outer_src, outer_dst = src_tokens[0], dst_tokens[0]
    src_ev, dst_ev = obs.ev(outer_src), obs.ev(outer_dst)
    for e, peer in ((src_ev, outer_dst), (dst_ev, outer_src)):
        e.seen_as_outer = True
        e.total_pkts += 1
        e.peers.add(peer)
        e.protocols.update(protocols - _BORING_LAYERS)

    sctp_ports = set(_tokens(parts[3])) | set(_tokens(parts[4]))
    sctp_dst = set(_tokens(parts[4]))
    udp_ports = set(_tokens(parts[5])) | set(_tokens(parts[6]))
    tcp_dst = _tokens(parts[7])

    # --- NGAP: the owner of SCTP 38412 is the AMF ---
    # (NGAP also appears embedded in SBI multipart bodies over TCP; the
    # SCTP-port requirement keeps those from producing evidence.)
    if parts[8] and NGAP_PORT in sctp_ports:
        amf_ev, ran_ev = (dst_ev, src_ev) if NGAP_PORT in sctp_dst else (src_ev, dst_ev)
        amf_ev.ngap_amf_side += 1
        ran_ev.ngap_ran_side += 1
        if parts[9]:  # UE-associated signalling
            ran_ev.ngap_ue_assoc += 1

    # --- E2AP: the owner of SCTP 36421/36422 is the Near-RT RIC ---
    if parts[10] and (E2AP_PORTS & sctp_ports):
        ric_ev, node_ev = (
            (dst_ev, src_ev) if (E2AP_PORTS & sctp_dst) else (src_ev, dst_ev)
        )
        ric_ev.e2_ric_side += 1
        node_ev.e2_node_side += 1

    # --- PFCP: direction from session-level message types ---
    for mt in _tokens(parts[11]):
        if mt in PFCP_CP_SENDS:
            src_ev.pfcp_smf_side += 1
            dst_ev.pfcp_upf_side += 1
        elif mt in PFCP_UP_SENDS:
            src_ev.pfcp_upf_side += 1
            dst_ev.pfcp_smf_side += 1
        else:  # heartbeat / association — either side may initiate
            src_ev.pfcp_peer += 1
            dst_ev.pfcp_peer += 1

    # --- SBI (HTTP/2): dst of a frame carrying :path serves that API ---
    for path in _tokens(parts[12]):
        if SBI_NOTIFY_MARKER in path:
            continue  # NRF callback endpoint — every NF serves this
        for prefix in SBI_PREFIXES:
            if path.startswith(prefix):
                dst_ev.sbi_prefixes_served.add(prefix)
                src_ev.sbi_client += 1
                break

    # --- GTP-U: outer endpoints + inner (tunneled) addresses ---
    if "gtp" in protocols and GTPU_PORT in udp_ports:
        inner_src = src_tokens[1] if len(src_tokens) > 1 else None
        inner_dst = dst_tokens[1] if len(dst_tokens) > 1 else None
        obs.gtpu_flows[(outer_src, outer_dst, inner_src, inner_dst)] += 1
        src_ev.gtpu_outer += 1
        dst_ev.gtpu_outer += 1
        if inner_src:
            obs.ev(inner_src).inner_src_count += 1
        if inner_dst:
            obs.ev(inner_dst).inner_dst_count += 1

    # --- Raw NR-RRC (not NGAP-encapsulated) points at UE-facing links ---
    if "nr-rrc" in protocols and "ngap" not in protocols:
        src_ev.rrc_raw += 1
        dst_ev.rrc_raw += 1

    # --- TCP services: track listener-side ports of interest ---
    for port in tcp_dst:
        dst_ev.server_ports[port] += 1
        if port == REDIS_PORT:
            obs.redis_clients.add(outer_src)
        elif port == E2T_PORT:
            obs.e2t_clients.add(outer_src)


# ---------------------------------------------------------------------------
# Stage 2: inference across IPs
# ---------------------------------------------------------------------------


def _infer_cross_ip(obs: PcapObservations) -> None:
    """Stage-2 inference that needs the whole capture, not single packets.
    Runs once per observation set; afterwards it can no longer be merged."""
    if obs.inferred:
        raise ValueError("_infer_cross_ip already ran on these observations")
    obs.inferred = True
    upf_ips = obs.upf_ips

    # PFCP-confirmed UPFs anchor GTP-U direction: the inner address on the
    # UE side of the tunnel is the UE; the outer peer is the RAN user plane.
    for (outer_src, outer_dst, inner_src, inner_dst), n in obs.gtpu_flows.items():
        if outer_dst in upf_ips:  # uplink
            if inner_src:
                obs.ev(inner_src).inner_uplink_src += n
            if outer_src not in upf_ips:
                obs.ev(outer_src).gtpu_ran_side += n
        if outer_src in upf_ips:  # downlink
            if inner_dst:
                obs.ev(inner_dst).inner_uplink_src += n
            if outer_dst not in upf_ips:
                obs.ev(outer_dst).gtpu_ran_side += n

    # An IP that is a client of both the RIC-internal Redis and the E2
    # Termination is the RIC platform side — only meaningful when the
    # capture actually contains E2 activity.
    common = obs.redis_clients & obs.e2t_clients
    if common and obs.has_e2_context:
        obs.ev(sorted(common)[0]).ric_client = True
