"""
Evidence-based IP role assessment engine.

Replaces the single-pass if-chain in rrc_utils.get_comprehensive_ip_roles.
Works in two stages over one tshark field-extraction pass:

  1. collect_evidence(): per-IP, direction-aware evidence counters
     (who terminates NGAP on 38412, who answers PFCP session requests,
     which SBI API prefixes an IP serves, GTP-U tunnel endpoints, ...).
  2. resolve_roles(): a declarative rule table scores the evidence into a
     single best role per IP with a confidence value and a human-readable
     reasoning string; other matching roles are reported as runner-ups.

Direction rules are anchored on protocol semantics rather than packet
order, so a request and its response reinforce the same labels instead of
flipping them (the main defect of the previous engine):
  - NGAP / E2AP: the side owning the well-known SCTP listener port
    (38412 / 36421-36422) is the AMF / RIC.
  - PFCP: both sides use UDP 8805, so direction comes from the message
    type (Session Establishment/Modification/Deletion Request = CP side).
  - SBI (HTTP/2): the destination of a frame carrying a matching ":path"
    header serves that NF API. NRF status-notify callbacks are excluded —
    in Open5GS every NF serves /nnrf-nfm/v1/nf-status-notify.
Frames containing ICMP are skipped entirely: ICMP errors quote the
offending packet, which shows up as a second, direction-reversed set of
field values on the same line.
"""

import ipaddress
import logging
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from models import db, PcapFile, IpRole

logger = logging.getLogger(__name__)

# Bump on any change to the collector or rule table: cached IpRole rows
# stamped with an older version are discarded and the pcap re-analyzed.
ROLE_ENGINE_VERSION = "2.0.0"

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


@dataclass
class PcapObservations:
    """Everything collect_evidence() learned about one pcap."""

    evidence: Dict[str, IpEvidence] = field(default_factory=dict)
    # (outer_src, outer_dst, inner_src, inner_dst) per GTP-U packet
    gtpu_flows: List[Tuple[str, str, Optional[str], Optional[str]]] = field(
        default_factory=list
    )
    redis_clients: Set[str] = field(default_factory=set)
    e2t_clients: Set[str] = field(default_factory=set)

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


@dataclass
class RoleAssessment:
    ip: str
    role: str
    confidence: float
    reasoning: str
    runner_ups: List[Tuple[str, float]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Stage 1: evidence collection (single tshark pass)
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


def _build_tshark_cmd(pcap_file: str) -> List[str]:
    cmd = ["tshark", "-r", pcap_file, "-T", "fields"]
    for f in _TSHARK_FIELDS:
        cmd += ["-e", f]
    # Tab separator: cannot appear inside header values. occurrence=a +
    # aggregator=, exposes every occurrence (all HTTP/2 paths in a frame,
    # inner+outer IPs of GTP-U tunnels) as comma-joined tokens.
    cmd += ["-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]
    return cmd


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
        obs.gtpu_flows.append((outer_src, outer_dst, inner_src, inner_dst))
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


def collect_evidence(pcap_file: str, timeout: int = 60) -> PcapObservations:
    """Run the single tshark pass and build per-IP evidence."""
    obs = PcapObservations()
    try:
        proc = subprocess.run(
            _build_tshark_cmd(pcap_file),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        for line in proc.stdout.splitlines():
            if line.strip():
                _parse_line(line, obs)
    except subprocess.TimeoutExpired:
        logger.warning("tshark DPI timed out on %s", pcap_file)
    except FileNotFoundError:
        logger.error("tshark not found — role assessment unavailable")
    except Exception:
        logger.exception("DPI error on %s", pcap_file)

    _infer_cross_ip(obs)
    return obs


def _infer_cross_ip(obs: PcapObservations) -> None:
    """Stage-2 inference that needs the whole capture, not single packets."""
    upf_ips = obs.upf_ips

    # PFCP-confirmed UPFs anchor GTP-U direction: the inner address on the
    # UE side of the tunnel is the UE; the outer peer is the RAN user plane.
    for outer_src, outer_dst, inner_src, inner_dst in obs.gtpu_flows:
        if outer_dst in upf_ips:  # uplink
            if inner_src:
                obs.ev(inner_src).inner_uplink_src += 1
            if outer_src not in upf_ips:
                obs.ev(outer_src).gtpu_ran_side += 1
        if outer_src in upf_ips:  # downlink
            if inner_dst:
                obs.ev(inner_dst).inner_uplink_src += 1
            if outer_dst not in upf_ips:
                obs.ev(outer_dst).gtpu_ran_side += 1

    # An IP that is a client of both the RIC-internal Redis and the E2
    # Termination is the RIC platform side — only meaningful when the
    # capture actually contains E2 activity.
    common = obs.redis_clients & obs.e2t_clients
    if common and obs.has_e2_context:
        obs.ev(sorted(common)[0]).ric_client = True


# ---------------------------------------------------------------------------
# Stage 3: declarative rules
# ---------------------------------------------------------------------------
# Each rule inspects one IP's evidence (plus capture context) and returns
# (role, confidence, reasoning) or None. All matches are collected; the
# highest confidence wins (earlier table position breaks ties) and the rest
# are reported as runner-ups.

def _ip_is(ip: str, check: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return getattr(addr, check)


def _rule_amf(e, obs):
    if e.ngap_amf_side:
        return ("AMF", 0.95, f"Terminates NGAP on SCTP {NGAP_PORT} ({e.ngap_amf_side} pkts)")


def _rule_gnb_ngap(e, obs):
    if e.ngap_ran_side:
        why = f"Initiates NGAP toward AMF:{NGAP_PORT} ({e.ngap_ran_side} pkts"
        if e.ngap_ue_assoc:
            why += f", incl. {e.ngap_ue_assoc} UE-associated msgs"
        return ("gNB", 0.95, why + ")")


def _rule_smf(e, obs):
    if e.pfcp_smf_side:
        return ("SMF", 0.95, f"PFCP session control-plane side ({e.pfcp_smf_side} msgs)")


def _rule_upf(e, obs):
    if e.pfcp_upf_side:
        return ("UPF", 0.95, f"PFCP session user-plane side ({e.pfcp_upf_side} msgs)")


def _rule_ric_e2(e, obs):
    if e.e2_ric_side:
        return ("NEAR_RT_RIC", 0.95, f"Terminates E2AP on SCTP {'/'.join(sorted(E2AP_PORTS))} ({e.e2_ric_side} pkts)")


def _rule_e2node(e, obs):
    if e.e2_node_side:
        return ("E2_NODE", 0.95, f"Initiates E2AP toward the RIC ({e.e2_node_side} pkts)")


def _rule_scp(e, obs):
    if len(e.sbi_prefixes_served) >= 2:
        served = ", ".join(sorted(e.sbi_prefixes_served))
        return ("SCP", 0.92, f"Serves multiple SBI APIs ({served}) — indirect-communication proxy")


def _rule_sbi_nf(e, obs):
    if len(e.sbi_prefixes_served) == 1:
        prefix = next(iter(e.sbi_prefixes_served))
        role = SBI_PREFIXES[prefix]
        return (role, 0.90, f"Serves SBI API {prefix}-* ({role} service)")


def _rule_gnb_gtpu(e, obs):
    if e.gtpu_ran_side:
        return ("gNB", 0.70, f"GTP-U user-plane peer of a PFCP-confirmed UPF ({e.gtpu_ran_side} pkts)")


def _rule_e2t(e, obs):
    if e.server_ports[E2T_PORT]:
        return ("E2T", 0.60, f"Listens on TCP {E2T_PORT} (E2 Termination)")


def _rule_ric_client(e, obs):
    if e.ric_client:
        return ("NEAR_RT_RIC", 0.60, f"Client of both RIC Redis ({REDIS_PORT}) and E2T ({E2T_PORT})")


def _rule_redis(e, obs):
    if e.server_ports[REDIS_PORT]:
        if obs.has_e2_context:
            return ("REDIS", 0.60, f"Listens on TCP {REDIS_PORT} within an O-RAN RIC deployment")
        return ("INFRA_REDIS", 0.60, f"Listens on TCP {REDIS_PORT} (Redis); no O-RAN context in capture")


def _rule_mongodb(e, obs):
    if e.server_ports[MONGODB_PORT]:
        return ("OPEN5GS_INFRA", 0.60, f"Listens on TCP {MONGODB_PORT} (MongoDB — Open5GS subscriber DB)")


def _rule_webui(e, obs):
    for port in WEBUI_PORTS:
        if e.server_ports[port]:
            return ("OPEN5GS_INFRA", 0.60, f"Listens on TCP {port} (Open5GS WebUI)")


def _rule_ue_gtpu(e, obs):
    if e.inner_uplink_src:
        return ("UE", 0.60, f"Inner GTP-U address exchanging traffic through a UPF ({e.inner_uplink_src} pkts)")


def _rule_ue_rrc(e, obs):
    if e.rrc_raw:
        return ("UE", 0.55, f"Endpoint of raw NR-RRC signalling ({e.rrc_raw} pkts)")


def _rule_ue_inner_private(e, obs):
    if e.inner_only and _ip_is(e.ip, "is_private") and not obs.upf_ips:
        return ("UE", 0.45, "Private address seen only inside GTP-U tunnels")


def _rule_dn_inner_public(e, obs):
    if e.inner_only and _ip_is(e.ip, "is_global"):
        return ("External/DN", 0.50, "Public address seen only inside GTP-U tunnels (data-network endpoint)")


def _rule_pfcp_node(e, obs):
    if e.pfcp_peer and not e.pfcp_smf_side and not e.pfcp_upf_side:
        return ("PFCP_NODE", 0.40, f"PFCP heartbeat/association only ({e.pfcp_peer} msgs) — CP/UP side unknown")


def _rule_dn_plain(e, obs):
    if (
        e.seen_as_outer
        and obs.upf_ips
        and not _ip_is(e.ip, "is_loopback")
        and not (e.protocols & _SIGNAL_LAYERS)
        and not e.sbi_prefixes_served
        and not any(e.server_ports[p] for p in (REDIS_PORT, E2T_PORT, MONGODB_PORT, *WEBUI_PORTS))
    ):
        return ("External/DN", 0.40, "Plain-traffic endpoint with no core-network signalling")


RULES = [
    _rule_amf,
    _rule_gnb_ngap,
    _rule_smf,
    _rule_upf,
    _rule_ric_e2,
    _rule_e2node,
    _rule_scp,
    _rule_sbi_nf,
    _rule_gnb_gtpu,
    _rule_e2t,
    _rule_ric_client,
    _rule_redis,
    _rule_mongodb,
    _rule_webui,
    _rule_ue_gtpu,
    _rule_ue_rrc,
    _rule_ue_inner_private,
    _rule_dn_inner_public,
    _rule_pfcp_node,
    _rule_dn_plain,
]


def resolve_roles(obs: PcapObservations) -> Dict[str, RoleAssessment]:
    """Apply the rule table to every observed IP."""
    assessments: Dict[str, RoleAssessment] = {}
    for ip, e in obs.evidence.items():
        matches = []
        for rule in RULES:
            result = rule(e, obs)
            if result:
                matches.append(result)

        if not matches:
            seen = ", ".join(sorted(e.protocols)) or "no traffic"
            assessments[ip] = RoleAssessment(
                ip=ip,
                role="Unidentified",
                confidence=0.0,
                reasoning=f"No matching evidence ({seen} seen)",
            )
            continue

        # Highest confidence wins; table order breaks ties.
        best = max(matches, key=lambda m: m[1])
        role, confidence, reasoning = best
        runner_ups = [(r, c) for r, c, _ in matches if r != role]
        if runner_ups:
            also = ", ".join(f"{r} ({c:.2f})" for r, c in runner_ups)
            reasoning += f"; also matched: {also}"
        assessments[ip] = RoleAssessment(
            ip=ip,
            role=role,
            confidence=confidence,
            reasoning=reasoning,
            runner_ups=runner_ups,
        )
    return assessments


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def assess_pcap(pcap_file: str) -> Dict[str, RoleAssessment]:
    """Pure per-pcap analysis: evidence collection + rule resolution."""
    logger.info("Role engine %s analyzing %s", ROLE_ENGINE_VERSION, pcap_file)
    return resolve_roles(collect_evidence(pcap_file))


def roles_as_strings(assessments: Dict[str, RoleAssessment]) -> Dict[str, str]:
    return {ip: a.role for ip, a in assessments.items()}


def get_or_compute_roles(pcap_file: str) -> Dict[str, RoleAssessment]:
    """
    Version-checked DB cache around assess_pcap. Falls back to pure
    analysis when there is no app context (background threads).
    """
    pcap_record = None
    try:
        pcap_record = PcapFile.query.filter_by(file_path=pcap_file).first()
        if pcap_record:
            rows = IpRole.query.filter_by(pcap_id=pcap_record.id).all()
            if rows and all(r.engine_version == ROLE_ENGINE_VERSION for r in rows):
                logger.info("Loaded %d roles from database cache", len(rows))
                return {
                    r.ip_address: RoleAssessment(
                        ip=r.ip_address,
                        role=r.role,
                        confidence=r.confidence or 0.0,
                        reasoning=r.reasoning or "",
                    )
                    for r in rows
                }
    except Exception as e:
        # Expected in background threads without app context
        logger.debug("Database lookup skipped (no app context): %s", e)
        pcap_record = None

    assessments = assess_pcap(pcap_file)

    if pcap_record and assessments:
        try:
            # Delete-before-insert: clears stale-version rows and prevents
            # duplicates when the same pcap is analyzed twice.
            IpRole.query.filter_by(pcap_id=pcap_record.id).delete()
            db.session.bulk_save_objects(
                [
                    IpRole(
                        pcap_id=pcap_record.id,
                        ip_address=ip,
                        role=a.role,
                        confidence=a.confidence,
                        reasoning=a.reasoning,
                        engine_version=ROLE_ENGINE_VERSION,
                    )
                    for ip, a in assessments.items()
                ]
            )
            db.session.commit()
            logger.info(
                "Cached %d roles to database (engine %s)",
                len(assessments),
                ROLE_ENGINE_VERSION,
            )
        except Exception:
            logger.exception("Failed to cache roles to database")
            db.session.rollback()

    return assessments
