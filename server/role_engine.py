"""
Evidence-based IP role assessment engine.

Replaced the single-pass if-chain of the former rrc_utils module.
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
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import packet_table
from models import db, PcapFile, IpRole
# Stage 1 and 2 live in role_evidence (shared with the sensor's dpi_agent);
# the names are re-exported here for existing callers and tests.
from role_evidence import (  # noqa: F401
    E2AP_PORTS,
    E2T_PORT,
    GTPU_PORT,
    MONGODB_PORT,
    NGAP_PORT,
    PFCP_CP_SENDS,
    PFCP_UP_SENDS,
    REDIS_PORT,
    SBI_NOTIFY_MARKER,
    SBI_PREFIXES,
    WEBUI_PORTS,
    _BORING_LAYERS,
    _N_FIELDS,
    _SIGNAL_LAYERS,
    _TSHARK_FIELDS,
    IpEvidence,
    PcapObservations,
    _infer_cross_ip,
    _parse_line,
    _tokens,
)

logger = logging.getLogger(__name__)

# Bump on any change to the collector or rule table: cached IpRole rows
# stamped with an older version are discarded and the pcap re-analyzed.
ROLE_ENGINE_VERSION = "2.2.0"


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


def collect_evidence(pcap_file: str) -> PcapObservations:
    """Build per-IP evidence from the shared packet table. Every occurrence of
    a field (all HTTP/2 paths in a frame, inner+outer IPs of GTP-U tunnels)
    arrives as comma-joined tokens."""
    obs = PcapObservations()
    try:
        for line in packet_table.lines(pcap_file, _TSHARK_FIELDS).splitlines():
            if line.strip():
                _parse_line(line, obs)
    except subprocess.TimeoutExpired:
        logger.warning("tshark DPI timed out on %s", pcap_file)
        obs.warnings.append("Role detection timed out reading the capture; roles may be incomplete.")
    except FileNotFoundError:
        logger.error("tshark not found — role assessment unavailable")
        obs.warnings.append("Role detection unavailable: tshark was not found on the server.")
    except Exception as exc:
        logger.exception("DPI error on %s", pcap_file)
        obs.warnings.append(
            f"Role detection failed while reading the capture ({type(exc).__name__}); "
            "roles may be incomplete."
        )

    _infer_cross_ip(obs)
    return obs


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


def _listing(values, limit: int = 3) -> str:
    """Sorted, quoted names for reasoning text, at most `limit` of them."""
    names = sorted(values)
    text = ", ".join(f"'{n}'" for n in names[:limit])
    if len(names) > limit:
        text += f" (+{len(names) - limit} more)"
    return text


def _identity_note(e) -> str:
    """Identities the IP stated about itself in setup messages, for the
    reasoning of whichever role wins (a gNB that is also an E2 node keeps its
    E2 Setup ID)."""
    notes = []
    if e.amf_names:
        notes.append(f"NG Setup AMF name {_listing(e.amf_names)}")
    if e.ran_node_names:
        notes.append(f"NG Setup RAN name {_listing(e.ran_node_names)}")
    if e.e2_node_ids:
        notes.append(f"E2 Setup node {_listing(e.e2_node_ids)}")
    if e.pfcp_node_ids:
        notes.append(f"PFCP Node ID {_listing(e.pfcp_node_ids)}")
    if e.nrf_nf_types:
        notes.append(f"NRF profile type {_listing(e.nrf_nf_types)}")
    return "; ".join(notes)


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


def _rule_nrf_profile(e, obs):
    # Self-declared: an NFProfile (NRF registration or NRF reply) lists this
    # address. Above the traffic-pattern SBI rules, below the rules where the
    # IP terminates a protocol. Conflicting profile types decide nothing.
    if len(e.nrf_nf_types) == 1:
        nf_type = next(iter(e.nrf_nf_types))
        # The type itself is in the identity note added by resolve_roles.
        return (nf_type, 0.93, "An NFProfile in NRF signalling lists this address")


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
        # Function Features name the side, but an EPC SGW-C/SGW-U announces
        # them too, so this stays PFCP_NODE rather than SMF/UPF.
        if e.pfcp_cp_features and not e.pfcp_up_features:
            return ("PFCP_NODE", 0.50, f"PFCP heartbeat/association only ({e.pfcp_peer} msgs) — control-plane side (announces CP Function Features)")
        if e.pfcp_up_features and not e.pfcp_cp_features:
            return ("PFCP_NODE", 0.50, f"PFCP heartbeat/association only ({e.pfcp_peer} msgs) — user-plane side (announces UP Function Features)")
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
    _rule_nrf_profile,
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
        identities = _identity_note(e)
        if identities:
            reasoning += f"; {identities}"
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


def assess_pcap(pcap_file: str, warnings: Optional[List[str]] = None) -> Dict[str, RoleAssessment]:
    """Pure per-pcap analysis: evidence collection + rule resolution. When the
    capture cannot be read completely, user-safe messages are appended to
    `warnings`."""
    logger.info("Role engine %s analyzing %s", ROLE_ENGINE_VERSION, pcap_file)
    obs = collect_evidence(pcap_file)
    if warnings is not None:
        warnings.extend(obs.warnings)
    return resolve_roles(obs)


def roles_as_strings(assessments: Dict[str, RoleAssessment]) -> Dict[str, str]:
    return {ip: a.role for ip, a in assessments.items()}


def get_or_compute_roles(
    pcap_file: str, warnings: Optional[List[str]] = None
) -> Dict[str, RoleAssessment]:
    """
    Version-checked DB cache around assess_pcap. Falls back to pure
    analysis when there is no app context (background threads).
    Roles from an incompletely read capture are returned with `warnings`
    filled in, and are not cached.
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

    found_warnings: List[str] = []
    assessments = assess_pcap(pcap_file, warnings=found_warnings)
    if warnings is not None:
        warnings.extend(found_warnings)

    if pcap_record and assessments and not found_warnings:
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
