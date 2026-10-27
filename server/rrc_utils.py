import subprocess
import logging
import os
from typing import List, Tuple, Optional, Dict, Any

from role_engine import get_or_compute_roles, roles_as_strings

logger = logging.getLogger(__name__)


##
# Only the fields PacketProcessor turns into ML features. A single
# `-T fields` pass stays at a few MB / seconds even for 100k+ packet captures;
# the old `-T json -V` dump was ~6 KB per packet and timed out on large files.
_FEATURE_FIELDS = ["frame.time_epoch", "frame.len", "frame.protocols", "ip.src"]
FEATURE_CACHE_SUFFIX = ".features.tsv"
_TSHARK_TIMEOUT = 300


def _packet_src_ip(protocols: List[str], src_tokens: List[str]) -> str:
    """
    Picks the packet's own source IP from every ip.src occurrence: the last
    IP header (the inner one on GTP-U frames), but never one quoted inside an
    ICMP error. Matches what the previous JSON-based extraction produced.
    """
    if "icmp" in protocols:
        own_headers = protocols[: protocols.index("icmp")].count("ip")
        if 0 < own_headers <= len(src_tokens):
            return src_tokens[own_headers - 1]
    return src_tokens[-1]


def _parse_feature_lines(output: str) -> List[Dict[str, Any]]:
    records = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < len(_FEATURE_FIELDS) or not parts[3]:
            continue  # non-IPv4 frame
        protocols = parts[2].split(":") if parts[2] else []
        try:
            records.append(
                {
                    "timestamp": float(parts[0] or 0),
                    "src_ip": _packet_src_ip(protocols, parts[3].split(",")),
                    "packet_len": int(parts[1] or 0),
                    "protocol": protocols[-1] if protocols else "Unknown",
                }
            )
        except ValueError:
            continue
    return records


def _run_tshark_and_load_packets(pcap_file: str) -> Optional[List[Dict[str, Any]]]:
    """
    Runs one tshark field pass and returns a feature record per IPv4 frame:
    {"timestamp", "src_ip", "packet_len", "protocol"}. The raw tshark output
    is cached next to the pcap so repeated analyses skip tshark.
    """
    cache_path = pcap_file + FEATURE_CACHE_SUFFIX
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                return _parse_feature_lines(f.read())
        except OSError:
            pass

    cmd = ["tshark", "-r", pcap_file, "-T", "fields"]
    for field in _FEATURE_FIELDS:
        cmd += ["-e", field]
    # Every ip.src occurrence (outer, GTP-U inner, ICMP-quoted) comma-joined;
    # _packet_src_ip picks the right one.
    cmd += ["-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_TSHARK_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        logger.error("tshark timed out after %ds on %s", _TSHARK_TIMEOUT, pcap_file)
        return None
    except FileNotFoundError:
        logger.error("tshark not found on PATH — cannot load packets")
        return None

    if result.returncode != 0:
        if not result.stdout:
            logger.error(
                "tshark failed on %s (exit %d): %s",
                pcap_file, result.returncode, result.stderr.strip(),
            )
            return None
        # e.g. exit 14 "cut short in the middle of a packet": every complete
        # packet was still read, so the output is usable.
        logger.warning(
            "tshark exit %d on %s, using partial output: %s",
            result.returncode, pcap_file, result.stderr.strip(),
        )

    try:
        with open(cache_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)
    except OSError:
        logger.warning("Could not write feature cache %s", cache_path)

    return _parse_feature_lines(result.stdout)


def get_cached_packets(pcap_file: str) -> Optional[List[Dict[str, Any]]]:
    return _run_tshark_and_load_packets(pcap_file)


##
# Role identification is delegated to the evidence-based engine in
# role_engine.py (direction-aware rules, confidence, reasoning, versioned
# DB cache). This wrapper keeps the legacy string-dict interface.
def get_comprehensive_ip_roles(pcap_file: str) -> Dict[str, str]:
    """Analyzes the PCAP to identify IP roles. Returns {ip: role}."""
    return roles_as_strings(get_or_compute_roles(pcap_file))


# --- Helper functions that reuse the main logic to avoid re-running TShark ---


def recognize_core_ips(pcap_file: str) -> Tuple[Optional[str], Optional[str]]:
    roles = get_comprehensive_ip_roles(pcap_file)
    gnb = next((ip for ip, role in roles.items() if role == "gNB"), None)
    amf = next((ip for ip, role in roles.items() if role == "AMF"), None)
    return gnb, amf


def get_gnb_ip(pcap_file: str) -> Optional[str]:
    gnb, _ = recognize_core_ips(pcap_file)
    return gnb


def get_amf_ip(pcap_file: str) -> Optional[str]:
    _, amf = recognize_core_ips(pcap_file)
    return amf


def recognize_oran_ips_roles(pcap_file: str) -> Dict[str, Optional[str]]:
    # This is now handled inside get_comprehensive_ip_roles
    # We return a dummy dict or re-parse if absolutely necessary for legacy support
    # Ideally, refactor calling code to use get_comprehensive_ip_roles directly.
    roles = get_comprehensive_ip_roles(pcap_file)
    return {
        "e2t_ip": next((k for k, v in roles.items() if v == "E2T"), None),
        "redis_ip": next(
            (k for k, v in roles.items() if v in ("REDIS", "INFRA_REDIS")), None
        ),
        "ric_client_ip": next(
            (k for k, v in roles.items() if v == "NEAR_RT_RIC"), None
        ),
        "e2_node_ip": next((k for k, v in roles.items() if v == "E2_NODE"), None),
    }


def get_e2t_ip(pcap_file: str) -> Optional[str]:
    return recognize_oran_ips_roles(pcap_file).get("e2t_ip")


def get_redis_ip(pcap_file: str) -> Optional[str]:
    return recognize_oran_ips_roles(pcap_file).get("redis_ip")


def get_ric_client_ip(pcap_file: str) -> Optional[str]:
    return recognize_oran_ips_roles(pcap_file).get("ric_client_ip")


def get_e2_node_ip(pcap_file: str) -> Optional[str]:
    return recognize_oran_ips_roles(pcap_file).get("e2_node_ip")
