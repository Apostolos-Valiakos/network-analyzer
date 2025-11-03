import subprocess
import json
from typing import List, Tuple, Optional, Dict, Any

##
# Global cache to store packets for each pcap file.
# This avoids re-running tshark for the same file multiple times during a session.
_packet_cache: Dict[str, Optional[List[Dict[str, Any]]]] = {}

##
# Runs tshark on a PCAP file and loads the resulting JSON output into memory.
# It handles errors from tshark execution and JSON decoding.
#
# @param [str] pcap_file The path to the PCAP file.
# @return [List[Dict[str, Any]]|None] A list of packet dictionaries (tshark JSON format) or None if loading fails.
def _run_tshark_and_load_packets(pcap_file: str) -> Optional[List[Dict[str, Any]]]:
    """Runs tshark and loads the JSON output, handling errors."""
    # Check if packets are already cached for this pcap_file
    if pcap_file in _packet_cache:
        return _packet_cache[pcap_file]

    cmd = [
        "tshark", "-r", pcap_file, "-T", "json", "-V"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        packets = json.loads(result.stdout)

        # Export packets to a JSON file (for caching on disk/debugging)
        export_path = pcap_file + ".packets.json"
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(packets, f, indent=2)

        # Cache the packets in memory
        _packet_cache[pcap_file] = packets
        return packets

    except (subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError):
        # Cache None for failed attempts to avoid retrying
        _packet_cache[pcap_file] = None
        return None

##
# Public function to get cached packets, loading them via tshark if they are not already cached.
#
# @param [str] pcap_file The path to the PCAP file.
# @return [List[Dict[str, Any]]|None] A list of packet dictionaries or None if loading fails.
def get_cached_packets(pcap_file: str) -> Optional[List[Dict[str, Any]]]:
    """Public function to get cached packets, loading if necessary."""
    return _run_tshark_and_load_packets(pcap_file)
    
##
# Identifies the gNB and AMF IPs by finding the SCTP association initiation.
# The gNB initiates the connection (SCTP INIT, chunk_type=1) to the AMF over the N2 interface.
# Optimized with tshark fields and display filters.
#
# @param [str] pcap_file The path to the PCAP file.
# @return [Tuple[str|None, str|None]] A tuple containing (gnb_ip, amf_ip) or (None, None) if not found.
def recognize_core_ips(pcap_file: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Identifies the gNB and AMF IPs by finding the SCTP association initiation.
    The gNB initiates the connection (SCTP INIT, chunk_type=1) to the AMF.
    Optimized with tshark fields.
    """
    cmd = [
        "tshark", "-r", pcap_file, "-Y", "sctp.chunk_type == 1",
        "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-c", "1"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout.strip()
        if output:
            # The source IP of the SCTP INIT is the initiator (gNB), and the destination is the receiver (AMF)
            src, dst = output.split("\t")
            return src, dst
        return None, None
    except Exception:
        return None, None

##
# Reads the pcap file and returns the IP address of the gNB.
# The gNB is identified as the initiator (source IP) of the SCTP INIT message.
#
# @param [str] pcap_file The path to the PCAP file.
# @return [str|None] The gNB IP address as a string, or None if not found.
def get_gnb_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of the gNB.
    Returns: The gNB IP address as a string, or None if not found.
    """
    gnb, _ = recognize_core_ips(pcap_file)
    return gnb

##
# Reads the pcap file and returns the IP address of the AMF.
# The AMF is identified as the responder (destination IP) of the SCTP INIT message.
#
# @param [str] pcap_file The path to the PCAP file.
# @return [str|None] The AMF IP address as a string, or None if not found.
def get_amf_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of the AMF.
    Returns: The AMF IP address as a string, or None if not found.
    """
    _, amf = recognize_core_ips(pcap_file)
    return amf

##
# Runs tshark on the given pcap file, extracts unique destination IPs
# from packets that contain NR-RRC, skips consecutive duplicates,
# and **excludes the gNB and AMF IPs**. The remaining IPs are typically UEs.
# Optimized with tshark fields and display filters.
#
# @param [str] pcap_file The path to the PCAP file.
# @return [List[str]] A sorted list of unique IP addresses identified as potential UEs.
def get_unique_rrc_ips(pcap_file: str) -> List[str]:
    """
    Runs tshark on the given pcap file, extracts unique destination IPs
    from packets that contain NR-RRC, skips consecutive duplicates,
    and **excludes the gNB and AMF IPs**.
    Optimized with tshark fields.
    """
    # First, get gNB and AMF to exclude them
    gnb_ip, amf_ip = recognize_core_ips(pcap_file)
    excluded_ips = {ip for ip in (gnb_ip, amf_ip) if ip}

    # Use tshark to filter for RRC and extract destination IPs
    cmd = [
        "tshark", "-r", pcap_file, "-Y", "nr-rrc",
        "-T", "fields", "-e", "ip.dst"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        ips = []
        last_ip = None
        for line in result.stdout.splitlines():
            ip_dst = line.strip()
            # Filter out consecutive duplicates and excluded IPs
            if ip_dst and ip_dst != last_ip and ip_dst not in excluded_ips:
                ips.append(ip_dst)
                last_ip = ip_dst
        return sorted(list(set(ips)))
    except Exception:
        return []

##
# Identifies O-RAN specific IPs (E2T, Redis, RIC Client, E2 Node)
# based on well-known ports and packet communication patterns (e.g., who talks to whom).
# Optimized with tshark fields for specific port communication.
#
# @param [str] pcap_file The path to the PCAP file.
# @return [Dict[str, str|None]] A dictionary mapping O-RAN role keys to their identified IP addresses.
def recognize_oran_ips_roles(pcap_file: str) -> Dict[str, Optional[str]]:
    """
    Identifies O-RAN specific IPs (E2T, Redis, RIC Client, E2 Node)
    based on well-known ports and packet communication patterns.
    Optimized with tshark fields for each port.
    """
    roles: Dict[str, Optional[str]] = {
        "e2t_ip": None,
        "redis_ip": None,
        "ric_client_ip": None,
        "e2_node_ip": None
    }
    
    # 1. Collect for Redis (port 6379 - database server)
    cmd_redis = [
        "tshark", "-r", pcap_file, "-Y", "tcp.dstport == 6379",
        "-T", "fields", "-e", "ip.src", "-e", "ip.dst"
    ]
    ric_client_candidates = set()
    try:
        result = subprocess.run(cmd_redis, capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) == 2:
                ip_src, ip_dst = parts
                # Destination is the Redis server
                if roles["redis_ip"] is None:
                    roles["redis_ip"] = ip_dst
                # Source is a client of Redis (likely RIC Client)
                ric_client_candidates.add(ip_src)
    except Exception:
        pass

    # 2. Collect for E2T (port 38000 - E2 Termination server)
    cmd_e2t = [
        "tshark", "-r", pcap_file, "-Y", "tcp.dstport == 38000",
        "-T", "fields", "-e", "ip.src", "-e", "ip.dst"
    ]
    e2t_client_candidates = set()
    try:
        result = subprocess.run(cmd_e2t, capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) == 2:
                ip_src, ip_dst = parts
                # Destination is the E2T server
                if roles["e2t_ip"] is None:
                    roles["e2t_ip"] = ip_dst
                # Source is a client of E2T (RIC Client or E2 Node)
                e2t_client_candidates.add(ip_src)
    except Exception:
        pass
            
    # 3. Identify Near-RT RIC Component (RIC Client)
    # The RIC Client typically connects to *both* Redis and E2T.
    common_clients = ric_client_candidates.intersection(e2t_client_candidates)
    if len(common_clients) > 0:
        # Take the most likely RIC client (first one found by IP sort order)
        roles["ric_client_ip"] = sorted(list(common_clients))[0]
    elif len(ric_client_candidates) > 0:
        # Fallback: take any client connecting to Redis
        roles["ric_client_ip"] = sorted(list(ric_client_candidates))[0]
            
    # 4. Identify E2 Node
    # An E2 Node is an E2T client that is NOT the established RIC Client.
    ric_ip = roles.get("ric_client_ip")
    final_e2_nodes = e2t_client_candidates - {ric_ip}
    
    if len(final_e2_nodes) > 0:
        # Take the most likely E2 Node (first one found by IP sort order)
        roles["e2_node_ip"] = sorted(list(final_e2_nodes))[0]
            
    return roles

##
# Reads the pcap file and returns the IP address of the E2 Terminator (E2T).
# The E2T is identified as the destination of TCP traffic on port 38000.
#
# @param [str] pcap_file The path to the PCAP file.
# @return [str|None] The E2T IP address as a string, or None if not found.
def get_e2t_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of the E2 Terminator (E2T).
    Returns: The E2T IP address as a string, or None if not found.
    """
    roles = recognize_oran_ips_roles(pcap_file)
    return roles.get("e2t_ip")

##
# Reads the pcap file and returns the IP address of the Redis Database Server.
# Redis is identified as the destination of TCP traffic on port 6379.
#
# @param [str] pcap_file The path to the PCAP file.
# @return [str|None] The Redis IP address as a string, or None if not found.
def get_redis_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of the Redis Database Server.
    Returns: The Redis IP address as a string, or None if not found.
    """
    roles = recognize_oran_ips_roles(pcap_file)
    return roles.get("redis_ip")

##
# Reads the pcap file and returns the IP address of the Near-RT RIC Component (client).
# The RIC Client is identified as the IP connecting to both Redis (6379) and E2T (38000).
#
# @param [str] pcap_file The path to the PCAP file.
# @return [str|None] The RIC Client IP address as a string, or None if not found.
def get_ric_client_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of the Near-RT RIC Component (client).
    Returns: The RIC Client IP address as a string, or None if not found.
    """
    roles = recognize_oran_ips_roles(pcap_file)
    return roles.get("ric_client_ip")

##
# Reads the pcap file and returns the IP address of an E2 Node (gNB/O-CU/O-DU).
# An E2 Node is identified as an IP connecting to E2T (38000) but not identified as the RIC Client.
#
# @param [str] pcap_file The path to the PCAP file.
# @return [str|None] The E2 Node IP address as a string, or None if not found.
def get_e2_node_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of an E2 Node (gNB/O-CU/O-DU).
    Returns: The E2 Node IP address as a string, or None if not found.
    """
    roles = recognize_oran_ips_roles(pcap_file)
    return roles.get("e2_node_ip")