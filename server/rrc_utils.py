import subprocess
import json
from typing import List, Tuple, Optional, Dict, Any

# Global cache to store packets for each pcap file
_packet_cache: Dict[str, Optional[List[Dict[str, Any]]]] = {}

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

        # Export packets to a JSON file
        export_path = pcap_file + ".packets.json"
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(packets, f, indent=2)

        # Cache the packets
        _packet_cache[pcap_file] = packets
        return packets

    except (subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError):
        # Cache None for failed attempts to avoid retrying
        _packet_cache[pcap_file] = None
        return None

def get_cached_packets(pcap_file: str) -> Optional[List[Dict[str, Any]]]:
    """Public function to get cached packets, loading if necessary."""
    return _run_tshark_and_load_packets(pcap_file)
    
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
            src, dst = output.split("\t")
            return src, dst
        return None, None
    except Exception:
        return None, None

def get_gnb_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of the gNB.
    Returns: The gNB IP address as a string, or None if not found.
    """
    gnb, _ = recognize_core_ips(pcap_file)
    return gnb

def get_amf_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of the AMF.
    Returns: The AMF IP address as a string, or None if not found.
    """
    _, amf = recognize_core_ips(pcap_file)
    return amf

def get_unique_rrc_ips(pcap_file: str) -> List[str]:
    """
    Runs tshark on the given pcap file, extracts unique destination IPs
    from packets that contain NR-RRC, skips consecutive duplicates,
    and **excludes the gNB and AMF IPs**.
    Optimized with tshark fields.
    """
    # First, get gNB and AMF
    gnb_ip, amf_ip = recognize_core_ips(pcap_file)
    excluded_ips = {ip for ip in (gnb_ip, amf_ip) if ip}

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
            if ip_dst and ip_dst != last_ip and ip_dst not in excluded_ips:
                ips.append(ip_dst)
                last_ip = ip_dst
        return sorted(list(set(ips)))
    except Exception:
        return []

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
    
    # Collect for Redis (port 6379)
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
                if roles["redis_ip"] is None:
                    roles["redis_ip"] = ip_dst
                ric_client_candidates.add(ip_src)
    except Exception:
        pass

    # Collect for E2T (port 38000)
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
                if roles["e2t_ip"] is None:
                    roles["e2t_ip"] = ip_dst
                e2t_client_candidates.add(ip_src)
    except Exception:
        pass
            
    # Post-process to assign the remaining roles

    # 3. Identify Near-RT RIC Component (RIC Client)
    # This is the IP that connects to both Redis and E2T (intersection of clients)
    common_clients = ric_client_candidates.intersection(e2t_client_candidates)
    if len(common_clients) > 0:
        # Sort and take the first one found (simple selection)
        roles["ric_client_ip"] = sorted(list(common_clients))[0]
    elif len(ric_client_candidates) > 0:
        # Fallback to any client connecting to Redis
        roles["ric_client_ip"] = sorted(list(ric_client_candidates))[0]
            
    # 4. Identify E2 Node
    # This is an E2T client that is NOT the established RIC Client
    ric_ip = roles.get("ric_client_ip")
    final_e2_nodes = e2t_client_candidates - {ric_ip}
    
    if len(final_e2_nodes) > 0:
        # Sort and take the first one found (simple selection)
        roles["e2_node_ip"] = sorted(list(final_e2_nodes))[0]
            
    return roles

def get_e2t_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of the E2 Terminator (E2T).
    Returns: The E2T IP address as a string, or None if not found.
    """
    roles = recognize_oran_ips_roles(pcap_file)
    return roles.get("e2t_ip")

def get_redis_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of the Redis Database Server.
    Returns: The Redis IP address as a string, or None if not found.
    """
    roles = recognize_oran_ips_roles(pcap_file)
    return roles.get("redis_ip")

def get_ric_client_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of the Near-RT RIC Component (client).
    Returns: The RIC Client IP address as a string, or None if not found.
    """
    roles = recognize_oran_ips_roles(pcap_file)
    return roles.get("ric_client_ip")

def get_e2_node_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of an E2 Node (gNB/O-CU/O-DU).
    Returns: The E2 Node IP address as a string, or None if not found.
    """
    roles = recognize_oran_ips_roles(pcap_file)
    return roles.get("e2_node_ip")