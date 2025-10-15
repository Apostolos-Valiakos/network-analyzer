# rrc_utils.py
import subprocess
import json
from typing import List, Tuple, Optional, Dict, Any

def _run_tshark_and_load_packets(pcap_file: str) -> Optional[List[Dict[str, Any]]]:
    """Runs tshark and loads the JSON output, handling errors."""
    cmd = [
        "tshark", "-r", pcap_file, "-T", "json", "-V"
    ]
    try:
        # check=True will raise an error if tshark fails
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError) as e:
        # print(f"Error loading packets: {e}") # Debugging line
        return None

def recognize_core_ips(packets: List[Dict[str, Any]]) -> Tuple[Optional[str], Optional[str]]:
    """
    Identifies the gNB and AMF IPs by finding the SCTP association initiation.
    The gNB initiates the connection (SCTP INIT, chunk_type=1) to the AMF.
    """
    gnb_ip = None
    amf_ip = None

    for pkt in packets:
        try:
            layers = pkt.get("_source", {}).get("layers", {})
            ip_layer = layers.get("ip")
            sctp_layer = layers.get("sctp")
            sctp_chunk_dict = sctp_layer.get("sctp.chunk")
            # SCTP chunk_type '1' is INIT (Initiation)
            chunk_type = sctp_layer.get("sctp.chunk", {}).get("sctp.chunk_type")
            if ip_layer and sctp_layer and chunk_type == "1":
                # gNB is the initiator (source IP)
                gnb_ip = ip_layer.get("ip.src")
                amf_ip = ip_layer.get("ip.dst")
                break
        except Exception:
            continue
            
    return gnb_ip, amf_ip

def get_gnb_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of the gNB.
    Returns: The gNB IP address as a string, or None if not found.
    """
    packets = _run_tshark_and_load_packets(pcap_file)
    if not packets:
        return None
    gnb, _ = recognize_core_ips(packets)
    return gnb

def get_amf_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of the AMF.
    Returns: The AMF IP address as a string, or None if not found.
    """
    packets = _run_tshark_and_load_packets(pcap_file)
    if not packets:
        return None
    _, amf = recognize_core_ips(packets)
    return amf

def get_unique_rrc_ips(pcap_file: str) -> List[str]:
    """
    Runs tshark on the given pcap file, extracts unique destination IPs
    from packets that contain NR-RRC, skips consecutive duplicates,
    and **excludes the gNB and AMF IPs**.
    """
    packets = _run_tshark_and_load_packets(pcap_file)
    if not packets:
        return []

    gnb_ip, amf_ip = recognize_core_ips(packets)

    excluded_ips = {ip for ip in (gnb_ip, amf_ip) if ip}

    ips = []
    last_ip = None

    for pkt in packets:
        try:
            layers = pkt.get("_source", {}).get("layers", {})
            frame = layers.get("frame", {})
            ip_layer = layers.get("ip")
            
            if not ip_layer:
                continue
                
            if "nr-rrc" in frame.get("frame.protocols", ""):
                ip_dst = ip_layer.get("ip.dst")
                
                if ip_dst and ip_dst != last_ip:
                    if ip_dst not in excluded_ips:
                        ips.append(ip_dst)
                    
                    last_ip = ip_dst 
                    
        except Exception:
            continue

    return sorted(list(set(ips)))
# rrc_utils.py
import subprocess
import json
from typing import List, Tuple, Optional, Dict, Any

def _run_tshark_and_load_packets(pcap_file: str) -> Optional[List[Dict[str, Any]]]:
    """Runs tshark and loads the JSON output, handling errors."""
    cmd = [
        "tshark", "-r", pcap_file, "-T", "json", "-V"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        packets = json.loads(result.stdout)

        #Export packets to a JSON file
        export_path = pcap_file + ".packets.json"
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(packets, f, indent=2)

        return packets

    except (subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError):
        return None
    
def recognize_core_ips(packets: List[Dict[str, Any]]) -> Tuple[Optional[str], Optional[str]]:
    """
    Identifies the gNB and AMF IPs by finding the SCTP association initiation.
    The gNB initiates the connection (SCTP INIT, chunk_type=1) to the AMF.
    """
    gnb_ip = None
    amf_ip = None

    for pkt in packets:
        try:
            layers = pkt.get("_source", {}).get("layers", {})
            ip_layer = layers.get("ip")
            sctp_layer = layers.get("sctp")
            sctp_chunk_dict = sctp_layer.get("sctp.chunk")
            # SCTP chunk_type '1' is INIT (Initiation)
            chunk_type = sctp_layer.get("sctp.chunk", {}).get("sctp.chunk_type")
            if ip_layer and sctp_layer and chunk_type == "1":
                # gNB is the initiator (source IP)
                gnb_ip = ip_layer.get("ip.src")
                amf_ip = ip_layer.get("ip.dst")
                break
        except Exception:
            continue
            
    return gnb_ip, amf_ip

def get_gnb_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of the gNB.
    Returns: The gNB IP address as a string, or None if not found.
    """
    packets = _run_tshark_and_load_packets(pcap_file)
    if not packets:
        return None
    gnb, _ = recognize_core_ips(packets)
    return gnb

def get_amf_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of the AMF.
    Returns: The AMF IP address as a string, or None if not found.
    """
    packets = _run_tshark_and_load_packets(pcap_file)
    if not packets:
        return None
    _, amf = recognize_core_ips(packets)
    return amf

def get_unique_rrc_ips(pcap_file: str) -> List[str]:
    """
    Runs tshark on the given pcap file, extracts unique destination IPs
    from packets that contain NR-RRC, skips consecutive duplicates,
    and **excludes the gNB and AMF IPs**.
    """
    packets = _run_tshark_and_load_packets(pcap_file)
    if not packets:
        return []

    gnb_ip, amf_ip = recognize_core_ips(packets)

    excluded_ips = {ip for ip in (gnb_ip, amf_ip) if ip}

    ips = []
    last_ip = None

    for pkt in packets:
        try:
            layers = pkt.get("_source", {}).get("layers", {})
            frame = layers.get("frame", {})
            ip_layer = layers.get("ip")
            
            if not ip_layer:
                continue
                
            if "nr-rrc" in frame.get("frame.protocols", ""):
                ip_dst = ip_layer.get("ip.dst")
                
                if ip_dst and ip_dst != last_ip:
                    if ip_dst not in excluded_ips:
                        ips.append(ip_dst)
                    
                    last_ip = ip_dst 
                    
        except Exception:
            continue

    return sorted(list(set(ips)))

def recognize_oran_ips_roles(pcap_file: str) -> List[str]:
    """
    Identifies O-RAN specific IPs (E2T, Redis, RIC Client, E2 Node)
    based on well-known ports and packet communication patterns.

    Logic:
    1. Redis Server: IP acting as the destination on TCP port 6379.
    2. E2 Terminator (E2T): IP acting as the destination on TCP port 38000.
    3. Near-RT RIC Client: IP that acts as the source/client for both Redis and E2T.
    4. E2 Node: IP that acts as the source/client for the E2T, but not the RIC Client.
    """
    roles: Dict[str, Optional[str]] = {
        "e2t_ip": None,
        "redis_ip": None,
        "ric_client_ip": None,
        "e2_node_ip": None
    }
    packets = _run_tshark_and_load_packets(pcap_file)
    
    ric_client_candidates = set()
    e2t_client_candidates = set()

    for pkt in packets:
        try:
            layers = pkt.get("_source", {}).get("layers", {})
            ip_layer = layers.get("ip")
            tcp_layer = layers.get("tcp")

            if not ip_layer or not tcp_layer:
                continue

            ip_src = ip_layer.get("ip.src")
            ip_dst = ip_layer.get("ip.dst")
            tcp_dstport = tcp_layer.get("tcp.dstport")

            # 1. Identify Redis Server (Server Port 6379)
            if tcp_dstport == "6379":
                if roles["redis_ip"] is None:
                    roles["redis_ip"] = ip_dst
                ric_client_candidates.add(ip_src) # Source IP is the client
                
            # 2. Identify E2 Terminator (E2T) (Server Port 38000)
            if tcp_dstport == "38000":
                if roles["e2t_ip"] is None:
                    roles["e2t_ip"] = ip_dst
                e2t_client_candidates.add(ip_src) # Source IP is the client
                

        except Exception:
            continue
            
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
    packets = _run_tshark_and_load_packets(pcap_file)
    if not packets:
        return None
    roles = recognize_oran_ips_roles(packets)
    return roles.get("e2t_ip")

def get_redis_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of the Redis Database Server.
    Returns: The Redis IP address as a string, or None if not found.
    """
    packets = _run_tshark_and_load_packets(pcap_file)
    if not packets:
        return None
    roles = recognize_oran_ips_roles(packets)
    return roles.get("redis_ip")

def get_ric_client_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of the Near-RT RIC Component (client).
    Returns: The RIC Client IP address as a string, or None if not found.
    """
    packets = _run_tshark_and_load_packets(pcap_file)
    if not packets:
        return None
    roles = recognize_oran_ips_roles(packets)
    return roles.get("ric_client_ip")

def get_e2_node_ip(pcap_file: str) -> Optional[str]:
    """
    Reads the pcap file and returns the IP address of an E2 Node (gNB/O-CU/O-DU).
    Returns: The E2 Node IP address as a string, or None if not found.
    """
    packets = _run_tshark_and_load_packets(pcap_file)
    if not packets:
        return None
    roles = recognize_oran_ips_roles(packets)
    return roles.get("e2_node_ip")