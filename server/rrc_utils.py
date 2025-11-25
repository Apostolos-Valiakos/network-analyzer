import subprocess
import json
from typing import List, Tuple, Optional, Dict, Any

##
# Global cache to store packets for each pcap file.
_packet_cache: Dict[str, Optional[List[Dict[str, Any]]]] = {}


##
# Runs tshark on a PCAP file and loads the resulting JSON output into memory.
def _run_tshark_and_load_packets(pcap_file: str) -> Optional[List[Dict[str, Any]]]:
    """Runs tshark and loads the JSON output, handling errors."""
    if pcap_file in _packet_cache:
        return _packet_cache[pcap_file]

    cmd = ["tshark", "-r", pcap_file, "-T", "json", "-V"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        packets = json.loads(result.stdout)

        # Export packets to a JSON file (optional)
        export_path = pcap_file + ".packets.json"
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(packets, f, indent=2)

        _packet_cache[pcap_file] = packets
        return packets

    except (subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError):
        _packet_cache[pcap_file] = None
        return None


def get_cached_packets(pcap_file: str) -> Optional[List[Dict[str, Any]]]:
    """Public function to get cached packets, loading if necessary."""
    return _run_tshark_and_load_packets(pcap_file)


##
# NEW: Comprehensive Role Identification using Deep Packet Inspection (DPI).
# Incorporates NGAP/E2AP codes, HTTP/2 URIs, and a Catch-All for Unidentified IPs.
def get_comprehensive_ip_roles(pcap_file: str) -> Dict[str, str]:
    """
    Analyzes the PCAP to identify IP roles using:
    1. NGAP/E2AP Procedure Codes (Sender Role)
    2. HTTP/2 URI Paths (Service Based Interfaces)
    3. PFCP Message Types
    4. O-RAN Port checks
    5. CATCH-ALL: Collects all remaining IPs as 'Unidentified'
    """
    identified_roles = {}

    # --- 1. Control Plane DPI (NGAP / E2AP / PFCP) ---
    cmd_cp = [
        "tshark",
        "-r",
        pcap_file,
        "-T",
        "fields",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "ngap.procedureCode",
        "-e",
        "e2ap.procedureCode",
        "-e",
        "pfcp.msg_type",
        "-Y",
        "ngap.procedureCode==21 || e2ap.procedureCode==1 || pfcp.msg_type==5 || pfcp.msg_type==50",
    ]

    try:
        proc = subprocess.run(cmd_cp, capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue

            src, dst = parts[0], parts[1]
            ngap_code = parts[2] if len(parts) > 2 else ""
            e2ap_code = parts[3] if len(parts) > 3 else ""
            pfcp_code = parts[4] if len(parts) > 4 else ""

            # NGAP: Setup Request (21) comes from gNB, goes to AMF
            if ngap_code == "21":
                identified_roles[src] = "gNB"
                identified_roles[dst] = "AMF"

            # E2AP: Setup Request (1) comes from E2 Node, goes to RIC/E2T
            if e2ap_code == "1":
                identified_roles[src] = "E2_NODE"
                identified_roles[dst] = "NEAR_RT_RIC"

            # PFCP: Session Establishment (50) usually SMF -> UPF
            if pfcp_code == "50":
                identified_roles[src] = "SMF"
                identified_roles[dst] = "UPF"
    except Exception:
        pass

    # --- 2. Service Based Interfaces (HTTP/2 URIs) ---
    cmd_sbi = [
        "tshark",
        "-r",
        pcap_file,
        "-T",
        "fields",
        "-e",
        "ip.dst",
        "-e",
        "http2.header.value",
        "-Y",
        'http2.header.name == ":path"',
    ]

    sbi_signatures = {
        "/namf": "AMF",
        "/nsmf": "SMF",
        "/nudm": "UDM",
        "/nnrf": "NRF",
        "/nausf": "AUSF",
        "/npcf": "PCF",
        "/nnef": "NEF",
        "/nscp": "SCP",
    }

    try:
        proc = subprocess.run(cmd_sbi, capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            if "\t" not in line:
                continue
            dst_ip, path_value = line.split("\t")

            for signature, role in sbi_signatures.items():
                if signature in path_value:
                    if dst_ip not in identified_roles:
                        identified_roles[dst_ip] = role
                    break
    except Exception:
        pass

    # --- 3. Integrate Old O-RAN Port Rules ---
    oran_roles = recognize_oran_ips_roles(pcap_file)
    for role_key, ip in oran_roles.items():
        if ip and ip not in identified_roles:
            simple_role = role_key.replace("_ip", "").upper()
            if simple_role == "RIC_CLIENT":
                simple_role = "NEAR_RT_RIC"
            identified_roles[ip] = simple_role

    # --- 4. CATCH-ALL: Ensure EVERY IP in the PCAP is listed ---
    # We extract all unique Source AND Destination IPs.
    # If they are not in the list, we mark them as "Unidentified".
    cmd_all_ips = [
        "tshark",
        "-r",
        pcap_file,
        "-T",
        "fields",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
    ]
    try:
        proc = subprocess.run(cmd_all_ips, capture_output=True, text=True)
        all_unique_ips = set()
        for line in proc.stdout.splitlines():
            parts = line.strip().split("\t")
            for p in parts:
                if p and p.strip():
                    all_unique_ips.add(p.strip())

        for ip in all_unique_ips:
            if ip not in identified_roles:
                identified_roles[ip] = "Unidentified"

    except Exception as e:
        print(f"Warning: Failed to extract all IPs: {e}")

    return identified_roles


##
# Identifies the gNB and AMF IPs.
def recognize_core_ips(pcap_file: str) -> Tuple[Optional[str], Optional[str]]:
    roles = get_comprehensive_ip_roles(pcap_file)
    gnb = next((ip for ip, role in roles.items() if role == "gNB"), None)
    amf = next((ip for ip, role in roles.items() if role == "AMF"), None)

    if gnb and amf:
        return gnb, amf

    # Fallback: Old SCTP INIT Rule
    cmd = [
        "tshark",
        "-r",
        pcap_file,
        "-Y",
        "sctp.chunk_type == 1",
        "-T",
        "fields",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-c",
        "1",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout.strip()
        if output:
            src, dst = output.split("\t")
            return (gnb or src), (amf or dst)
        return gnb, amf
    except Exception:
        return gnb, amf


def get_gnb_ip(pcap_file: str) -> Optional[str]:
    gnb, _ = recognize_core_ips(pcap_file)
    return gnb


def get_amf_ip(pcap_file: str) -> Optional[str]:
    _, amf = recognize_core_ips(pcap_file)
    return amf


##
# Extracts unique UE IPs.
def get_unique_rrc_ips(pcap_file: str) -> List[str]:
    gnb_ip, amf_ip = recognize_core_ips(pcap_file)
    excluded_ips = {ip for ip in (gnb_ip, amf_ip) if ip}

    # Use tshark to filter for RRC and extract destination IPs
    cmd = ["tshark", "-r", pcap_file, "-Y", "nr-rrc", "-T", "fields", "-e", "ip.dst"]
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


##
# Identifies O-RAN specific IPs based on well-known ports.
def recognize_oran_ips_roles(pcap_file: str) -> Dict[str, Optional[str]]:
    roles: Dict[str, Optional[str]] = {
        "e2t_ip": None,
        "redis_ip": None,
        "ric_client_ip": None,
        "e2_node_ip": None,
    }

    # 1. Redis (6379)
    cmd_redis = [
        "tshark",
        "-r",
        pcap_file,
        "-Y",
        "tcp.dstport == 6379",
        "-T",
        "fields",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
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

    # 2. E2T (38000)
    cmd_e2t = [
        "tshark",
        "-r",
        pcap_file,
        "-Y",
        "tcp.dstport == 38000",
        "-T",
        "fields",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
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

    # 3. Identify RIC Client
    common_clients = ric_client_candidates.intersection(e2t_client_candidates)
    if len(common_clients) > 0:
        roles["ric_client_ip"] = sorted(list(common_clients))[0]
    elif len(ric_client_candidates) > 0:
        roles["ric_client_ip"] = sorted(list(ric_client_candidates))[0]

    # 4. Identify E2 Node
    ric_ip = roles.get("ric_client_ip")
    final_e2_nodes = e2t_client_candidates - {ric_ip}
    if len(final_e2_nodes) > 0:
        roles["e2_node_ip"] = sorted(list(final_e2_nodes))[0]

    return roles


def get_e2t_ip(pcap_file: str) -> Optional[str]:
    return recognize_oran_ips_roles(pcap_file).get("e2t_ip")


def get_redis_ip(pcap_file: str) -> Optional[str]:
    return recognize_oran_ips_roles(pcap_file).get("redis_ip")


def get_ric_client_ip(pcap_file: str) -> Optional[str]:
    return recognize_oran_ips_roles(pcap_file).get("ric_client_ip")


def get_e2_node_ip(pcap_file: str) -> Optional[str]:
    return recognize_oran_ips_roles(pcap_file).get("e2_node_ip")
