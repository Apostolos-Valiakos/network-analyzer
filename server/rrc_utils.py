import subprocess
import json
import os
from typing import List, Tuple, Optional, Dict, Any
from models import db, PcapFile, IpRole


##
# Runs tshark on a PCAP file and loads the resulting JSON output.
# Optimization: Checks for existing .json dump on disk first.
def _run_tshark_and_load_packets(pcap_file: str) -> Optional[List[Dict[str, Any]]]:
    """Runs tshark and loads the JSON output, handling errors."""

    export_path = pcap_file + ".packets.json"
    if os.path.exists(export_path):
        try:
            with open(export_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    cmd = ["tshark", "-r", pcap_file, "-T", "json", "-V"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        packets = json.loads(result.stdout)

        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(packets, f, indent=2)

        return packets

    except (subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError):
        return None


def get_cached_packets(pcap_file: str) -> Optional[List[Dict[str, Any]]]:
    return _run_tshark_and_load_packets(pcap_file)


##
# OPTIMIZED: Single-Pass Role Identification.
# Combines 5 separate TShark calls into 1 to drastically improve speed.
def get_comprehensive_ip_roles(pcap_file: str) -> Dict[str, str]:
    """
    Analyzes the PCAP to identify IP roles using a single TShark pass.
    """
    identified_roles = {}
    pcap_record = None  # FIX: Initialize to prevent UnboundLocalError

    # --- 1. Database Cache Lookup ---
    try:
        pcap_record = PcapFile.query.filter_by(file_path=pcap_file).first()
        if pcap_record:
            stored_roles = IpRole.query.filter_by(pcap_id=pcap_record.id).all()
            if stored_roles:
                print(f"Loading {len(stored_roles)} roles from Database...")
                return {r.ip_address: r.role for r in stored_roles}
    except Exception as e:
        # Expected in background threads without app context
        print(f"Database lookup skipped (Background Context): {e}")

    # --- 2. Single-Pass Deep Packet Inspection ---
    print(f"Performing Single-Pass DPI on {pcap_file}...")

    # We extract ALL necessary fields in one go.
    # Fields: IP Src/Dst, Proto Codes, HTTP Headers, TCP Ports
    cmd = [
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
        "-e",
        "http2.header.value",
        "-e",
        "tcp.dstport",
        "-E",
        "separator=|",  # Use pipe separator to handle spaces in headers
        "-E",
        "occurrence=f",  # Take first occurrence to keep output clean
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

    # O-RAN Candidates sets
    redis_candidates = set()  # Port 6379
    e2t_candidates = set()  # Port 38000
    all_seen_ips = set()

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            if not line.strip():
                continue

            parts = line.split("|")
            # Ensure we have enough parts (pad with empty strings if missing)
            if len(parts) < 7:
                parts += [""] * (7 - len(parts))

            src, dst, ngap, e2ap, pfcp, http_val, tcp_port = parts[:7]

            if not src or not dst:
                continue

            all_seen_ips.add(src)
            all_seen_ips.add(dst)

            # --- Logic: Control Plane Codes ---
            if ngap == "21":
                identified_roles.update({src: "gNB", dst: "AMF"})
            if e2ap == "1":
                identified_roles.update({src: "E2_NODE", dst: "NEAR_RT_RIC"})
            if pfcp == "50":
                identified_roles.update({src: "SMF", dst: "UPF"})

            # --- Logic: SBI (HTTP/2) ---
            if http_val:
                for sig, role in sbi_signatures.items():
                    if sig in http_val and dst not in identified_roles:
                        identified_roles[dst] = role
                        break

            # --- Logic: O-RAN Ports ---
            if tcp_port == "6379":
                if "redis_ip" not in identified_roles:
                    identified_roles["redis_ip_placeholder"] = dst  # Marker
                redis_candidates.add(src)
            elif tcp_port == "38000":
                if "e2t_ip" not in identified_roles:
                    identified_roles["e2t_ip_placeholder"] = dst  # Marker
                e2t_candidates.add(src)

    except Exception as e:
        print(f"DPI Error: {e}")

    # --- 3. Resolve O-RAN Complex Roles ---
    # Redis & E2T Servers (Destinations)
    # Note: We used placeholders above to store the server IPs found via destination
    # We now map them cleanly if they aren't already identified
    for ip, role in list(identified_roles.items()):
        if role == "redis_ip_placeholder":
            identified_roles[ip] = "REDIS"
        if role == "e2t_ip_placeholder":
            identified_roles[ip] = "E2T"

    # Client Logic
    common_clients = redis_candidates.intersection(e2t_candidates)
    if common_clients:
        ric_client = sorted(list(common_clients))[0]
        identified_roles[ric_client] = "NEAR_RT_RIC"  # It talks to both

    # E2 Nodes talk to E2T but are not the RIC
    for ip in e2t_candidates:
        if ip not in identified_roles:
            identified_roles[ip] = "E2_NODE"

    # --- 4. Catch-All ---
    for ip in all_seen_ips:
        if ip not in identified_roles:
            identified_roles[ip] = "Unidentified"

    # --- 5. Save Results to Database ---
    if pcap_record:
        try:
            new_role_objects = []
            for ip, role in identified_roles.items():
                # Avoid duplicates if logic runs twice
                new_role_objects.append(
                    IpRole(
                        pcap_id=pcap_record.id,
                        ip_address=ip,
                        role=role,
                        reasoning="Optimized TShark DPI",
                    )
                )

            if new_role_objects:
                db.session.bulk_save_objects(new_role_objects)
                db.session.commit()
                print(f"Cached {len(new_role_objects)} roles to Database.")
        except Exception as e:
            print(f"Failed to cache roles: {e}")
            db.session.rollback()

    return identified_roles


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


def get_unique_rrc_ips(pcap_file: str) -> List[str]:
    # Extract RRC specifically if needed, or rely on previous roles
    # For RRC specifically, we might still need a tiny separate call
    # if we strictly need 'nr-rrc' filter, but usually extracting all IPs is enough.
    # Keeping original logic for safety but can be optimized further.
    cmd = ["tshark", "-r", pcap_file, "-Y", "nr-rrc", "-T", "fields", "-e", "ip.dst"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return sorted(list(set(result.stdout.splitlines())))
    except Exception:
        return []


def recognize_oran_ips_roles(pcap_file: str) -> Dict[str, Optional[str]]:
    # This is now handled inside get_comprehensive_ip_roles
    # We return a dummy dict or re-parse if absolutely necessary for legacy support
    # Ideally, refactor calling code to use get_comprehensive_ip_roles directly.
    roles = get_comprehensive_ip_roles(pcap_file)
    return {
        "e2t_ip": next((k for k, v in roles.items() if v == "E2T"), None),
        "redis_ip": next((k for k, v in roles.items() if v == "REDIS"), None),
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
