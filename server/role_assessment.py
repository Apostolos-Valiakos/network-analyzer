import json
import ipaddress
from collections import defaultdict


##
# Checks if an IP address is a loopback address.
def is_loopback(ip_address):
    try:
        return ipaddress.ip_address(ip_address).is_loopback
    except ValueError:
        return False


##
# NEW: Enhanced extractor that gets ports AND DPI info (URI, Procedure Codes).
def get_protocol_details_enhanced(layer):
    """Extracts protocol, port, and DPI information from a layer."""
    protocol = layer.get("layer_name")
    fields = layer.get("fields", {})

    info = {
        "protocol": protocol,
        "srcport": fields.get("srcport")
        or fields.get("tcp.srcport")
        or fields.get("udp.srcport")
        or fields.get("sctp.srcport"),
        "dstport": fields.get("dstport")
        or fields.get("tcp.dstport")
        or fields.get("udp.dstport")
        or fields.get("sctp.dstport"),
        "uri_path": None,
        "procedure_code": None,
        "msg_type": None,
    }

    # DPI Rule: HTTP/2 Headers for SBI
    if protocol == "http2":
        headers = fields.get("http2.header", [])
        # Handle list or single dict structure from Tshark
        if isinstance(headers, dict):
            headers = [headers]
        for h in headers:
            if isinstance(h, dict) and h.get("http2.header.name") == ":path":
                info["uri_path"] = h.get("http2.header.value")
                break

    # DPI Rule: NGAP Procedure Codes
    if protocol == "ngap":
        info["procedure_code"] = fields.get("ngap.procedureCode")

    # DPI Rule: PFCP Message Types
    if protocol == "pfcp":
        info["msg_type"] = fields.get("pfcp.msg_type")

    return info


##
# Analyzes packet data. Keeps OLD rules and adds NEW DPI rules.
def analyze_packets_and_assign_roles_optimized(file_path):
    ip_data = defaultdict(
        lambda: {
            "roles": set(),
            "reasoning_parts": set(),
            "is_loopback": False,
            "observed_src_ports": defaultdict(set),
            "observed_dst_ports": defaultdict(set),
            "peer_communication_details": defaultdict(
                lambda: {
                    "protocols": set(),
                    "src_ports_to_peer": set(),
                    "dst_ports_from_peer": set(),
                    "dpi_hits": [],  # Store detailed DPI info here
                }
            ),
        }
    )

    try:
        with open(file_path, "r") as f:
            packets = json.load(f)
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return []

    # --- Phase 1: Aggregate data (Original + DPI) ---
    for packet in packets:
        src_ip = None
        dst_ip = None
        layers = packet.get("layers", [])

        # Find IP
        for layer in layers:
            if layer.get("layer_name") == "ip":
                src_ip = layer.get("fields", {}).get("src")
                dst_ip = layer.get("fields", {}).get("dst")
                if src_ip and is_loopback(src_ip):
                    ip_data[src_ip]["is_loopback"] = True
                if dst_ip and is_loopback(dst_ip):
                    ip_data[dst_ip]["is_loopback"] = True
                break

        if not src_ip or not dst_ip:
            continue

        # Find Transport/App Layers
        for layer in layers:
            info = get_protocol_details_enhanced(layer)
            proto = info["protocol"]

            if proto in ["tcp", "udp", "sctp", "http2", "ngap", "pfcp"]:
                # 1. Record Ports (Old Logic)
                if info["srcport"]:
                    ip_data[src_ip]["observed_src_ports"][proto].add(info["srcport"])
                if info["dstport"]:
                    ip_data[dst_ip]["observed_dst_ports"][proto].add(info["dstport"])

                # 2. Record Peer Comm (Old Logic + DPI)
                # Src -> Dst
                ip_data[src_ip]["peer_communication_details"][dst_ip]["protocols"].add(
                    proto
                )
                if info["srcport"]:
                    ip_data[src_ip]["peer_communication_details"][dst_ip][
                        "src_ports_to_peer"
                    ].add(info["srcport"])
                if info["dstport"]:
                    ip_data[src_ip]["peer_communication_details"][dst_ip][
                        "dst_ports_from_peer"
                    ].add(info["dstport"])
                if info["uri_path"] or info["procedure_code"] or info["msg_type"]:
                    ip_data[src_ip]["peer_communication_details"][dst_ip][
                        "dpi_hits"
                    ].append(info)

                # Dst -> Src (Symmetric)
                ip_data[dst_ip]["peer_communication_details"][src_ip]["protocols"].add(
                    proto
                )

    # --- Phase 2: Apply Rules (Merged) ---
    final_results = []
    for ip, obs in ip_data.items():
        current_roles = set()
        current_reasoning = obs["reasoning_parts"].copy()

        # Rule 1: Loopback (Old Rule)
        if obs["is_loopback"]:
            current_roles.add("5G Core Network Function (Loopback Interface)")
            current_reasoning.add(f"IP {ip} is a loopback address.")

        # Iterate peers for Interface & DPI rules
        for peer_ip, interaction in obs["peer_communication_details"].items():
            protocols = interaction["protocols"]
            src_ports = interaction["src_ports_to_peer"]
            dst_ports = interaction["dst_ports_from_peer"]
            dpi_hits = interaction["dpi_hits"]

            # --- NEW: DPI Rules ---
            for hit in dpi_hits:
                # HTTP/2 URIs
                uri = hit.get("uri_path")
                if uri:
                    if "/namf" in uri:
                        current_roles.add("AMF")
                        current_reasoning.add(f"Target of SBI {uri}")
                    elif "/nsmf" in uri:
                        current_roles.add("SMF")
                        current_reasoning.add(f"Target of SBI {uri}")
                    elif "/nudm" in uri:
                        current_roles.add("UDM")
                        current_reasoning.add(f"Target of SBI {uri}")
                    elif "/nnrf" in uri:
                        current_roles.add("NRF")
                        current_reasoning.add(f"Target of SBI {uri}")

                # NGAP Procedure
                proc = hit.get("procedure_code")
                if proc == "21":  # NGSetup
                    if (
                        "38412" in src_ports
                    ):  # If this IP is sending on SCTP (ephemeral)
                        current_roles.add("gNB")
                    else:  # If this IP is receiving/has 38412
                        current_roles.add("AMF")
                    current_reasoning.add("Part of NGAP Setup (N2)")

            # --- OLD: Interface/Port Rules (Preserved) ---
            if "sctp" in protocols:
                if "38412" in src_ports.union(dst_ports) and not current_roles:
                    current_roles.add("AMF/gNB (Heuristic)")
                    current_reasoning.add("SCTP port 38412 traffic.")

            if "udp" in protocols and "8805" in src_ports.union(dst_ports):
                current_roles.add("SMF/UPF")
                current_reasoning.add("UDP port 8805 (PFCP) traffic.")

        # Rule 3: Hierarchical Inference (Old Rule Preserved)
        specific_ips_for_smf = {"127.0.0.4", "127.0.0.7", "127.0.0.9"}
        if ip in specific_ips_for_smf and obs["is_loopback"]:
            pass

        # Rule 4: Explicit "Unidentified" Fallback
        if not current_roles:
            current_roles.add("Unidentified")
            current_reasoning.add(
                "No specific 5G Core, O-RAN, or external web traffic patterns matched."
            )

        # Final Formatting
        final_results.append(
            {
                "ip": ip,
                "roles": sorted(list(current_roles.union(obs["roles"]))),
                "reasoning": "; ".join(sorted(list(current_reasoning))),
            }
        )

    final_results.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
    return final_results
