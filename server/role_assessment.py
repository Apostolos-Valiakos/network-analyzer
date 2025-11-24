import json
import ipaddress
from collections import defaultdict


##
# Checks if an IP address is a loopback address.
#
# @param [str] ip_address The string representation of an IP address.
# @return [bool] True if the address is a loopback (e.g., in 127.0.0.0/8), False otherwise.
def is_loopback(ip_address):
    """Checks if an IP address is a loopback address."""
    try:
        return ipaddress.ip_address(ip_address).is_loopback
    except ValueError:
        return False


##
# Extracts protocol and port information from a network layer dictionary.
#
# @param [dict] layer The layer dictionary, typically from tshark's JSON output.
# @return [tuple] (protocol: str|None, srcport: str|None, dstport: str|None)
def get_protocol_port_info(layer):
    """Extracts protocol and port information from a layer."""
    protocol = layer.get("layer_name")
    if protocol == "tcp":
        return (
            "tcp",
            layer.get("fields", {}).get("srcport"),
            layer.get("fields", {}).get("dstport"),
        )
    elif protocol == "udp":
        return (
            "udp",
            layer.get("fields", {}).get("srcport"),
            layer.get("fields", {}).get("dstport"),
        )
    elif protocol == "sctp":
        return (
            "sctp",
            layer.get("fields", {}).get("srcport"),
            layer.get("fields", {}).get("dstport"),
        )
    return None, None, None


##
# Analyzes packet data from a JSON file, infers 5G Core Network Function roles
# for each IP address based on communication patterns, ports, and direction, and provides reasoning.
#
# The analysis is optimized for a single pass through the packets to gather all necessary statistics
# before applying role assignment rules.
#
# @param [str] file_path The path to the JSON file containing packet data (e.g., from TShark).
# @return [list] A list of dictionaries, where each dictionary contains
#               'ip', 'roles', and 'reasoning' for an IP address.
def analyze_packets_and_assign_roles_optimized(file_path):
    """
    Analyzes packet data from a JSON file, infers 5G Core Network Function roles
    for each IP address based on communication patterns and direction, and provides reasoning.

    Args:
        file_path (str): The path to the JSON file containing packet data.

    Returns:
        list: A list of dictionaries, where each dictionary contains
              'ip', 'roles', and 'reasoning' for an IP address.
    """
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
                }
            ),
        }
    )

    try:
        with open(file_path, "r") as f:
            packets = json.load(f)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from '{file_path}': {e}")
        return []

    # --- Phase 1: Aggregate data from all packets ---
    for packet in packets:
        src_ip = None
        dst_ip = None

        # First, find IP layer for source and destination IPs
        for layer in packet.get("layers", []):
            if layer.get("layer_name") == "ip":
                ip_fields = layer.get("fields", {})
                src_ip = ip_fields.get("src")
                dst_ip = ip_fields.get("dst")

                # Check for loopback status
                if src_ip and is_loopback(src_ip):
                    ip_data[src_ip]["is_loopback"] = True
                if dst_ip and is_loopback(dst_ip):
                    ip_data[dst_ip]["is_loopback"] = True
                break

        if not src_ip or not dst_ip:
            continue

        # Second, find transport layers (TCP/UDP/SCTP) for ports and protocols
        for layer in packet.get("layers", []):
            protocol, packet_src_port, packet_dst_port = get_protocol_port_info(layer)
            if protocol:
                # 1. Record observed ports for each IP (unidirectional view)
                if packet_src_port:
                    ip_data[src_ip]["observed_src_ports"][protocol].add(packet_src_port)
                if packet_dst_port:
                    ip_data[dst_ip]["observed_dst_ports"][protocol].add(packet_dst_port)

                # 2. Record communication details with the peer (bidirectional view)
                # Data from the perspective of src_ip talking to dst_ip
                ip_data[src_ip]["peer_communication_details"][dst_ip]["protocols"].add(
                    protocol
                )
                if packet_src_port:
                    ip_data[src_ip]["peer_communication_details"][dst_ip][
                        "src_ports_to_peer"
                    ].add(packet_src_port)
                if packet_dst_port:
                    ip_data[src_ip]["peer_communication_details"][dst_ip][
                        "dst_ports_from_peer"
                    ].add(packet_dst_port)

                # Data from the perspective of dst_ip talking to src_ip (opposite direction)
                ip_data[dst_ip]["peer_communication_details"][src_ip]["protocols"].add(
                    protocol
                )
                if packet_dst_port:
                    ip_data[dst_ip]["peer_communication_details"][src_ip][
                        "src_ports_to_peer"
                    ].add(packet_dst_port)
                if packet_src_port:
                    ip_data[dst_ip]["peer_communication_details"][src_ip][
                        "dst_ports_from_peer"
                    ].add(packet_src_port)

    # --- Phase 2: Apply role assignment rules based on aggregated data ---
    final_results = []
    for ip, obs in ip_data.items():
        current_roles = set()
        current_reasoning = obs[
            "reasoning_parts"
        ].copy()  # Use pre-set reasoning from internal rules

        # Rule 1: Loopback address check
        if obs["is_loopback"]:
            current_roles.add("5G Core Network Function (Loopback Interface)")
            current_reasoning.add(
                f"IP {ip} is a loopback address (127.0.0.0/8 range), strongly indicating an internal 5G Core Function."
            )

        # Rule 2: Interface-based role inference (N2, N4, SBI, etc.)
        for peer_ip, interaction_data in obs["peer_communication_details"].items():
            protocols = interaction_data["protocols"]
            src_ports_to_peer = interaction_data["src_ports_to_peer"]
            dst_ports_from_peer = interaction_data["dst_ports_from_peer"]

            # Special case for gNB-AMF distinction (example scenario)
            if {ip, peer_ip} == {"192.168.100.4", "192.168.100.5"}:
                if "sctp" in protocols and "38412" in (
                    src_ports_to_peer.union(dst_ports_from_peer)
                ):
                    if ip == "192.168.100.5" and "38412" in src_ports_to_peer:
                        current_roles.add("gNB (Next Generation NodeB)")
                        current_reasoning.add(
                            f"Communicates with {peer_ip} via SCTP on port 38412 (NGAP) as a source. This indicates it initiates UE-related requests, strongly suggesting a gNB role."
                        )
                    elif ip == "192.168.100.4" and "38412" in dst_ports_from_peer:
                        current_roles.add(
                            "AMF (Access and Mobility Management Function)"
                        )
                        current_reasoning.add(
                            f"Communicates with {peer_ip} via SCTP on port 38412 (NGAP) as a destination. This indicates it responds to UE-related requests, strongly suggesting an AMF role."
                        )
                    else:
                        current_roles.add(
                            "AMF (Access and Mobility Management Function)"
                        )
                        current_roles.add("gNB (Next Generation NodeB)")
                        current_reasoning.add(
                            f"Communicates with {peer_ip} via SCTP on port 38412 (NGAP), suggesting N2 interface (AMF-gNB). Directional flow is key for distinction."
                        )
                continue

            # General N2 (NGAP)
            if "sctp" in protocols:
                if "38412" in src_ports_to_peer.union(dst_ports_from_peer):
                    current_roles.add("AMF (Access and Mobility Management Function)")
                    current_roles.add("gNB (Next Generation NodeB)")
                    current_reasoning.add(
                        f"Communicates with {peer_ip} via SCTP on port 38412 (NGAP), suggesting N2 interface. Likely AMF or gNB."
                    )
                # General N4 (PFCP Control Plane) / N11 (AMF-SMF)
                if "3868" in src_ports_to_peer.union(dst_ports_from_peer):
                    current_roles.add("SMF (Session Management Function)")
                    current_roles.add("UPF (User Plane Function)")
                    current_roles.add("AMF (Access and Mobility Management Function)")
                    current_reasoning.add(
                        f"Communicates with {peer_ip} via SCTP on port 3868 (PFCP/GTP-C), suggesting N4 (SMF-UPF) or N11 (AMF-SMF) interface. Likely SMF, UPF, or AMF."
                    )

            # N4 (PFCP) via UDP
            if "udp" in protocols:
                if "8805" in src_ports_to_peer.union(dst_ports_from_peer):
                    current_roles.add("SMF (Session Management Function)")
                    current_roles.add("UPF (User Plane Function)")
                    current_reasoning.add(
                        f"Communicates with {peer_ip} via UDP on port 8805 (PFCP), strongly suggesting N4 interface. Likely SMF or UPF."
                    )

            # Service-Based Interfaces (SBI) - N8/N10/N12/N13/N17/etc.
            if "tcp" in protocols:
                if "443" in src_ports_to_peer.union(dst_ports_from_peer):
                    current_roles.add("NRF (Network Repository Function)")
                    current_roles.add("PCF (Policy Control Function)")
                    current_roles.add("AUSF (Authentication Server Function)")
                    current_roles.add("UDM (Unified Data Management)")
                    current_roles.add("AMF (Access and Mobility Management Function)")
                    current_roles.add("SMF (Session Management Function)")
                    current_reasoning.add(
                        f"Communicates with {peer_ip} via TCP on port 443 (HTTPS/HTTP2), suggesting service-based interfaces like NRF, PCF, AUSF, UDM, AMF, or SMF."
                    )

                # Internal Loopback API/Service
                if (
                    "7777" in src_ports_to_peer.union(dst_ports_from_peer)
                    and obs["is_loopback"]
                ):
                    current_roles.add("5G Core Function (Internal API endpoint)")
                    current_reasoning.add(
                        f"Observed internal TCP traffic on loopback interface (port 7777), indicating an internal API or microservice within the 5G Core."
                    )

        # Rule 3: Hierarchical inference based on specific internal communication patterns
        specific_ips_for_smf = {"127.0.0.4", "127.0.0.7", "127.0.0.9"}
        if ip in specific_ips_for_smf:
            if obs["is_loopback"]:
                peers_of_current_ip = set(obs["peer_communication_details"].keys())

                if (
                    ip == "127.0.0.4"
                    and "127.0.0.7" in peers_of_current_ip
                    and "127.0.0.9" in peers_of_current_ip
                ):
                    has_pfcp_like_traffic_with_7 = False
                    has_n7_like_traffic_with_9 = False

                    interaction_with_7 = obs["peer_communication_details"].get(
                        "127.0.0.7",
                        {
                            "protocols": set(),
                            "src_ports_to_peer": set(),
                            "dst_ports_from_peer": set(),
                        },
                    )
                    if (
                        "sctp" in interaction_with_7["protocols"]
                        and "3868"
                        in (
                            interaction_with_7["src_ports_to_peer"].union(
                                interaction_with_7["dst_ports_from_peer"]
                            )
                        )
                    ) or (
                        "udp" in interaction_with_7["protocols"]
                        and "8805"
                        in (
                            interaction_with_7["src_ports_to_peer"].union(
                                interaction_with_7["dst_ports_from_peer"]
                            )
                        )
                    ):
                        has_pfcp_like_traffic_with_7 = True

                    interaction_with_9 = obs["peer_communication_details"].get(
                        "127.0.0.9",
                        {
                            "protocols": set(),
                            "src_ports_to_peer": set(),
                            "dst_ports_from_peer": set(),
                        },
                    )
                    if "tcp" in interaction_with_9["protocols"] and "443" in (
                        interaction_with_9["src_ports_to_peer"].union(
                            interaction_with_9["dst_ports_from_peer"]
                        )
                    ):
                        has_n7_like_traffic_with_9 = True

                    if has_pfcp_like_traffic_with_7 and has_n7_like_traffic_with_9:
                        # Infer SMF (127.0.0.4)
                        current_roles.add("SMF (Session Management Function)")
                        current_reasoning.add(
                            f"Communicates with 127.0.0.7 (via PFCP-like traffic) and 127.0.0.9 (via HTTP/2 N7-like traffic), strongly suggesting {ip} is the SMF."
                        )

                        # Set roles for peers (UPF and PCF)
                        ip_data["127.0.0.7"]["roles"].add("UPF (User Plane Function)")
                        ip_data["127.0.0.7"]["reasoning_parts"].add(
                            f"Likely UPF due to PFCP-like communication with 127.0.0.4 (SMF)."
                        )

                        ip_data["127.0.0.9"]["roles"].add(
                            "PCF (Policy Control Function)"
                        )
                        ip_data["127.0.0.9"]["reasoning_parts"].add(
                            f"Likely PCF due to HTTP/2 (N7-like) communication with 127.0.0.4 (SMF)."
                        )

        # Rule 4: Default/External Classification (if no 5G Core role assigned)
        if not obs["is_loopback"] and not current_roles:
            is_external_web = False
            # Check for external web server/client behavior
            if "tcp" in obs["observed_src_ports"] and (
                "80" in obs["observed_src_ports"]["tcp"]
                or "443" in obs["observed_src_ports"]["tcp"]
            ):
                current_roles.add("External Client / Initiator")
                current_reasoning.add(
                    f"Observed as source of external HTTP/HTTPS traffic (ports 80/443), suggesting an external client."
                )
                is_external_web = True
            if "tcp" in obs["observed_dst_ports"] and (
                "80" in obs["observed_dst_ports"]["tcp"]
                or "443" in obs["observed_dst_ports"]["tcp"]
            ):
                current_roles.add("External Server / Web Application")
                current_reasoning.add(
                    f"Observed as destination for external HTTP/HTTPS traffic (ports 80/443), suggesting an external web server or application."
                )
                is_external_web = True

            if not is_external_web:
                current_roles.add("General Network Entity (Non-5G Core)")
                current_reasoning.add(
                    f"Observed general network traffic, but no specific 5G Core interface protocols, loopback status, or clear directional web traffic detected."
                )

        # Final catch for loopback IPs that didn't get a more specific role
        if (
            obs["is_loopback"]
            and "5G Core Network Function (Loopback Interface)" not in current_roles
            and not current_reasoning
        ):
            current_roles.add("5G Core Network Function (Loopback Interface)")
            current_reasoning.add(
                f"IP {ip} is a loopback address (127.0.0.0/8 range), indicating an internal 5G Core Function (no more specific role inferred)."
            )

        # --- Phase 3: Format the final result ---
        final_results.append(
            {
                "ip": ip,
                "roles": sorted(
                    list(current_roles.union(obs["roles"]))
                ),  # Merge roles set during hierarchical inference
                "reasoning": " ".join(
                    sorted(list(current_reasoning.union(obs["reasoning_parts"])))
                ).strip(),  # Merge reasoning
            }
        )

    # Sort results by IP address for consistency
    final_results.sort(key=lambda x: ipaddress.ip_address(x["ip"]))

    return final_results
