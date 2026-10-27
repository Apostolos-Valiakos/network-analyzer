from scapy.all import PcapReader, IP
from scapy.data import IP_PROTOS
from scapy.layers.inet import IP


##
# Orchestrates the PCAP analysis pipeline using a memory-efficient streaming approach.
# REFACTOR: Replaced rdpcap() with PcapReader() to fix Critical Memory Issue.
# REFACTOR: Merged protocol and conversation analysis into a single pass.
#
# @param [str] filepath The path to the PCAP file.
# @return [tuple] (result: dict|None, error: str|None)
def initialize_analysis(filepath):
    """
    Load the PCAP in a stream, run analysis in one pass, and return combined results.
    """
    total_packets = 0
    ip_protocols = {}  # Format: {ip: set(protocols)}
    conversations = {}  # Format: { (ip1, ip2): { 'ip1_to_ip2': 0, ... } }

    try:
        # Use PcapReader to stream packets one by one (Low RAM usage)
        with PcapReader(filepath) as reader:
            for pkt in reader:
                total_packets += 1

                # We only care about IP packets for this analysis
                if IP not in pkt:
                    continue

                src = pkt[IP].src
                dst = pkt[IP].dst

                # --- 1. Protocol Analysis Logic ---
                # Get all layer names after IP
                protocol_layers = [
                    layer.__name__
                    for layer in pkt.layers()
                    if layer not in (pkt.__class__, IP)  # Skip Ethernet/IP base
                ]

                # Fallback to proto number if no higher layers found
                if protocol_layers:
                    proto_name = " -> ".join(protocol_layers)
                else:
                    try:
                        proto_name = IP_PROTOS[pkt[IP].proto]
                    except Exception:
                        proto_name = f"UNKNOWN({pkt[IP].proto})"

                # Add to set (we convert to list at the end)
                if src not in ip_protocols:
                    ip_protocols[src] = set()
                ip_protocols[src].add(proto_name)

                # --- 2. Conversation Analysis Logic ---
                # Create a canonical key for the conversation (IPs sorted alphabetically)
                key = tuple(sorted([src, dst]))

                if key not in conversations:
                    conversations[key] = {
                        f"{key[0]}_to_{key[1]}": 0,
                        f"{key[1]}_to_{key[0]}": 0,
                    }

                # Count packets sent in the specific direction
                direction_key = f"{src}_to_{dst}"
                if direction_key in conversations[key]:
                    conversations[key][direction_key] += 1

    except Exception as e:
        return None, f"Error processing PCAP: {str(e)}"

    # Post-processing: Convert sets to sorted lists for JSON serialization
    final_protocols = {ip: sorted(list(protos)) for ip, protos in ip_protocols.items()}

    # Convert conversation tuple keys to string representation if needed,
    # but Python dicts can handle tuple keys (JSON cannot).
    # The frontend expects a dictionary, usually we serialize this in app.py.
    # We will return the raw dict here.

    result = {
        "total_packets": total_packets,
        "ip_protocols": final_protocols,
        "conversations": conversations,
    }

    return result, None
