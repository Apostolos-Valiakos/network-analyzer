from scapy.all import rdpcap, IP
from scapy.data import IP_PROTOS
import re
from scapy.layers.inet import IP


##
# Loads a PCAP file from the specified path.
#
# @param [str] filepath The absolute or relative path to the PCAP file.
# @return [tuple] (packets: scapy.plist.PacketList, error: str|None)
def load_pcap(filepath):
    """Load PCAP file and return packets."""
    try:
        packets = rdpcap(filepath)
        return packets, None
    except Exception as e:
        return None, str(e)


from scapy.layers.inet import IP, IP_PROTOS


##
# Analyzes the protocols associated with traffic sent by each IP address.
# It prioritizes higher-level layer names (e.g., TCP, HTTP) over raw IP protocol numbers.
#
# @param [scapy.plist.PacketList] packets A list of Scapy packet objects.
# @return [dict] A dictionary mapping source IP addresses (str) to a sorted list of
#         protocol names (list of str) they used.
def analyze_protocols(packets):
    """Return a dict mapping each IP to the set of protocol names it sends."""
    ip_protocols = {}

    for pkt in packets:
        if IP not in pkt:
            continue

        src = pkt[IP].src

        # Get all layer names after IP
        protocol_layers = [
            layer.__name__
            for layer in pkt.layers()
            if layer not in (pkt.__class__, IP)  # Skip Ethernet/IP base
        ]

        # If we still want to fall back to proto number if no higher layers found
        if protocol_layers:
            proto_name = " -> ".join(protocol_layers)
        else:
            try:
                proto_name = IP_PROTOS[pkt[IP].proto]
            except Exception:
                proto_name = f"UNKNOWN({pkt[IP].proto})"

        ip_protocols.setdefault(src, set()).add(proto_name)

    # Convert sets to sorted lists
    return {ip: sorted(protos) for ip, protos in ip_protocols.items()}


##
# Identifies and counts packets exchanged between pairs of IP addresses.
# Conversation keys are sorted tuples of (ip1, ip2). Counts are directional.
#
# @param [scapy.plist.PacketList] packets A list of Scapy packet objects.
# @return [dict] A dictionary where keys are sorted IP address tuples (str, str)
#         and values are dictionaries counting packets in each direction
#         (e.g., {'ip1_to_ip2': count, 'ip2_to_ip1': count}).
def analyze_conversations(packets):
    """Return a dict describing conversations between IPs and packet counts."""
    conversations = {}

    for pkt in packets:
        if IP not in pkt:
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst

        # Create a canonical key for the conversation (IPs sorted alphabetically)
        key = tuple(sorted([src, dst]))
        if key not in conversations:
            conversations[key] = {
                f"{key[0]}_to_{key[1]}": 0,
                f"{key[1]}_to_{key[0]}": 0,
            }

        # Count packets sent in the right direction
        if src < dst:
            # src is the first element in the sorted key
            conversations[key][f"{src}_to_{dst}"] += 1
        else:
            # src is the second element in the sorted key
            conversations[key][f"{src}_to_{dst}"] += 1

    return conversations


##
# Orchestrates the PCAP analysis pipeline: loads the file, analyzes protocols,
# and analyzes conversations.
#
# @param [str] filepath The path to the PCAP file.
# @return [tuple] (result: dict|None, error: str|None) A dictionary containing
#         'total_packets', 'ip_protocols', and 'conversations' data, or an error string.
def initialize_analysis(filepath):
    """Load the PCAP, run all analysis functions, and return combined results."""
    packets, error = load_pcap(filepath)
    if error:
        return None, error

    total_packets = len(packets)
    ip_protocols = analyze_protocols(packets)
    conversations = analyze_conversations(packets)
    # ue_sessions = analyze_ue_sessions(packets)

    result = {
        "total_packets": total_packets,
        "ip_protocols": ip_protocols,
        "conversations": conversations,
        # 'ue_sessions': ue_sessions
    }

    return result, None
