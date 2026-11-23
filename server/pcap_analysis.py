"""
Traffic summaries of a capture, read from the shared tshark packet table
(packet_table.py): packet count, per-pair conversations and, for
/analyze-saved-pcap, the protocol stacks each source IP sent.
"""
from typing import Dict, List

import packet_table


def summarize_traffic(filepath):
    """
    Packet count and per-pair conversation counts from the shared packet table.
    Only IPv4 frames count as conversations; the outermost IP header is used.

    @return (result: dict|None, error: str|None)
    """
    total_packets = 0
    conversations = {}
    try:
        for packet in packet_table.outer_packets(filepath):
            total_packets += 1
            if packet is None:
                continue
            src, dst = packet.src, packet.dst
            key = tuple(sorted([src, dst]))
            if key not in conversations:
                conversations[key] = {
                    f"{key[0]}_to_{key[1]}": 0,
                    f"{key[1]}_to_{key[0]}": 0,
                }
            conversations[key][f"{src}_to_{dst}"] += 1
    except Exception as e:
        return None, f"Error processing PCAP: {str(e)}"
    return {"total_packets": total_packets, "conversations": conversations}, None


def protocol_label(frame_protocols: str) -> str:
    """The protocol stack above the outer IPv4 header, from tshark's
    frame.protocols: "eth:ethertype:ip:sctp:ngap:ngap:nas-5gs" -> "sctp:ngap:nas-5gs".

    Repeated adjacent layers (tshark lists NGAP twice) are collapsed. A frame
    with nothing decoded above IP is labelled "ip".
    """
    layers = frame_protocols.split(":")
    if "ip" in layers:
        layers = layers[layers.index("ip") + 1:]
    label: List[str] = []
    for layer in layers:
        if layer and (not label or label[-1] != layer):
            label.append(layer)
    return ":".join(label) or "ip"


def protocol_labels(filepath: str) -> Dict[str, List[str]]:
    """{source IP: sorted protocol stacks it sent}, for IPv4 frames, by the
    outermost source address."""
    labels: Dict[str, set] = {}
    for protocols, src in packet_table.columns(filepath, ["frame.protocols", "ip.src"]):
        if src:
            labels.setdefault(packet_table.first(src), set()).add(protocol_label(protocols))
    return {ip: sorted(stacks) for ip, stacks in labels.items()}


def initialize_analysis(filepath):
    """
    Packet count, conversations and per-IP protocol stacks for
    /analyze-saved-pcap, in one cached tshark pass.

    @return (result: dict|None, error: str|None)
    """
    result, err = summarize_traffic(filepath)
    if err:
        return None, err
    try:
        result["ip_protocols"] = protocol_labels(filepath)
    except Exception as e:
        return None, f"Error processing PCAP: {str(e)}"
    return result, None
