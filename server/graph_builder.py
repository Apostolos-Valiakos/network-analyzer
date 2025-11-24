##
# Builds a JSON object representing a force-directed graph structure from
# network conversation data. The output is typically used for visualization
# libraries like ECharts.
#
# Nodes represent unique IP addresses, and links represent conversations
# between them, weighted by the total number of packets exchanged.
#
# @param [dict] conversations A dictionary where keys are IP pairs (ip1, ip2)
# and values are dictionaries of packet counts per protocol.
# @return [dict] A dictionary formatted as a graph object with 'nodes', 'links',
# and 'categories'.
def build_graph_json(conversations):
    # Collect unique IPs
    unique_ips = set()
    for (ip1, ip2), counts in conversations.items():
        unique_ips.add(ip1)
        unique_ips.add(ip2)

    unique_ips = sorted(unique_ips)
    ip_to_index = {ip: idx for idx, ip in enumerate(unique_ips)}

    # Nodes list
    nodes = [{"name": ip, "value": 1, "category": 0} for ip in unique_ips]

    # Links list
    links = []
    for (ip1, ip2), counts in conversations.items():
        # Calculate the total traffic value (sum of all protocols in the conversation)
        value = sum(counts.values())
        links.append(
            {"source": ip_to_index[ip1], "target": ip_to_index[ip2], "value": value}
        )

    return {
        "type": "force",
        "categories": [{"name": "IP", "keyword": {}, "base": "IP"}],
        "nodes": nodes,
        "links": links,
    }
