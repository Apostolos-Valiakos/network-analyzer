def build_graph_json(conversations):
    # Collect unique IPs
    unique_ips = set()
    for (ip1, ip2), counts in conversations.items():
        unique_ips.add(ip1)
        unique_ips.add(ip2)

    unique_ips = sorted(unique_ips)
    ip_to_index = {ip: idx for idx, ip in enumerate(unique_ips)}

    # Nodes list
    nodes = [
        {"name": ip, "value": 1, "category": 0}
        for ip in unique_ips
    ]

    # Links list
    links = []
    for (ip1, ip2), counts in conversations.items():
        value = sum(counts.values())
        links.append({
            "source": ip_to_index[ip1],
            "target": ip_to_index[ip2],
            "value": value
        })

    return {
        "type": "force",
        "categories": [
            {
                "name": "IP",
                "keyword": {},
                "base": "IP"
            }
        ],
        "nodes": nodes,
        "links": links
    }
