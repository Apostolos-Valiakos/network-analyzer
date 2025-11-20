import os
import json
from collections import defaultdict
from datetime import datetime

import numpy as np
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import AgglomerativeClustering
import networkx as nx
import community  # python-louvain

# ----------------------------
# 1. Parse PCAP and extract features
# ----------------------------
##
# Extracts traffic features for each unique IP address in a PCAP file.
#
# @param [str] pcap_file The path to the PCAP file.
# @return [pandas.DataFrame] A DataFrame where each row is an IP address and
#         columns are the extracted features (bytes, packets, partners, ports, duration, etc.).
def extract_features(pcap_file):
    packets = rdpcap(pcap_file)

    stats = defaultdict(lambda: {
        "bytes_sent": 0,
        "bytes_received": 0,
        "packets_sent": 0,
        "packets_received": 0,
        "partners": set(),
        "ports": set(),
        "timestamps": []
    })

    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            length = len(pkt)

            stats[src]["bytes_sent"] += length
            stats[src]["packets_sent"] += 1
            stats[src]["partners"].add(dst)
            stats[src]["timestamps"].append(float(pkt.time))

            stats[dst]["bytes_received"] += length
            stats[dst]["packets_received"] += 1
            stats[dst]["partners"].add(src)
            stats[dst]["timestamps"].append(float(pkt.time))

            if TCP in pkt or UDP in pkt:
                stats[src]["ports"].add(pkt.sport)
                stats[dst]["ports"].add(pkt.dport)

    # Build feature DataFrame
    data = []
    for ip, s in stats.items():
        timestamps = sorted(s["timestamps"])
        durations = (timestamps[-1] - timestamps[0]) if len(timestamps) > 1 else 0
        interarrivals = np.diff(timestamps) if len(timestamps) > 1 else [0]
        avg_interarrival = np.mean(interarrivals) if len(interarrivals) > 0 else 0

        data.append({
            "ip": ip,
            "bytes_sent": s["bytes_sent"],
            "bytes_received": s["bytes_received"],
            "packets_sent": s["packets_sent"],
            "packets_received": s["packets_received"],
            "unique_partners": len(s["partners"]),
            "unique_ports": len(s["ports"]),
            "duration": durations,
            "avg_interarrival": avg_interarrival,
            "unique_partners_list": list(s["partners"])  # For graph modularity
        })

    df = pd.DataFrame(data)
    return df

# ----------------------------
# 2. Perform Agglomerative Clustering
# ----------------------------
##
# Performs Agglomerative Hierarchical Clustering on the IP features.
# Features are first scaled using StandardScaler.
#
# @param [pandas.DataFrame] df The feature DataFrame containing IP traffic metrics.
# @param [int|None] n_clusters The number of clusters to form (mutually exclusive with distance_threshold).
# @param [float|None] distance_threshold The linkage distance threshold (mutually exclusive with n_clusters).
# @return [pandas.DataFrame] The input DataFrame augmented with a 'cluster' label column.
def cluster_nodes(df, n_clusters=None, distance_threshold=None):
    features = df.drop(columns=["ip", "unique_partners_list"]).fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features)

    model = AgglomerativeClustering(
        n_clusters=n_clusters,
        distance_threshold=distance_threshold,
        linkage="ward"
    )
    labels = model.fit_predict(X_scaled)

    df["cluster"] = labels
    return df

# ----------------------------
# 3. Detect anomalies
# ----------------------------
##
# Identifies clusters with a size less than or equal to a specified threshold as anomalies.
#
# @param [pandas.DataFrame] df The clustered DataFrame containing the 'cluster' column.
# @param [int] threshold The maximum size a cluster can be to be flagged as anomalous.
# @return [list] A list of dictionaries, each containing the IP, its cluster ID, and an 'anomaly' boolean flag.
def detect_anomalies(df, threshold=2):
    anomalies = []
    for cluster_id, group in df.groupby("cluster"):
        is_anomaly = len(group) <= threshold
        for ip in group["ip"]:
            anomalies.append({"ip": ip, "cluster": int(cluster_id), "anomaly": is_anomaly})
    return anomalies

# ----------------------------
# 4. Build graph data for ECharts
# ----------------------------
##
# Converts the clustered IP data into a graph format suitable for network visualization libraries like ECharts.
# Nodes are IPs, and links connect IPs within the same cluster.
#
# @param [pandas.DataFrame] df The clustered DataFrame.
# @return [dict] A dictionary containing 'categories', 'nodes', and 'links' for graph visualization.
def build_graph_data(df):
    categories = [{"name": f"Cluster {c}", "keyword": {}, "base": "IP"} for c in df["cluster"].unique()]

    nodes = []
    ip_to_index = {}
    for idx, row in enumerate(df.itertuples(index=False)):
        nodes.append({
            "name": row.ip,
            "value": 1,
            "category": int(row.cluster)
        })
        ip_to_index[row.ip] = idx

    links = []
    for i, row1 in df.iterrows():
        for j, row2 in df.iterrows():
            if i < j and row1["cluster"] == row2["cluster"]:
                links.append({
                    "source": ip_to_index[row1["ip"]],
                    "target": ip_to_index[row2["ip"]],
                    "value": 1
                })

    graph_data = {
        "type": "force",
        "categories": categories,
        "nodes": nodes,
        "links": links
    }
    return graph_data

# ----------------------------
# 5. Save results
# ----------------------------
##
# Saves the clustered DataFrame to both CSV and JSON files in the specified directory.
#
# @param [pandas.DataFrame] df The clustered DataFrame to save.
# @param [str] filename_base The base filename (e.g., "capture.pcap") to derive the output filenames from.
# @param [str] upload_folder The directory path where the files should be saved.
# @return [tuple] (csv_path: str, json_path: str) The full paths to the saved files.
def save_results(df, filename_base, upload_folder="./uploads"):
    os.makedirs(upload_folder, exist_ok=True)
    timestamped = os.path.splitext(filename_base)[0]

    csv_path = os.path.join(upload_folder, f"{timestamped}.csv")
    json_path = os.path.join(upload_folder, f"{timestamped}.json")

    df.to_csv(csv_path, index=False)
    df.to_json(json_path, orient="records", indent=4)

    return csv_path, json_path

# ----------------------------
# 6. Compute Cluster Importance
# ----------------------------
##
# Computes an importance score for each cluster based on traffic and connectivity.
#
# @param [pandas.DataFrame] df The clustered DataFrame.
# @return [tuple] (importance_sorted: list, most_important: int|None)
#         A list of cluster importance dictionaries sorted descendingly by score, and the ID of the most important cluster.
def compute_cluster_importance(df):
    importance = []

    for cluster_id, group in df.groupby("cluster"):
        size = len(group)
        total_unique_partners = int(group["unique_partners"].sum())
        edge_density = total_unique_partners / max(size * size, 1)
        total_packets = int(group["packets_sent"].sum() + group["packets_received"].sum())
        traffic_score = np.log1p(total_packets)
        score = (edge_density * 0.7) + (traffic_score * 0.3)

        importance.append({
            "cluster": int(cluster_id),
            "size": size,
            "unique_partners_sum": total_unique_partners,
            "edge_density": float(edge_density),
            "traffic_score": float(traffic_score),
            "score": float(score)
        })

    importance_sorted = sorted(importance, key=lambda x: x["score"], reverse=True)
    most_important = importance_sorted[0]["cluster"] if importance_sorted else None

    return importance_sorted, most_important

# ----------------------------
# 7. Compute modularity score for a given clustering
# ----------------------------
##
# Computes the modularity of a given clustering using the Louvain method.
#
# @param [pandas.DataFrame] df The DataFrame containing IPs and their partners.
# @param [list|np.array] labels Cluster labels assigned to each IP.
# @return [float] The modularity score of the clustering.
def compute_modularity(df, labels):
    G = nx.Graph()
    ip_list = df["ip"].tolist()

    for ip in ip_list:
        G.add_node(ip)

    # Add edges based on communication partners
    for idx, row in df.iterrows():
        src = row["ip"]
        for dst in row["unique_partners_list"]:
            if src != dst:
                G.add_edge(src, dst)

    partition = {ip: int(labels[i]) for i, ip in enumerate(ip_list)}
    return community.modularity(partition, G)

# ----------------------------
# 8. Suggest clusters using modularity
# ----------------------------
##
# Determines the optimal number of clusters by maximizing graph modularity.
# Iterates over k=2..max_clusters, performs agglomerative clustering, and
# selects the k that produces the highest modularity score.
#
# @param [pandas.DataFrame] df The feature DataFrame.
# @param [int] max_clusters Maximum number of clusters to test.
# @return [dict] Dictionary containing best cluster count, modularity score,
#         cluster hierarchy with importance, and most important cluster.
def suggest_clusters_modularity(df, max_clusters=10):
    features = df.drop(columns=["ip", "unique_partners_list"]).select_dtypes(include="number").values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features)

    best_k = 2
    best_modularity = -1
    best_labels = None
    max_clusters = min(max_clusters, len(df))

    modularity_scores = []  # <-- NEW (for chart)

    for k in range(2, max_clusters + 1):
        model = AgglomerativeClustering(n_clusters=k)
        labels = model.fit_predict(X_scaled)
        mod_score = compute_modularity(df, labels)

        # collect all points for the chart
        modularity_scores.append({
            "k": k,
            "modularity": float(round(mod_score, 4))
        })

        if mod_score > best_modularity:
            best_modularity = mod_score
            best_k = k
            best_labels = labels

    df["cluster"] = best_labels
    importance_sorted, most_important = compute_cluster_importance(df)

    return {
        "best_k": best_k,
        "best_modularity": float(round(best_modularity, 4)),
        "modularity_scores": modularity_scores,    # <-- NEW FIELD
        "cluster_hierarchy": importance_sorted,
        "mostImportantCluster": most_important
    }


# ----------------------------
# 9. Full pipeline
# ----------------------------
##
# Executes the full clustering and anomaly detection pipeline for a given PCAP file.
# Automatically determines optimal clusters using graph modularity.
#
# @param [str] pcap_path The path to the PCAP file.
# @param [int] max_clusters Maximum number of clusters to test for modularity.
# @param [int] anomaly_threshold The cluster size threshold for flagging anomalies.
# @return [dict] A dictionary containing the list of anomalies, graph data for visualization,
#         and a summary of cluster modularity results.
def analyze_pcap_for_clustering(pcap_path, max_clusters=10, anomaly_threshold=2):
    df = extract_features(pcap_path)
    cluster_result = suggest_clusters_modularity(df, max_clusters=max_clusters)
    df = cluster_nodes(df, n_clusters=cluster_result["best_k"])
    anomalies = detect_anomalies(df, threshold=anomaly_threshold)
    graph_data = build_graph_data(df)
    save_results(df, os.path.basename(pcap_path), 'server/cluster_analysis')

    return {
        "clusters": anomalies,
        "graphData": graph_data,
        "clusterSummary": cluster_result
    }
