import os
import json
from collections import defaultdict
from datetime import datetime

import numpy as np
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import AgglomerativeClustering
from scipy.cluster.hierarchy import linkage, fcluster
from kneed import KneeLocator


# ----------------------------
# 1. Parse PCAP and extract features
# ----------------------------
##
# Extracts traffic features for each unique IP address in a PCAP file.
#
# @param [str] pcap_file The path to the PCAP file.
# @return [pandas.DataFrame] A DataFrame where each row is an IP address and
#         columns are the extracted features (bytes, packets, partners, ports, duration, etc.).
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
            "avg_interarrival": avg_interarrival
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
    features = df.drop(columns=["ip"]).fillna(0)

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
    timestamped = os.path.splitext(filename_base)[0] + "_clusters"

    csv_path = os.path.join(upload_folder, f"{timestamped}.csv")
    json_path = os.path.join(upload_folder, f"{timestamped}.json")

    df.to_csv(csv_path, index=False)
    df.to_json(json_path, orient="records", indent=4)

    return csv_path, json_path


# ----------------------------
# 6. Full pipeline
# ----------------------------
##
# Executes the full clustering and anomaly detection pipeline for a given PCAP file.
#
# @param [str] pcap_path The path to the PCAP file.
# @param [int] n_clusters The number of clusters to form.
# @param [float|None] distance_threshold The distance threshold for clustering.
# @param [int] anomaly_threshold The cluster size threshold for flagging anomalies.
# @return [dict] A dictionary containing the list of anomalies and the graph data for visualization.
def analyze_pcap(pcap_path, n_clusters=4, distance_threshold=None, anomaly_threshold=2):
    df = extract_features(pcap_path)
    df = cluster_nodes(df, n_clusters=n_clusters, distance_threshold=distance_threshold)
    anomalies = detect_anomalies(df, threshold=anomaly_threshold)
    graph_data = build_graph_data(df)
    save_results(df, os.path.basename(pcap_path), 'server/cluster_analysis')

    return {
        "clusters": anomalies,  # includes anomaly flags
        "graphData": graph_data
    }

##
# Computes the Within-Cluster Sum of Squares (WCSS) for a range of cluster numbers (k)
# using Agglomerative Clustering and suggests an optimal k via the Elbow method.
#
# @param [pandas.DataFrame] df The feature DataFrame.
# @param [int] max_clusters The maximum number of clusters to test.
# @return [dict] A dictionary containing WCSS values, the suggested elbow point (k),
#         cluster importance, and the most important cluster ID.
def suggest_clusters_elbow(df, max_clusters=10):
    """
    Returns WCSS data, suggested elbow point, and most important cluster.
    All values converted to Python-native types for JSON serialization.
    """
    # Select numeric features
    features = df.select_dtypes(include="number").values
    n_samples = features.shape[0]

    if n_samples == 0:
        return {
            "wcss_data": [],
            "elbow_point": None,
            "cluster_hierarchy": [],
            "mostImportantCluster": None
        }

    # Limit max_clusters to number of samples
    max_clusters = min(max_clusters, n_samples)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features)

    # Compute WCSS for k = 1 to max_clusters
    wcss_data = []
    for k in range(1, max_clusters + 1):
        model = AgglomerativeClustering(n_clusters=k)
        labels = model.fit_predict(X_scaled)
        cluster_sum = 0
        for i in range(k):
            cluster_points = X_scaled[labels == i]
            if len(cluster_points) > 0:
                center = cluster_points.mean(axis=0)
                cluster_sum += ((cluster_points - center) ** 2).sum()
        wcss_data.append({"k": int(k), "wcss": float(cluster_sum)})

    # Detect elbow automatically
    ks = [d["k"] for d in wcss_data]
    wcss = [d["wcss"] for d in wcss_data]
    kn = KneeLocator(ks, wcss, curve='convex', direction='decreasing')
    elbow_point = int(kn.knee) if kn.knee is not None else None

    if elbow_point:
        df_clustered = cluster_nodes(df.copy(), n_clusters=elbow_point)
        importance_sorted, most_important = compute_cluster_importance(df_clustered)
    else:
        importance_sorted = []
        most_important = None

    return {
        "wcss_data": wcss_data,
        "elbow_point": elbow_point,
        "cluster_hierarchy": importance_sorted,
        "mostImportantCluster": most_important
    }

##
# Computes an importance score for each cluster based on total packet count and unique IP count.
#
# @param [pandas.DataFrame] df The clustered DataFrame.
# @return [tuple] (importance_sorted: list, most_important: int|None) A list of cluster importance dictionaries sorted descendingly by score, and the ID of the most important cluster.
def compute_cluster_importance(df):
    """
    Compute importance of clusters based on total packets
    and number of unique IPs.
    Returns a sorted list of cluster importance and the most important cluster.
    """
    importance = []
    for cluster_id, group in df.groupby("cluster"):
        total_packets = int(group["packets_sent"].sum() + group["packets_received"].sum())
        unique_ips = group["ip"].nunique()

        # Weighted score: packets + (unique_ips * 100)
        score = total_packets + (unique_ips * 100)

        importance.append({
            "cluster": int(cluster_id),
            "total_packets": total_packets,
            "unique_ips": unique_ips,
            "score": score
        })

    # Sort clusters by importance
    importance_sorted = sorted(importance, key=lambda x: x["score"], reverse=True)
    most_important = importance_sorted[0]["cluster"] if importance_sorted else None

    return importance_sorted, most_important