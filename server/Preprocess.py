# Preprocess.py
import glob
import os
import sys
import time
import multiprocessing as mp
import json
import csv
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder

try:
    from rrc_utils import (
        get_unique_rrc_ips,
        recognize_oran_ips_roles,
        get_cached_packets,
        get_comprehensive_ip_roles,
    )
except ImportError:
    print("Warning: 'rrc_utils' not found.")
    sys.exit(1)


class PacketProcessor:
    """
    Parses pcap files and extracts features.
    Relies on rrc_utils for the master list of IP roles.
    """

    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.extracted_data = []
        self.ip_roles = {}

        # --- 1. Get Master List of Roles (DPI + Catch-All) ---
        # This function now guarantees EVERY IP in the pcap is present.
        print(f"Applying comprehensive DPI & IP scan for {pcap_file}...")
        self.ip_roles = get_comprehensive_ip_roles(pcap_file)

        # Add UEs (Rule-based overlap)
        ue_ips = get_unique_rrc_ips(pcap_file)
        for ip in ue_ips:
            # Overwrite 'Unidentified' if we know it's a UE
            if self.ip_roles.get(ip) == "Unidentified" or ip not in self.ip_roles:
                self.ip_roles[ip] = "UE"

        # --- 2. Define OLD Keyword Rules (Preserved for backward compatibility) ---
        self.role_rules = {
            "gnB": ["PDUSessionResourceSetupResponse"],
            "5G_Core": ["PDUSessionResourceSetupRequest"],
            "UE": ["SomeRRCpacketThatShowsthisisAUE"],
            "SMF": [
                "PFCP Session Modification Request",
                "Session Establishment Request",
            ],
            "UPF": [
                "PFCP Session Modification Response",
                "Session Establishment Response",
            ],
        }

    def _process_packet(self, pkt_dict):
        features = {}
        try:
            layers = pkt_dict.get("_source", {}).get("layers", {})
            frame_layer = layers.get("frame", {})
            ip_layer = layers.get("ip")
            if not ip_layer:
                return

            src_ip = ip_layer.get("ip.src")
            features["timestamp"] = float(frame_layer.get("frame.time_epoch", 0))
            features["src_ip"] = src_ip
            features["packet_len"] = int(frame_layer.get("frame.len", 0))
            protocols = frame_layer.get("frame.protocols", "").split(":")
            features["protocol"] = protocols[-1] if protocols else "Unknown"

            current_role = self.ip_roles.get(src_ip)

            # --- 3. Apply OLD Keyword Logic (Fallback) ---
            # Only run if role is still Unidentified (and exists in our list)
            if current_role == "Unidentified":
                packet_string = json.dumps(layers)
                for role, msgs in self.role_rules.items():
                    for msg in msgs:
                        if msg.lower() in packet_string.lower():
                            self.ip_roles[src_ip] = role
                            break

            # Note: We do NOT add new IPs here anymore.
            # We trust rrc_utils.get_comprehensive_ip_roles has found them all.

            self.extracted_data.append(features)
        except Exception:
            pass

    def parse_pcap(self, packets=None):
        if packets is None:
            packets = get_cached_packets(self.pcap_file)
            if packets is None:
                return self.extracted_data, self.ip_roles

        for pkt_dict in packets:
            self._process_packet(pkt_dict)

        return self.extracted_data, self.ip_roles


class FeatureEngineer:
    """Transforms raw packet data into structured dataset."""

    def __init__(self, raw_data, ip_roles):
        self.raw_data = raw_data
        self.ip_roles = ip_roles
        self.df = pd.DataFrame(raw_data)
        self.sequence_length = 5
        self.processed_data = []
        self.labels = []
        self.protocol_encoder = LabelEncoder()
        self.label_encoder = LabelEncoder()

    def run_preprocessing(self):
        if self.df.empty:
            return None, None, None, None

        self.df.fillna(0, inplace=True)
        self.df = self.df[self.df["protocol"].notna()]

        self.df["protocol_encoded"] = self.protocol_encoder.fit_transform(
            self.df["protocol"].astype(str)
        )

        grouped = self.df.groupby("src_ip")
        for ip, group in grouped:
            if ip not in self.ip_roles:
                continue
            group = group.sort_values("timestamp")

            for i in range(len(group) - self.sequence_length + 1):
                sequence = group.iloc[i : i + self.sequence_length]
                seq_features = sequence[
                    ["timestamp", "packet_len", "protocol_encoded"]
                ].values
                self.processed_data.append(seq_features)
                self.labels.append(self.ip_roles[ip])

        if not self.processed_data:
            return None, None, None, None

        X = np.array(self.processed_data)
        y = np.array(self.labels)

        all_possible_roles = list(set(self.ip_roles.values()))
        self.label_encoder.fit(all_possible_roles)
        y_encoded = self.label_encoder.transform(y)
        class_names = self.label_encoder.classes_

        num_features = X.shape[2]
        X_reshaped = X.reshape(-1, num_features)
        scaler = StandardScaler()
        X_reshaped = scaler.fit_transform(X_reshaped)
        X = X_reshaped.reshape(-1, self.sequence_length, num_features)

        return X, y_encoded, class_names, self.label_encoder


def _pipeline_worker(pcap_file_path, model_name, result_queue, selected_ips=None):
    try:
        start_time = time.time()
        packets = get_cached_packets(pcap_file_path)
        if packets is None:
            result_queue.put({"status": "failed", "message": "Failed to load packets."})
            return

        processor = PacketProcessor(pcap_file_path)
        raw_data, ip_roles = processor.parse_pcap(packets=packets)

        if selected_ips:
            raw_data = [d for d in raw_data if d["src_ip"] in selected_ips]
            ip_roles = {k: v for k, v in ip_roles.items() if k in selected_ips}

        engineer = FeatureEngineer(raw_data, ip_roles)
        X, y, classes, enc = engineer.run_preprocessing()

        # Summary Generation:
        # This iterates over ALL roles in ip_roles, guaranteeing that even IPs
        # that generated no features (e.g., Silent Destination IPs) are included in the report.
        summary = []
        u_roles, counts = np.unique(list(ip_roles.values()), return_counts=True)
        for r, c in zip(u_roles, counts):
            summary.append(
                {
                    "class_name": r,
                    "count": int(c),
                    "ips": [ip for ip, role in ip_roles.items() if role == r],
                }
            )

        results_dir = "./server/results"
        os.makedirs(results_dir, exist_ok=True)
        base = os.path.splitext(os.path.basename(pcap_file_path))[0]
        with open(f"{results_dir}/{base}.json", "w") as f:
            json.dump(summary, f, indent=4)
        csv_path = os.path.join(results_dir, f"{base}.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["class_name", "count", "ips"])
            for row in summary:
                ips = ";".join(row.get("ips", []))
                writer.writerow([row.get("class_name"), row.get("count"), ips])

        result_queue.put(
            {
                "status": "success",
                "total_classified": len(ip_roles),
                "processing_time": round(time.time() - start_time, 2),
                "rule_based_classification_summary": summary,
                "ip_roles": ip_roles,
            }
        )
    except Exception as e:
        result_queue.put({"status": "failed", "message": str(e)})


def run_ip_role_pipeline(pcap_file_path, model_name, selected_ips=None):
    queue = mp.Queue()
    process = mp.Process(
        target=_pipeline_worker, args=(pcap_file_path, model_name, queue, selected_ips)
    )
    process.start()
    try:
        return queue.get(timeout=300)
    except mp.queues.Empty:
        process.terminate()
        return {"status": "failed", "message": "Timeout"}
