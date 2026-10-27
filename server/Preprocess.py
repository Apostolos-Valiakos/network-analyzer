# server/Preprocess.py
import os
import sys
import time
import multiprocessing as mp
import json
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from rrc_utils import get_cached_packets
from role_engine import get_or_compute_roles, roles_as_strings


class PacketProcessor:
    """
    Parses pcap packets to extract features (timestamp, length, protocol).
    REFACTOR: Removed slow legacy string-matching logic.
    """

    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.extracted_data = []

        # --- 1. Role Identification (evidence-based engine, via TShark) ---
        # UE detection now happens inside the engine (GTP-U inner IPs, raw RRC).
        print(f"Loading roles for {pcap_file}...")
        self.assessments = get_or_compute_roles(pcap_file)
        self.ip_roles = roles_as_strings(self.assessments)

    def parse_pcap(self, packets=None):
        # get_cached_packets already yields per-packet feature records
        # (timestamp, src_ip, packet_len, protocol) via a tshark field pass.
        if packets is None:
            packets = get_cached_packets(self.pcap_file)
            if packets is None:
                return self.extracted_data, self.ip_roles

        self.extracted_data.extend(packets)
        return self.extracted_data, self.ip_roles


class FeatureEngineer:
    """
    Transforms raw packet data into structured dataset for ML.
    REFACTOR: Uses Numpy vectorization instead of slow Pandas .iloc loops.
    """

    def __init__(self, raw_data, ip_roles):
        self.raw_data = raw_data
        self.ip_roles = ip_roles
        self.sequence_length = 5
        self.processed_data = []
        self.labels = []
        self.protocol_encoder = LabelEncoder()
        self.label_encoder = LabelEncoder()

    def run_preprocessing(self):
        if not self.raw_data:
            return None, None, None, None

        df = pd.DataFrame(self.raw_data)

        # Cleanup
        df.fillna(0, inplace=True)
        if "protocol" not in df.columns:
            return None, None, None, None

        df = df[df["protocol"].notna()]

        # Encode protocols once
        df["protocol_encoded"] = self.protocol_encoder.fit_transform(
            df["protocol"].astype(str)
        )

        # --- OPTIMIZED LOOP ---
        # Group by IP and convert to Numpy arrays immediately to avoid DataFrame overhead in loops
        grouped = df.groupby("src_ip")

        for ip, group in grouped:
            if ip not in self.ip_roles:
                continue

            # Sort by time
            group = group.sort_values("timestamp")

            # Convert to numpy for speed
            timestamps = group["timestamp"].values
            lengths = group["packet_len"].values
            protos = group["protocol_encoded"].values

            num_packets = len(group)
            if num_packets < self.sequence_length:
                continue

            # Vectorized windowing logic
            # We construct sequences without calling .iloc repeatedly
            for i in range(num_packets - self.sequence_length + 1):
                # Slice numpy arrays (very fast)
                seq_t = timestamps[i : i + self.sequence_length]
                seq_l = lengths[i : i + self.sequence_length]
                seq_p = protos[i : i + self.sequence_length]

                # Stack features: [timestamp, packet_len, protocol]
                seq_features = np.column_stack((seq_t, seq_l, seq_p))

                self.processed_data.append(seq_features)
                self.labels.append(self.ip_roles[ip])

        if not self.processed_data:
            return None, None, None, None

        # Final Formatting
        X = np.array(self.processed_data)
        y = np.array(self.labels)

        # Encode Labels
        all_possible_roles = list(set(self.ip_roles.values()))
        self.label_encoder.fit(all_possible_roles)
        y_encoded = self.label_encoder.transform(y)
        class_names = self.label_encoder.classes_

        # Scaling
        num_features = X.shape[2]
        X_reshaped = X.reshape(-1, num_features)
        scaler = StandardScaler()
        X_reshaped = scaler.fit_transform(X_reshaped)
        X = X_reshaped.reshape(-1, self.sequence_length, num_features)

        return X, y_encoded, class_names, self.label_encoder


def _pipeline_worker(pcap_file_path, model_name, result_queue, selected_ips=None):
    """
    Worker process to run the analysis in the background without blocking Flask.
    """
    try:
        from app import app

        with app.app_context():
            start_time = time.time()

            # 1. Load packet features (tshark field pass, cached next to the pcap)
            packets = get_cached_packets(pcap_file_path)
            if packets is None:
                result_queue.put(
                    {"status": "failed", "message": "Failed to load packets."}
                )
                return

            # 2. Parse & Extract Roles
            processor = PacketProcessor(pcap_file_path)
            raw_data, ip_roles = processor.parse_pcap(packets=packets)

            # Filter if user selected specific IPs
            if selected_ips:
                raw_data = [d for d in raw_data if d["src_ip"] in selected_ips]
                ip_roles = {k: v for k, v in ip_roles.items() if k in selected_ips}

            # 3. Feature Engineering (Optimized)
            engineer = FeatureEngineer(raw_data, ip_roles)
            X, y, classes, enc = engineer.run_preprocessing()

            # 4. Generate Summary Report
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

            # Save result for frontend retrieval
            results_dir = "./server/results"
            os.makedirs(results_dir, exist_ok=True)
            base = os.path.splitext(os.path.basename(pcap_file_path))[0]
            with open(f"{results_dir}/{base}.json", "w") as f:
                json.dump(summary, f, indent=4)

            most_frequent_class = (
                max(summary, key=lambda x: x["count"])["class_name"]
                if summary
                else None
            )

            result_queue.put(
                {
                    "status": "success",
                    "total_classified": len(ip_roles),
                    "most_frequent_class": most_frequent_class,
                    "processing_time": round(time.time() - start_time, 2),
                    "rule_based_classification_summary": summary,
                    "ip_roles": ip_roles,
                    "ip_role_details": {
                        ip: {
                            "role": a.role,
                            "confidence": a.confidence,
                            "reasoning": a.reasoning,
                        }
                        for ip, a in processor.assessments.items()
                        if ip in ip_roles
                    },
                }
            )
    except Exception as e:
        import traceback

        traceback.print_exc()
        result_queue.put({"status": "failed", "message": str(e)})


def _run_pipeline_blocking(pcap_file_path, model_name, selected_ips=None):
    """Blocking subprocess wrapper — must be called from a real OS thread."""
    queue = mp.Queue()
    process = mp.Process(
        target=_pipeline_worker, args=(pcap_file_path, model_name, queue, selected_ips)
    )
    process.start()
    try:
        result = queue.get(timeout=600)
        process.join(timeout=5)
        return result
    except mp.queues.Empty:
        process.terminate()
        process.join(timeout=5)
        return {"status": "failed", "message": "Pipeline Timeout"}


def run_ip_role_pipeline(pcap_file_path, model_name, selected_ips=None):
    """
    Entry point called by app.py.
    Runs the blocking subprocess in a real OS thread via eventlet.tpool so
    the Eventlet event loop is not blocked while the pipeline executes.
    """
    try:
        import eventlet.tpool
        return eventlet.tpool.execute(
            _run_pipeline_blocking, pcap_file_path, model_name, selected_ips
        )
    except ImportError:
        return _run_pipeline_blocking(pcap_file_path, model_name, selected_ips)
