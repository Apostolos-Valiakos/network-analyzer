# Preprocess.py
import glob
import os
import sys
import time  # Used for processing time calculation
import multiprocessing as mp
import json

# Libraries for packet capture parsing.
try:
    from scapy.all import rdpcap, IP, SCTP
    from scapy.layers.l2 import Ether
    import pandas as pd
    import numpy as np

    #     import tensorflow as tf
    #     from tensorflow import keras
    #     from keras.models import Model
    #     from keras.layers import Input, Conv1D, LSTM, GRU, Dense, Dropout
    #     from keras.optimizers import Adam
    #     from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    import pyshark
    from pyshark.capture.capture import TSharkCrashException

    # Attempt to import rrc_utils, provide a fallback if it's not installed
    # Note: rrc_utils is imported inside the worker function as well for safety
    try:
        from rrc_utils import (
            get_unique_rrc_ips,
            recognize_oran_ips_roles,
            get_cached_packets,
        )
    except ImportError:
        print("Warning: 'rrc_utils' not found.")

except ImportError as e:
    print(f"Error importing a required library: {e}")
    print(
        "Please install the required libraries using: pip install scapy pandas numpy tensorflow scikit-learn pyshark"
    )
    sys.exit(1)

# --- Class Definitions ---


##
# Parses pcap files and extracts rule-based features for IP role assignment.
# This class handles Phase 1 of the pipeline using Scapy and Pyshark.
class PacketProcessor:
    """
    Parses pcap files and extracts rule-based features for IP role assignment.
    This class handles Phase 1 of the pipeline using Scapy and Pyshark.
    """

    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.extracted_data = []
        self.ip_roles = {}
        self.role_rules = {
            # Expanded rules to include more specific keywords.
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
            # 'AMF': ['NGSetupRequest', 'InitialUEMessage', 'NgapPDUSessionResourceSetupRequest']
        }

    ##
    # Extracts features and applies rule-based logic to assign roles.
    # This function performs a detailed, layer-by-layer search for keywords in a single packet.
    #
    # @param [dict] pkt_dict The packet data in tshark JSON format.
    # @return [None] Updates internal `self.ip_roles` and `self.extracted_data`.
    def _process_packet(self, pkt_dict):
        """
        Extracts features and applies rule-based logic to assign roles.
        This function performs a detailed, layer-by-layer search for keywords.
        """
        features = {}
        try:
            layers = pkt_dict.get("_source", {}).get("layers", {})
            frame_layer = layers.get("frame", {})
            ip_layer = layers.get("ip")
            if not ip_layer:
                return

            src_ip = ip_layer.get("ip.src")
            if src_ip not in self.ip_roles:
                self.ip_roles[src_ip] = "Unidentified"
            features["timestamp"] = 0
            features["src_ip"] = src_ip
            features["packet_len"] = int(frame_layer.get("frame.len", 0))

            # Determine the highest-level protocol (last in frame.protocols)
            protocols = frame_layer.get("frame.protocols", "").split(":")
            features["protocol"] = protocols[-1] if protocols else "Unknown"

            # Check if the IP's role is already determined. If so, return early for efficiency.
            if self.ip_roles.get(src_ip) in self.role_rules.keys():
                return

            # Detailed search for keywords within layers (use json.dumps for string search to preserve functionality)
            packet_string = json.dumps(layers)

            for role, msgs in self.role_rules.items():
                for msg in msgs:
                    if msg.lower() in packet_string.lower():
                        self.ip_roles[src_ip] = role
                        return  # Role found, stop processing this packet

            self.extracted_data.append(features)
        except AttributeError:
            # Handle packets without an IP layer gracefully
            pass
        except Exception as e:
            # Handle other potential parsing errors
            print(f"Error processing packet: {e}")

    ##
    # Parses a pcap using cached tshark JSON output if provided, otherwise falls back to loading via rrc_utils.
    # Skips corrupted or unreadable packets.
    #
    # @param [list|None] packets A list of packets in tshark JSON dictionary format. If None, loads them internally.
    # @return [tuple] (extracted_data: list, ip_roles: dict) The list of extracted features and the dictionary of IP roles.
    def parse_pcap(self, packets=None):
        """
        Parses a pcap using cached tshark JSON output if provided, otherwise falls back to loading via rrc_utils.
        Skips corrupted or unreadable packets.
        """
        if packets is None:
            packets = get_cached_packets(self.pcap_file)
            if packets is None:
                print(f"Failed to load packets for {self.pcap_file}")
                return self.extracted_data, self.ip_roles

        for idx, pkt_dict in enumerate(packets):
            try:
                self._process_packet(pkt_dict)
            except Exception as e:
                # Catch-all safety net for unexpected parser errors
                print(f"Error on packet #{idx}, skipping. Details: {e}")
                continue

        print(f"Finished parsing {self.pcap_file}")
        return self.extracted_data, self.ip_roles


##
# Transforms raw packet data into a structured dataset for a deep learning model.
# This class handles Phase 2 of the pipeline: creating time series sequences and normalizing features.
class FeatureEngineer:
    """
    Transforms raw packet data into a structured dataset for a deep learning model.
    This class handles Phase 2 of the pipeline.
    """

    def __init__(self, raw_data, ip_roles):
        self.raw_data = raw_data
        self.ip_roles = ip_roles
        self.df = pd.DataFrame(raw_data)
        self.sequence_length = 5
        self.processed_data = []
        self.labels = []
        self.ip_sequence_map = []
        self.feature_columns = ["timestamp", "packet_len", "protocol_encoded"]

        self.protocol_encoder = LabelEncoder()
        self.label_encoder = LabelEncoder()

    ##
    # Groups the raw packet DataFrame by source IP and generates fixed-length time series sequences
    # (of length `self.sequence_length`) for deep learning model input.
    #
    # @return [None] Populates `self.processed_data` (X) and `self.labels` (y).
    def _prepare_time_series(self):
        """
        Prepares time series sequences from the dataframe.
        """
        if self.df.empty:
            return

        # Group by source IP
        grouped = self.df.groupby("src_ip")

        for ip, group in grouped:
            if ip not in self.ip_roles:
                continue

            # Sort by timestamp to ensure correct sequence
            group = group.sort_values("timestamp")

            for i in range(len(group) - self.sequence_length + 1):
                sequence = group.iloc[i : i + self.sequence_length]
                sequence_features = sequence[self.feature_columns].values
                self.processed_data.append(sequence_features)
                self.labels.append(self.ip_roles[ip])
                self.ip_sequence_map.append((ip, i))

    ##
    # Main function to run all feature engineering steps: handling N/A, encoding protocols,
    # generating sequences, encoding labels, and normalizing numerical features.
    #
    # @return [tuple] (X: np.array|None, y_encoded: np.array|None, class_names: np.array|None, label_encoder: LabelEncoder|None)
    def run_preprocessing(self):
        """
        Main function to run all feature engineering steps.
        """
        if self.df.empty:
            print("No data to process. Exiting.")
            return None, None, None, None

        # Handle missing values
        self.df.fillna(0, inplace=True)

        # Encode categorical features
        self.df = self.df[self.df["protocol"].notna()]
        self.df["protocol"] = self.df["protocol"].astype(str)

        # 👇 CORRECTION: Use the dedicated protocol_encoder
        self.df["protocol_encoded"] = self.protocol_encoder.fit_transform(
            self.df["protocol"]
        )

        # Prepare time series sequences
        self._prepare_time_series()

        if not self.processed_data:
            print("No valid sequences created. Please check data and sequence length.")
            return None, None, None, None

        # Convert to numpy arrays
        X = np.array(self.processed_data)
        y = np.array(self.labels)

        # 👇 CORRECTION: Fit the dedicated label_encoder on ALL possible IP roles (y labels)
        # This includes 'Unidentified' and all rule-based roles to prevent the KeyError/ValueError
        all_possible_roles = list(set(self.ip_roles.values()))
        self.label_encoder.fit(all_possible_roles)

        # Encode labels
        y_encoded = self.label_encoder.transform(y)
        class_names = self.label_encoder.classes_

        # Check if there is more than one class to train on
        if len(class_names) < 2:
            print(
                "Error: The dataset contains only a single class after rule-based labeling. Cannot train a classifier."
            )
            return None, None, None, None

        # Normalize numerical features
        num_features = X.shape[2]
        X_reshaped = X.reshape(-1, num_features)
        scaler = StandardScaler()
        X_reshaped = scaler.fit_transform(X_reshaped)
        X = X_reshaped.reshape(-1, self.sequence_length, num_features)

        # Return the encoder too for completeness
        return X, y_encoded, class_names, self.label_encoder


# class HybridModel(Model):
#     """
#     Hybrid CNN-LSTM model for spatio-temporal feature learning.
#     This class handles Phase 3 of the pipeline.
#     """
#     def __init__(self, sequence_length, num_features, num_classes):
#         super(HybridModel, self).__init__()
#         self.sequence_length = sequence_length
#         self.num_features = num_features
#         self.num_classes = num_classes
#
#         # CNN for spatial/packet-level feature extraction
#         self.conv1d = Conv1D(filters=64, kernel_size=3, activation='relu')
#         self.dropout1 = Dropout(0.2)
#
#         # LSTM for temporal dependency modeling
#         self.lstm = LSTM(128, return_sequences=False)
#         self.dropout2 = Dropout(0.2)
#
#         # Output layer
#         self.dense = Dense(num_classes, activation='softmax')
#
#     def call(self, inputs):
#         x = self.conv1d(inputs)
#         x = self.dropout1(x)
#         x = self.lstm(x)
#         x = self.dropout2(x)
#         return self.dense(x)
#
#     def get_config(self):
#         config = super(HybridModel, self).get_config()
#         config.update({
#             "sequence_length": self.sequence_length,
#             "num_features": self.num_features,
#             "num_classes": self.num_classes
#         })
#         return config
#
#     @classmethod
#     def from_config(cls, config):
#         # Extract only the parameters expected by __init__
#         relevant_config = {
#             "sequence_length": config["sequence_length"],
#             "num_features": config["num_features"],
#             "num_classes": config["num_classes"]
#         })
#         return cls(**relevant_config)

# --- Multiprocessing Implementation (Solution 3) ---


##
# Multiprocessing-safe pipeline worker for PCAP analysis.
# Runs the full analysis pipeline for a single PCAP file, applying rule-based
# classification and feature engineering.
#
# @param [str] pcap_file_path The path to the PCAP file to analyze.
# @param [str] model_name A placeholder for the model name (unused in rule-only pipeline).
# @param [mp.Queue] result_queue The queue to push the final analysis report to.
# @param [list[str]|None] selected_ips Optional list of IPs to filter the analysis to.
# @return [None] Puts the final analysis report into `result_queue`.
def _pipeline_worker(
    pcap_file_path: str,
    model_name: str,
    result_queue: mp.Queue,
    selected_ips: list[str] = None,
):
    """
    Multiprocessing-safe pipeline worker for PCAP analysis.
    Handles:
      - Loading packets
      - Rule-based IP role classification
      - Feature extraction
      - Optional filtering by cluster IPs
      - Returns results via a multiprocessing.Queue
    """

    import time
    import os
    import json
    import glob
    import pandas as pd
    import numpy as np

    # Import rrc_utils safely inside the worker
    try:
        from rrc_utils import (
            get_unique_rrc_ips,
            recognize_oran_ips_roles,
            get_cached_packets,
        )
        from Preprocess import (
            PacketProcessor,
            FeatureEngineer,
        )  # Ensure these classes are visible
    except ImportError as e:
        result_queue.put(
            {
                "status": "failed",
                "message": f"Cannot import required modules: {e}",
                "processing_time": 0,
            }
        )
        return

    start_time = time.time()

    # --- Load packets ---
    packets = get_cached_packets(pcap_file_path)
    if packets is None:
        result_queue.put(
            {
                "status": "failed",
                "message": f"Failed to load packets from {pcap_file_path}.",
                "processing_time": round(time.time() - start_time, 2),
            }
        )
        return

    # --- Phase 1: Packet Parsing & Rule-Based Classification ---
    packet_processor = PacketProcessor(pcap_file_path)
    raw_data, ip_roles = packet_processor.parse_pcap(packets=packets)

    if selected_ips:
        # Filter raw data and roles if only specific IPs are requested
        raw_data = [pkt for pkt in raw_data if pkt.get("src_ip") in selected_ips]
        ip_roles = {ip: role for ip, role in ip_roles.items() if ip in selected_ips}

    if not raw_data:
        result_queue.put(
            {
                "status": "failed",
                "message": "No packets extracted after parsing. Check PCAP file.",
                "total_classified": 0,
                "processing_time": round(time.time() - start_time, 2),
                "classification_summary": [],
            }
        )
        return

    # Add UEs automatically
    try:
        # Uses external utility to identify UE IPs and assign the 'UE' role
        ue_ips = get_unique_rrc_ips(pcap_file_path)
        for ip in ue_ips:
            ip_roles[ip] = "UE"
    except Exception as e:
        print(f"Warning: Failed to retrieve UE IPs: {e}")

    # Map ORAN roles
    try:
        # Uses external utility to identify ORAN component IPs and assign roles
        oran_roles_map = recognize_oran_ips_roles(pcap_file_path)
        for role_key, ip_address in oran_roles_map.items():
            if ip_address:
                final_role = role_key.replace("_ip", "").upper()
                if role_key == "e2_node_ip":
                    final_role = "E2_NODE"
                elif role_key == "ric_client_ip":
                    final_role = "NEAR_RT_RIC"
                if ip_roles.get(ip_address) in ("Unidentified", None) or final_role in (
                    "E2_NODE",
                    "NEAR_RT_RIC",
                    "E2T",
                    "REDIS",
                ):
                    ip_roles[ip_address] = final_role
    except Exception as e:
        print(f"Warning: Failed to recognize ORAN roles: {e}")

    # --- Phase 2: Feature Engineering ---
    feature_engineer = FeatureEngineer(raw_data, ip_roles)
    X, y_encoded, class_names, label_encoder = feature_engineer.run_preprocessing()

    # Prepare rule-based summary
    rule_based_summary = []
    unique_roles, counts = np.unique(list(ip_roles.values()), return_counts=True)
    for role, count in zip(unique_roles, counts):
        ips_for_role = [ip for ip, r in ip_roles.items() if r == role]
        percentage = round((count / len(ip_roles)) * 100, 1) if len(ip_roles) > 0 else 0
        rule_based_summary.append(
            {
                "class_name": role,
                "count": int(count),
                "percentage": percentage,
                "ips": ips_for_role,
            }
        )

    # Save summary results
    try:
        # Note: This is redundant if save_summary_results is called outside the worker, but retained for worker independence.
        results_dir = "./server/results"
        os.makedirs(results_dir, exist_ok=True)
        base_name = os.path.splitext(os.path.basename(pcap_file_path))[0]
        pd.DataFrame(rule_based_summary).to_csv(
            f"{results_dir}/{base_name}.csv", index=False
        )
        with open(f"{results_dir}/{base_name}.json", "w") as f:
            json.dump(rule_based_summary, f, indent=4)
    except Exception as e:
        print(f"Error saving summary: {e}")

    # Clean up any cached PCAP JSON files (used by the file loading utility)
    for file in glob.glob("./generated_pcaps/*.json"):
        os.remove(file)

    end_time = time.time()

    # --- Send final report ---
    final_report = {
        "status": "success",
        "message": "Pipeline completed successfully (rule-based analysis).",
        "total_classified": len(ip_roles),
        "processing_time": round(end_time - start_time, 2),
        "rule_based_classification_summary": rule_based_summary,
        "classification_summary": [],  # No ML-based classification
        "ip_roles": ip_roles,
        "saved_model_path_prefix": None,
    }

    result_queue.put(final_report)


##
# Public function that spawns a new process to run the analysis pipeline and waits for the result via a queue.
# This function isolates the heavy-lifting PCAP processing in a separate process to prevent blocking the main application thread.
#
# @param [str] pcap_file_path The path to the PCAP file.
# @param [str] model_name A placeholder for the model name.
# @param [list[str]|None] selected_ips Optional list of IPs to filter the analysis to.
# @return [dict] The final analysis report from the worker process.
def run_ip_role_pipeline(
    pcap_file_path: str, model_name: str, selected_ips: list[str] = None
) -> dict:
    """
    Public function that spawns a new process to run the pipeline
    and waits for the result via a queue.
    """
    queue = mp.Queue()

    process = mp.Process(
        target=_pipeline_worker, args=(pcap_file_path, model_name, queue, selected_ips)
    )
    print(f"Spawning worker process for PCAP analysis: {pcap_file_path}...")
    process.start()

    # Wait for the process to finish and get the result from the queue
    try:
        analysis_report = queue.get(timeout=300)  # Wait up to 5 minutes

    except mp.queues.Empty:
        # If timeout occurs, terminate the process and return a failure report
        process.terminate()
        process.join()
        return {
            "status": "failed",
            "message": "Pipeline process timed out.",
            "total_classified": 0,
            "processing_time": 300.0,
            "classification_summary": [],
        }

    # Ensure the process is fully terminated and cleaned up
    process.join()

    return analysis_report


##
# Creates a 'results' folder if it doesn't exist and saves the rule_based_summary
# as both CSV and JSON files with unique names based on the PCAP file.
#
# @param [list] rule_based_summary The list of dictionaries containing IP role classification counts.
# @param [str] pcap_file_path The path to the original PCAP file.
# @param [str] model_name A placeholder for the model name (unused in the filename).
# @return [None] Prints success or failure message.
def save_summary_results(rule_based_summary, pcap_file_path, model_name):
    """
    Creates a 'results' folder if it doesn't exist and saves the rule_based_summary
    as both CSV and JSON files with unique names based on the PCAP file and model name.
    """
    try:
        # Create results directory
        results_dir = "./server/results"
        os.makedirs(results_dir, exist_ok=True)

        # Extract base filename from pcap_file_path
        pcap_basename = os.path.splitext(os.path.basename(pcap_file_path))[0]

        # Define file paths
        csv_file = os.path.join(results_dir, f"{pcap_basename}.csv")
        json_file = os.path.join(results_dir, f"{pcap_basename}.json")

        # Convert rule_based_summary to DataFrame
        df_summary = pd.DataFrame(rule_based_summary)

        # Save as CSV
        df_summary.to_csv(csv_file, index=False)
        print(f"Saved rule-based summary to {csv_file}")

        # Save as JSON
        with open(json_file, "w") as f:
            json.dump(rule_based_summary, f, indent=4)
        print(f"Saved rule-based summary to {json_file}")

    except Exception as e:
        print(f"Error saving summary results: {e}")
