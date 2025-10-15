# Preprocess.py
import os
import sys
import time # Used for processing time calculation
import multiprocessing as mp # <-- ADDED for process isolation

# Libraries for packet capture parsing.
try:
    from scapy.all import rdpcap, IP, SCTP
    from scapy.layers.l2 import Ether
    import pandas as pd
    import numpy as np
    import tensorflow as tf
    from tensorflow import keras
    from keras.models import Model
    from keras.layers import Input, Conv1D, LSTM, GRU, Dense, Dropout
    from keras.optimizers import Adam
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    import pyshark
    from pyshark.capture.capture import TSharkCrashException
    
    # Attempt to import rrc_utils, provide a fallback if it's not installed
    # Note: rrc_utils is imported inside the worker function as well for safety
    try:
        from rrc_utils import get_unique_rrc_ips, recognize_oran_ips_roles
    except ImportError:
        print("Warning: 'rrc_utils' not found.")

except ImportError as e:
    print(f"Error importing a required library: {e}")
    print("Please install the required libraries using: pip install scapy pandas numpy tensorflow scikit-learn pyshark")
    sys.exit(1)

# --- Class Definitions ---

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
            'gnB': ['PDUSessionResourceSetupResponse'],
            '5G_Core': ['PDUSessionResourceSetupRequest'],
            'UE': ['SomeRRCpacketThatShowsthisisAUE'],
            'SMF': ['PFCP Session Modification Request','Session Establishment Request'],
            'UPF': ['PFCP Session Modification Response','Session Establishment Response'],
            # 'AMF': ['NGSetupRequest', 'InitialUEMessage', 'NgapPDUSessionResourceSetupRequest']
        }

    def _process_packet(self, pkt):
        """
        Extracts features and applies rule-based logic to assign roles.
        This function performs a detailed, layer-by-layer search for keywords.
        """
        features = {}
        try:
            # Check for IP layer to get basic info
            if 'IP' in pkt:
                src_ip = pkt.ip.src
                features['timestamp'] = 0.0

                features['src_ip'] = src_ip
                # features['dst_ip'] = dst_ip
                features['packet_len'] = pkt.length
                
                # Add the highest-level protocol to the features
                features['protocol'] = pkt.highest_layer
                
                # Check if the IP's role is already determined. If so, return early for efficiency.
                if self.ip_roles.get(src_ip) in self.role_rules.keys():
                    return
                
                # Detailed search for keywords within layers
                packet_string = str(pkt)
                
                for role, msgs in self.role_rules.items():
                    for msg in msgs:
                        if msg.lower() in packet_string.lower():
                            self.ip_roles[src_ip] = role
                            return # Role found, stop processing this packet
                
                self.extracted_data.append(features)
        except AttributeError:
            # Handle packets without an IP layer gracefully
            pass
        except Exception as e:
            # Handle other potential parsing errors
            print(f"Error processing packet: {e}")

    def parse_pcap(self):
        """
        Parses a pcap using Pyshark, skipping corrupted or unreadable packets.
        """
        import pyshark
        from pyshark.capture.capture import TSharkCrashException

        try:
            capture = pyshark.FileCapture(
                self.pcap_file,
                use_json=True,       # safer parsing
                keep_packets=False,  # avoid storing all packets
            )

            for idx, pkt in enumerate(capture):
                try:
                    # Try to process normally
                    if 'IP' in pkt:
                        # Initialize role as 'Unidentified' if not set
                        self.ip_roles.setdefault(pkt.ip.src, 'Unidentified')
                    self._process_packet(pkt)

                except (AttributeError, KeyError) as e:
                    # These mean partial or malformed dissection
                    print(f"⚠️ Skipping malformed packet #{idx}: {e}")
                    continue

                except TSharkCrashException as e:
                    # TShark crashed on this packet
                    print(f"⚠️ Skipping corrupted packet #{idx}: {e}")
                    continue

                except Exception as e:
                    # Catch-all safety net for unexpected parser errors
                    print(f"⚠️ Error on packet #{idx}, skipping. Details: {e}")
                    continue

            capture.close()
            print(f"✅ Finished parsing {self.pcap_file}")
            return self.extracted_data, self.ip_roles

        except TSharkCrashException as e:
            print(f"⚠️ File-level TShark crash (likely truncated pcap). Error: {e}")
            return self.extracted_data, self.ip_roles

        except FileNotFoundError:
            print(f"❌ File not found: {self.pcap_file}")
            return [], {}

        except Exception as e:
            print(f"❌ Unexpected parsing error: {e}")
            return [], {}

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
        self.feature_columns = ['timestamp', 'packet_len', 'protocol_encoded']
        
        # 👇 CORRECTION: Use separate encoders for protocol features and the final y labels
        self.protocol_encoder = LabelEncoder()
        self.label_encoder = LabelEncoder()

    def _prepare_time_series(self):
        """
        Prepares time series sequences from the dataframe.
        """
        if self.df.empty:
            return

        # Group by source IP
        grouped = self.df.groupby('src_ip')
        
        for ip, group in grouped:
            if ip not in self.ip_roles:
                continue
            
            # Sort by timestamp to ensure correct sequence
            group = group.sort_values('timestamp')
            
            for i in range(len(group) - self.sequence_length + 1):
                sequence = group.iloc[i:i + self.sequence_length]
                sequence_features = sequence[self.feature_columns].values
                self.processed_data.append(sequence_features)
                self.labels.append(self.ip_roles[ip])
                self.ip_sequence_map.append((ip, i))

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
        self.df = self.df[self.df['protocol'].notna()]
        self.df['protocol'] = self.df['protocol'].astype(str)
        
        # 👇 CORRECTION: Use the dedicated protocol_encoder
        self.df['protocol_encoded'] = self.protocol_encoder.fit_transform(self.df['protocol'])

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
            print("Error: The dataset contains only a single class after rule-based labeling. Cannot train a classifier.")
            return None, None, None, None
            
        # Normalize numerical features
        num_features = X.shape[2]
        X_reshaped = X.reshape(-1, num_features)
        scaler = StandardScaler()
        X_reshaped = scaler.fit_transform(X_reshaped)
        X = X_reshaped.reshape(-1, self.sequence_length, num_features)
        
        # Return the encoder too for completeness
        return X, y_encoded, class_names, self.label_encoder 

class HybridModel(Model):
    """
    Hybrid CNN-LSTM model for spatio-temporal feature learning.
    This class handles Phase 3 of the pipeline.
    """
    def __init__(self, sequence_length, num_features, num_classes):
        super(HybridModel, self).__init__()
        self.sequence_length = sequence_length
        self.num_features = num_features
        self.num_classes = num_classes
        
        # CNN for spatial/packet-level feature extraction
        self.conv1d = Conv1D(filters=64, kernel_size=3, activation='relu')
        self.dropout1 = Dropout(0.2)
        
        # LSTM for temporal dependency modeling
        self.lstm = LSTM(128, return_sequences=False)
        self.dropout2 = Dropout(0.2)
        
        # Output layer
        self.dense = Dense(num_classes, activation='softmax')
    
    def call(self, inputs):
        x = self.conv1d(inputs)
        x = self.dropout1(x)
        x = self.lstm(x)
        x = self.dropout2(x)
        return self.dense(x)

    def get_config(self):
        config = super(HybridModel, self).get_config()
        config.update({
            "sequence_length": self.sequence_length,
            "num_features": self.num_features,
            "num_classes": self.num_classes
        })
        return config
    
    @classmethod
    def from_config(cls, config):
        # Extract only the parameters expected by __init__
        relevant_config = {
            "sequence_length": config["sequence_length"],
            "num_features": config["num_features"],
            "num_classes": config["num_classes"]
        }
        return cls(**relevant_config)

# --- Multiprocessing Implementation (Solution 3) ---

def _pipeline_worker(pcap_file_path: str, model_name: str, result_queue: mp.Queue):
    """
    The main logic of the pipeline, executed in a separate process.
    Handles PCAP parsing, feature engineering, model training, and reporting.
    """
    start_time = time.time()
    
    print(f"--- Starting Pipeline for PCAP: {pcap_file_path} (Model Name: {model_name}) ---")
    
    # Re-import rrc_utils here to ensure all dependencies are resolved in the new process
    try:
        from rrc_utils import get_unique_rrc_ips
        ue_ips = get_unique_rrc_ips(pcap_file_path)
    except Exception as e:
        print(f"Error calling rrc_utils in worker: {e}")
        result_queue.put({
            "status": "failed",
            "message": f"Error calling rrc_utils: {e}",
            "processing_time": round(time.time() - start_time, 2),
        })
        return
        
    # --- Phase 1: Packet Capture Parsing and Feature Extraction ---
    packet_processor = PacketProcessor(pcap_file_path)
    raw_data, ip_roles = packet_processor.parse_pcap()
        
    if not raw_data:
        print("No data extracted from any source. Exiting pipeline.")
        result_queue.put({
            "status": "failed",
            "message": "No data extracted from PCAP file. Check file path and parsing logic.",
            "total_classified": 0,
            "processing_time": round(time.time() - start_time, 2),
            "classification_summary": []
        })
        return

    for ip in ue_ips:
        ip_roles[ip] = "UE"


    
    oran_roles_map = recognize_oran_ips_roles(pcap_file_path)

    for role_key, ip_address in oran_roles_map.items():
        if ip_address:
            # Clean up the role name for the final output (e.g., 'e2t_ip' -> 'E2T')
            final_role = role_key.replace('_ip', '').upper()
            
            if role_key == 'e2_node_ip':
                final_role = 'E2_NODE'
            elif role_key == 'ric_client_ip':
                final_role = 'NEAR_RT_RIC'
            
            # Assign the role, only if it hasn't been assigned a more specific role already
            if ip_roles.get(ip_address) in ('Unidentified', None):
                 ip_roles[ip_address] = final_role
            # Ensure an IP that is an E2 Node but was previously Unidentified gets the E2 Node role
            elif final_role in ('E2_NODE', 'NEAR_RT_RIC', 'E2T', 'REDIS'):
                 ip_roles[ip_address] = final_role
        
    # --- Phase 2: Feature Engineering and Dataset Preparation ---

    feature_engineer = FeatureEngineer(raw_data, ip_roles)

    rule_based_roles = ip_roles
    rule_based_summary = []
    unique_roles, counts = np.unique(list(rule_based_roles.values()), return_counts=True)
    for role, count in zip(unique_roles, counts):
        ips_for_role = [ip for ip, r in rule_based_roles.items() if r == role]
        percentage = round((count / len(rule_based_roles)) * 100, 1) if len(rule_based_roles) > 0 else 0.0
        rule_based_summary.append({
            "class_name": role,
            "count": int(count),
            "percentage": percentage,
            "ips": ips_for_role
        })

    print("\nFinal IP Roles (before training):")
    for ip, role in ip_roles.items():
        print(f"IP: {ip}, Role: {role}")

    X, y, class_names, label_encoder = feature_engineer.run_preprocessing()
    
    if X is None or y is None:
        print("Dataset preparation failed. Exiting.")
        result_queue.put({
            "status": "failed",
            "message": "Dataset preparation failed. Not enough data or classes to train.",
            "total_classified": 0,
            "processing_time": round(time.time() - start_time, 2),
            "classification_summary": []
        })
        return
    
    # --- Phase 2b: Safe Train/Test Split with small class handling ---
    from collections import Counter
    class_counts = Counter(y)
    min_class_count = min(class_counts.values())
    
    from sklearn.model_selection import train_test_split
    if min_class_count < 2:
        print("⚠️ Warning: Some classes have fewer than 2 samples. Stratified split skipped.")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=None
        )
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
    
    # --- Phase 3: Model Design and Training ---
    sequence_length = X_train.shape[1]
    num_features = X_train.shape[2]
    num_classes = len(class_names)

    model = HybridModel(sequence_length, num_features, num_classes)
    model.compile(optimizer=Adam(learning_rate=0.001),
                  loss='sparse_categorical_crossentropy',
                  metrics=['accuracy'])
                      
    # Early stopping
    early_stopping = tf.keras.callbacks.EarlyStopping(
        monitor='val_loss', patience=10, restore_best_weights=True
    )
    
    print("\nStarting model training...")
    model.fit(X_train, y_train,
              epochs=100,
              batch_size=32,
              validation_split=0.2,
              callbacks=[early_stopping],
              verbose=0)
    
    # --- Phase 4: Validation, Deployment, and Analysis Report ---
    print("\n--- Model Evaluation ---")
    loss, accuracy = model.evaluate(X_test, y_test, verbose=0)

    # Classification summary
    y_pred_probs = model.predict(X_test, verbose=0)
    y_pred_indices = np.argmax(y_pred_probs, axis=1)
    total_classified = len(y_pred_indices)
    y_pred_roles = class_names[y_pred_indices]
    
    unique_roles, counts = np.unique(y_pred_roles, return_counts=True)
    role_to_ips = {}
    for ip, role in ip_roles.items():
        role_to_ips.setdefault(role, []).append(ip)
    classification_summary = []
    for role, count in zip(unique_roles, counts):
        percentage = round((count / total_classified) * 100, 1) if total_classified > 0 else 0.0
        classification_summary.append({
            "class_name": str(role),
            "count": int(count),
            "percentage": percentage,
            "ips": role_to_ips.get(role, [])
        })

    # Model saving
    MODEL_DIR = "models"
    os.makedirs(MODEL_DIR, exist_ok=True)
    full_model_path = os.path.join(MODEL_DIR, f"{model_name}_full_model.keras")
    weights_path = os.path.join(MODEL_DIR, f"{model_name}.weights.h5")

    try:
        model.save(full_model_path)
        model.save_weights(weights_path)
        print(f"\n✅ Model and weights saved successfully in the '{MODEL_DIR}' directory.")
    except Exception as e:
        print(f"\n❌ An error occurred while saving the model: {e}")
        
    end_time = time.time()
    
    # Final report
    final_report = {
        "status": "success",
        "message": f"Pipeline completed. Test Accuracy: {accuracy:.4f}",
        "total_classified": total_classified,
        "processing_time": round(end_time - start_time, 2),
        "rule_based_classification_summary": rule_based_summary,
        "classification_summary": classification_summary,
        "ip_roles": ip_roles,
        "saved_model_path_prefix": os.path.join(MODEL_DIR, model_name)
    }
    
    result_queue.put(final_report)


def run_ip_role_pipeline(pcap_file_path: str, model_name: str) -> dict:
    """
    Public function that spawns a new process to run the pipeline 
    and waits for the result via a queue.
    """
    queue = mp.Queue()
    
    # Create and start the child process
    process = mp.Process(
        target=_pipeline_worker, 
        args=(pcap_file_path, model_name, queue)
    )
    print(f"Spawning worker process for PCAP analysis: {pcap_file_path}...")
    process.start()
    
    # Wait for the process to finish and get the result from the queue
    try:
        analysis_report = queue.get(timeout=300) # Wait up to 5 minutes
            
    except mp.queues.Empty:
        # If timeout occurs, terminate the process and return a failure report
        process.terminate()
        process.join()
        return {
            "status": "failed",
            "message": "Pipeline process timed out.",
            "total_classified": 0,
            "processing_time": 300.0,
            "classification_summary": []
        }
    
    # Ensure the process is fully terminated and cleaned up
    process.join()
    
    return analysis_report