# Network Traffic Analysis & 5G/O-RAN Profiling Service

**A full-stack application for analyzing, clustering, and profiling 5G and O-RAN network traffic using machine learning and rule-based heuristics.**

This project provides a sophisticated backend for **Deep Packet Inspection (DPI)**, **Role Classification**, and **PCAP Generation**, paired with a modern **Vue.js + Vuetify** frontend for real-time visualization and interactive analysis.

---

## Key Features

### **1. Advanced 5G & O-RAN Analysis**

Unlike generic analyzers, this tool is optimized for next-gen mobile networks:

- **5G Core Identification:** Identifies AMF, SMF, UPF, and UDM using **HTTP/2 SBI (Service Based Interface)** signatures (e.g., `/namf`, `/nsmf`).
- **O-RAN Component Detection:** Detects Near-RT RIC, E2 Nodes, and E2T traffic using **E2AP procedure codes** and specific ports (e.g., 38000 for E2T, 6379 for Redis).
- **Control Plane Analysis:** Parses **NGAP** (gNB AMF) and **PFCP** (SMF UPF) signaling to map network topology.
- **UE Session Extraction:** Extracts IMSI, GUTI, SUCI, and PDU Session IDs using `pyshark`.

### **2. Frontend Visualization (Vue.js + Vuetify)**

- **Real-Time Sniffer:**
- Live packet capture via WebSocket (`ws://127.0.0.1:5001`).
- Interactive interface selection and buffer management.
- Live metrics: Packets/sec, total data size, and raw packet logs.

- **Analysis Wizard:** A step-by-step interface for processing PCAPs:

1. **Clustering:** Force-directed graph visualization with **Graph Modularity** optimization to suggest the ideal number of clusters ().
2. **Profiling:** Rule-based and ML classification of IP roles.
3. **Results:** Export roles and hierarchies to JSON or CSV.

- **Network Graphs:** High-performance topology rendering using **Apache ECharts**.

### **3. Machine Learning Pipeline**

- **Feature Engineering:** Extracts packet length, protocol sequences, and timestamps.
- **Role Classification:** Hybird approach using **DPI rules** (headers, ports) and **ML sequencing** to label nodes (e.g., "gNB", "Malicious", "Unknown").

### **4. Privacy Metrics**

- **Privacy Metrics Dashboard:** New section in `analyze.vue` to compute and compare privacy metrics before/after anonymization.
- **Supported Metrics:** Calculates **k-anonymity**, **l-diversity**, and **t-closeness** on selected identifier groups.
- **Anonymization Controls:** Lets users apply **pseudonymization**, **generalization**, and **suppression** per selected columns.
- **API Support:** Includes a dedicated `POST /privacy-metrics` endpoint for metric computation and transformed-record previews.

---

## Architecture

```text
├── client/ (Vue.js)
│   ├── views/
│   │   ├── realTime.vue       # Live WebSocket capture & PCAP generation
│   │   ├── clustering.vue     # Multi-step analysis wizard
│   │   └── analyze.vue        # Quick static PCAP analysis
│   ├── components/
│   │   ├── NetworkGraph.vue   # ECharts topology visualizer
│   │   ├── ModularityChart.vue# Elbow method visualization
│   │   └── stepper/           # Wizard sub-components
│   └── ...
├── server/ (Flask)
│   ├── app.py                 # API Entry point
│   ├── rrc_utils.py           # 5G/O-RAN extraction logic (TShark wrappers)
│   ├── Preprocess.py          # ML Feature extraction & Pipeline
│   ├── role_assessment.py     # Rule-based heuristics
│   ├── ueAnalysis.py          # UE identifier extraction
│   └── pcap_generator_service.py # Packet reassembly service
├── Dockerfile                 # Container configuration
└── Makefile                   # Documentation build tools

```

---

## Installation & Setup

### Prerequisites

- **Python 3.10+**
- **Wireshark/TShark:** Required for the backend to parse specific 5G fields.
- _Ubuntu:_ `sudo apt install tshark`
- _Windows:_ Install Wireshark and ensure `tshark` is in your PATH.

### Option A: Running with Docker (Recommended)

The project includes a `Dockerfile` for easy deployment.

1. **Build the image:**

```bash
docker build -t network-analyzer .

```

2. **Run the container:**

```bash
docker run -p 5000:5000 network-analyzer

```

_The API will be available at `http://127.0.0.1:5000`._

### Option B: Local Development

1. **Install Python Dependencies:**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r server/requirements.txt
```

If you prefer not to use a virtual environment, you can install directly:

```bash
pip install -r server/requirements.txt
```

### System dependencies

This project requires `tshark` for role classification and deep packet inspection.

On macOS (Homebrew):

```bash
brew install wireshark
```

2. **Run the Flask Server:**

```bash
python3 server/app.py
```

Or via npm:

```bash
npm run api
```

You can override the API port (default 5000) with:

```bash
PORT=5001 python3 server/app.py
```

### 4. Run the frontend (Nuxt)

```bash
npm install
HOST=0.0.0.0 PORT=3000 npm run dev
```

The frontend uses these env vars (optional):

```bash
API_BASE_URL=http://127.0.0.1:5001
WS_URL=ws://127.0.0.1:5001
```

Server starts at:

```
http://127.0.0.1:5000
```

Swagger Docs:

```
http://127.0.0.1:5000/apidocs/
```

---

## Environment Variables

| Variable             | Description                   | Default                  |
| -------------------- | ----------------------------- | ------------------------ |
| `PCAP_OUTPUT_DIR`    | Directory for generated PCAPs | `server/generated_pcaps` |
| `MAX_CONTENT_LENGTH` | Max upload size               | `1GB`                    |

```bash
npm install
npm run dev

```

---

## API Overview

### **Core Analysis**

- `POST /automated-analysis`: Upload a PCAP for full stack analysis (Stats, Graph, UE, Roles).
- `POST /clustering`: Perform agglomerative clustering on network nodes.
- `POST /run_pipeline`: Trigger the ML/Rule-based classification pipeline.

### **Real-Time & PCAP Generation**

- `POST /save-pcap`: Stream Base64 packet chunks to build a PCAP file on the server.
- `GET /generated_pcaps/<filename>`: Download the assembled PCAP.

### **Utilities**

- `GET /suggested_clusters`: Calculates the "Elbow" or modularity peak to suggest clusters.
- `POST /save_roles`: Export identified network roles to CSV/JSON.
- `POST /privacy-metrics`: Compute k-anonymity, l-diversity, and t-closeness after optional anonymization transforms.

---

## Documentation

The project uses Sphinx for documentation.

```bash
# Build documentation
make html

```

---

**2025 © UTH – XTRUST-6G**
