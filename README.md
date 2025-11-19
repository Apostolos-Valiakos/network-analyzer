# Network Traffic Analysis & PCAP Generation Service

**Flask API for uploading, analyzing, generating, and processing PCAP files**

This project provides a full-featured backend service for **network traffic analysis**, **PCAP ingestion & generation**, **role classification**, **UE session extraction**, **clustering**, and **automated packet-capture pipelines**. It exposes a REST API with Swagger documentation and integrates several analytical modules to process packet captures efficiently.

---

## Features

### **PCAP Handling**

- Upload PCAP files (`/analyze`)
- Analyze saved/generated PCAPs
- Stream packets in Base64 and assemble into PCAP (`/save-pcap`)
- Download generated PCAP files

### **Network Analysis**

- Total packet statistics
- IP protocol breakdown
- Network conversation graph (JSON)
- UE session extraction
- Role assessment (rule-based + ML)
- Machine Learning IP role classification pipeline

### **Clustering & Anomaly Detection**

- Agglomerative clustering on PCAPs
- Elbow method for optimal cluster suggestion
- Cluster hierarchy & importance scoring
- Export clustering results to JSON/CSV

### **Automated Pipeline**

- Fully automated PCAP analysis (`/automated-analysis`)
- Long-running WebSocket-based sniffing pipeline (`/start-analysis-from-websocket`)
- Background capture + analysis + result export

### **Developer-friendly**

- Built with **Flask**, **Scapy**, **Pandas**, and custom analysis modules
- Automatic Swagger UI available at: **`/apidocs/`**

---

## Project Structure

```
server/
├── uploads/              # Temporary uploaded user files
├── generated_pcaps/      # PCAP files created from streamed packets
├── cluster_analysis/     # Stored clustering results (json/csv)
├── results/              # ML pipeline results
├── app.py                # Main Flask server
└── analysis modules...   # pcap_analysis, ueAnalysis, etc.
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Apostolos-Valiakos/network-analyzer
cd network-analyzer
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the server

```bash
python app.py
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
export PCAP_OUTPUT_DIR="mydir/"
```

---

## API Overview

### **Upload & Analyze PCAP**

`POST /analyze` – Protocol analysis, conversation graph, UE sessions

### **Streamed PCAP Assembly**

`POST /save-pcap` – Send Base64 packet chunks incrementally

### **Download Assembled PCAP**

`GET /generated_pcaps/<filename>`

### **Clustering**

`POST /clustering` – Run agglomerative clustering
`GET /suggested_clusters` – Elbow method
`POST /save-results` – Save clustering output

### **Machine Learning Role Classification**

`POST /run_pipeline`

### **Automated end-to-end pipeline**

`POST /automated-analysis`

### **WebSocket Packet Capture**

`POST /start-analysis-from-websocket`

---

## Dependencies / External Modules

- `pcap_analysis` – Packet parsing & statistics
- `ueAnalysis` – UE session extraction
- `role_assessment` – Rule-based IP role detection
- `Preprocess` – ML preprocessing
- `agglomerative_clustering` – Clustering engine
- `graph_builder` – Conversation graph
- `connectToWebsocket` – WebSocket capture

---

# Vue Frontend – Capabilities Overview

The frontend provides a clean, modern, and minimalistic interface for interacting with the network traffic analysis backend. It is built using Vue.js and TailwindCSS.

## Frontend Capabilities

### **1. PCAP File Upload**

- Users can select and upload `.pcap` files directly from the browser.
- Input validation ensures only valid PCAPs can be analyzed.

### **2. Trigger Backend Network Analysis**

- A single **Analyze** button sends the uploaded file to the `/analyze` endpoint.
- Displays a loading state while the server processes the PCAP.

### **3. Display of Analysis Results**

Once the backend responds, the frontend displays:

- **Total packets** processed
- **IP protocol statistics** (TCP/UDP/ICMP breakdown, etc.)
- **UE session list** extracted from the PCAP

All results are shown in a clean, structured layout.

### **4. Download Generated PCAP**

- A **Download PCAP** button retrieves the newly assembled/generated PCAP created by the backend.
- Uses a direct link to the `/generated_pcaps/<filename>` endpoint.

### **5. Responsive & Accessible UI**

- Fully responsive layout using Tailwind CSS
- Dark mode theme (gray + purple accent)
- Accessible buttons, clean spacing, readable typography
