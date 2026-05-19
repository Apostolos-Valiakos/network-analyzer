# Network Analyzer

**5G / 6G Network Traffic Analysis & Intelligence Platform**  
Developed by the University of Thessaly

---

## Overview

Network Analyzer is a full-stack research platform for deep inspection,
clustering, and role classification of 5G and 6G network traffic. It
accepts uploaded PCAP files or a live Zeek telemetry stream from a sensor
VM, runs automated analysis pipelines, and presents results through
interactive dashboards.

---

## Features

| Feature | Description |
|---|---|
| PCAP Upload & Analysis | Protocol distribution, conversation stats, interactive network graph |
| Agglomerative Clustering | Unsupervised grouping by traffic behaviour; modularity-based auto k-selection |
| IP Role Assessment | Rule-based classification: 5G Core NF, O-RAN, UE, external server, unknown |
| UE Session Tracking | Extracts IMSI, GUTI, and IPv4 per user equipment from control-plane traffic |
| Real-Time Monitoring | Live Zeek flow ingestion via host agent; WebSocket anomaly alerts |
| Nmap Scan Integration | On-demand network scans proxied through the sensor VM |
| Export | Clustering results and role reports as CSV or JSON |
| Swagger UI | Interactive API documentation at `/apidocs` — no login required |

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│              Browser  (Nuxt 2 / Vue 2 SPA)   :3000         │
│  Analyze · Clustering · Real Time · Monitoring · Admin     │
└─────────────────────────┬──────────────────────────────────┘
                          │  REST + WebSocket (Socket.IO)
┌─────────────────────────▼──────────────────────────────────┐
│          Flask API  (server/app.py)   :5555                 │
│  JWT auth · Flask-SocketIO · Flasgger Swagger UI           │
│  PCAP analysis · Clustering · Role pipeline · Zeek ingest  │
└───────────┬────────────────────────────┬───────────────────┘
            │ SQLAlchemy                 │ psycopg2 bulk insert
┌───────────▼────────────────────────────▼───────────────────┐
│         PostgreSQL 14 + TimescaleDB   :5432                 │
│  users · pcap_files · flow_statistics (hypertable)          │
│  role_snapshots · ue_sessions · cluster_results             │
└─────────────────────────▲──────────────────────────────────┘
                          │  X-Internal-Token
┌─────────────────────────┴──────────────────────────────────┐
│       Host Sensor VM  (Host Files/)   :5005                 │
│  zeek_agent.py  →  POST /v1/ingest/zeek                     │
│  start_sensor.sh — tcpdump capture + Nmap async service     │
└────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Node.js | ≥ 18 | For the Nuxt frontend |
| Python | ≥ 3.10 | For the Flask backend |
| PostgreSQL | ≥ 14 | Main database |
| TimescaleDB | ≥ 2.x | PostgreSQL extension — auto-enabled on first start |
| tshark | any recent | Packet dissection cache used by analysis pipeline |
| Zeek | ≥ 6.x | Optional — required only for Continuous Monitoring |
| Nmap | any | Optional — required only for Nmap scan feature |

---

## Configuration

### Backend — `server/.env`

```env
# Required
JWT_SECRET_KEY=change-me-to-a-long-random-string

# Database (defaults to local PostgreSQL)
DATABASE_URL=postgresql://postgres:pass@localhost:5432/network_analyzer

# Internal token shared between app.py and the sensor VM agents
SECRET_TOKEN=change-me-to-another-random-string

# Seeds the first admin account on startup (only if no admin exists yet)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme123

# CORS — comma-separated allowed origins
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# Flask server port (default: 5555)
PORT=5555
```

### Frontend — `.env`

```env
VUE_APP_API_BASE_URL=http://127.0.0.1:5555
VUE_APP_REALTIME_BASE_URL=http://127.0.0.1:5555
```

---

## Installation

### 1. Database

```bash
createdb network_analyzer
# TimescaleDB extension and all tables are created automatically
# by the server on first startup.
```

### 2. Backend

```bash
cd server
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt

# Create server/.env and fill in the values above
python app.py
```

The server starts on `http://127.0.0.1:5555`.

### 3. Frontend

```bash
# From the project root
npm install
npm run dev          # development server at http://localhost:3000

# Production build
npm run build && npm run start
```

### 4. Host Sensor VM (optional — Continuous Monitoring only)

The sensor VM exposes a small Flask service on port 5005 and runs a Zeek
agent that forwards parsed `conn.log` entries to the main API.

```bash
cd "Host Files"

# Start the tcpdump / Nmap service
bash start_sensor.sh

# Start the Zeek flow agent
# Configure SECRET_TOKEN and the API URL inside the script to match server/.env
python zeek_agent.py
```

---

## API Documentation

Interactive Swagger UI:

```
http://127.0.0.1:5555/apidocs
```

No login is required to browse the documentation. Endpoints that require a
JWT Bearer token are marked with a lock icon. Use the **Authorize** button
in the UI to supply your token for live testing.

**Obtain a token:**

```http
POST http://127.0.0.1:5555/auth/login
Content-Type: application/json

{ "username": "admin", "password": "changeme123" }
```

---

## API Endpoint Summary

### Authentication

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/auth/login` | — | Obtain a JWT access token |
| POST | `/auth/register` | Admin JWT | Create a new user account |
| GET | `/auth/users` | Admin JWT | List all users |
| DELETE | `/auth/users/<id>` | Admin JWT | Delete a user |

### PCAP Management

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/save-pcap` | JWT | Stream Base64 packet chunks to assemble a PCAP |
| GET | `/generated_pcaps/<filename>` | JWT | Download a stored PCAP file |

### Analysis

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/analyze-saved-pcap/<filename>` | JWT | Protocol stats + network graph for a stored PCAP |
| POST | `/automated-analysis` | JWT | Upload a PCAP, run full analysis + role pipeline |
| POST | `/start-analysis-from-websocket` | JWT | Capture from a WebSocket URL then run pipeline |

### Clustering

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/suggested_clusters?file=` | JWT | Modularity-based optimal k suggestion |
| POST | `/clustering` | JWT | Run agglomerative clustering |
| POST | `/save-results` | JWT | Persist clustering results (CSV + JSON) |
| GET | `/clustering-output/<filename>` | JWT | Download a saved clustering result |
| POST | `/run_pipeline` | JWT | Run the IP role classification pipeline |
| GET | `/save_roles?file=&type=` | JWT | Download role report as JSON or CSV |

### Continuous Monitoring

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/v1/ingest/zeek` | X-Internal-Token | Receive Zeek flow batches from the sensor VM |
| GET | `/v1/network/statistics` | JWT | Query time-series flow statistics |
| GET | `/v1/network/roles/latest` | JWT | Latest IP role snapshot |
| GET | `/v1/network/pcap/headers` | JWT | Fetch headers-only PCAP from sensor for a time range |
| GET | `/v1/network/pcap/latest/full` | JWT | Fetch the latest full-payload PCAP from sensor |
| GET | `/v1/network/export` | JWT | Export flow data as CSV or JSON |
| POST | `/v1/analyze_live` | JWT | Run role pipeline on the latest captured PCAP |
| POST | `/v1/scan/start` | JWT | Trigger an Nmap scan on the sensor VM |
| GET | `/v1/scan/results` | JWT | Retrieve Nmap scan results |

---

## Project Structure

```
network-analyzer/
├── components/          # Vue components (AppHeader, stepper steps, charts)
├── Host Files/          # Sensor VM agents (zeek_agent.py, start_sensor.sh)
├── layouts/             # Nuxt layouts (default.vue with theme CSS variables)
├── middleware/          # Nuxt auth middleware
├── pages/               # Nuxt page components
│   ├── index.vue        # Home / dashboard
│   ├── analyze.vue      # PCAP upload & analysis
│   ├── clustering.vue   # Clustering stepper
│   ├── realTime.vue     # Real-time WebSocket capture
│   ├── continuous_monitoring.vue
│   ├── about.vue
│   ├── contact.vue
│   ├── login.vue
│   └── admin/users.vue
├── plugins/             # Nuxt plugins (auth, api fetch wrapper)
├── server/
│   ├── app.py           # Main Flask application
│   ├── models.py        # SQLAlchemy models
│   ├── requirements.txt
│   ├── docs/            # Swagger YAML definitions per endpoint
│   ├── agglomerative_clustering.py
│   ├── pcap_analysis.py
│   ├── Preprocess.py    # IP role classification pipeline
│   ├── role_assessment.py
│   ├── graph_builder.py
│   ├── ueAnalysis.py
│   └── snapshot_scheduler.py
├── store/               # Vuex store (auth module)
├── nuxt.config.js
└── package.json
```

---

## License

MIT License — Copyright © 2025 University of Thessaly
