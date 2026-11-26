# Network Analyzer (PENM)

**Privacy Enhanced Network Monitor: 5G / 6G traffic analysis platform**
Developed by the University of Thessaly for the XTRUST-6G project.

PENM analyses 5G and 6G network traffic from uploaded captures or a live
capture sensor. It identifies what each IP address is (gNB, AMF, SMF, UPF, UE,
O-RAN components…), extracts UE identities, groups devices by behaviour,
measures privacy risk, monitors the live network and scans devices with Nmap.

## Documentation

Start at **[docs/index.html](docs/index.html)**. It links to:

| Guide | For |
|---|---|
| [Deployment Guide](docs/deployment.html) | Installing with Docker, the capture sensor, updates, backups, troubleshooting |
| [User Guide](docs/user-guide.html) | Every page of the web application |
| [API Guide](docs/api-guide.html) | Logging in, `/apidocs`, every endpoint, errors and limits |
| [Developer Guide](docs/developer-guide.html) | Code layout, local setup, architecture, tests, releases |

`CLAUDE.md` summarises the conventions for contributors.

## Features

| Feature | Description |
|---|---|
| Capture analysis | Packet and conversation statistics, network graph, per-IP protocol stacks |
| IP role assessment | Evidence-based classification of 5G core functions, O-RAN components, UEs and other hosts, with confidence and reasoning |
| UE identities | IMSI (also from null-scheme SUCI), 5G-TMSI, PDU session and the UE's IP address |
| Clustering | Agglomerative clustering with modularity-based choice of the number of clusters and anomaly flags |
| Privacy metrics | k-anonymity, l-diversity and t-closeness, before and after pseudonymisation, generalisation and suppression |
| Continuous monitoring | Zeek flow statistics from the sensor, live role snapshots, pcap downloads, CSV/JSON export |
| Real-time capture | Live packets from the sensor in the browser, saved and analysed |
| Active probing | Nmap scans (fast, version, vulnerability) run from the sensor |
| API | REST API with interactive documentation at `/apidocs`; XTRUST-6G WP5 alerts |

## Architecture

```
 Browser ──► frontend (Nuxt 2 SPA, nginx :80) ──► backend (Flask, gunicorn :5555) ──► PostgreSQL + TimescaleDB
                                                     ▲   │
                         Zeek flows (X-Internal-Token)│   │ pcap slices, Nmap (:5005)
                                                     │   ▼
                               capture sensor (dumpcap, Zeek, pcap_server, publisher :5002)
```

## Quick start (Docker)

```bash
cp .env.example .env        # set DB_PASSWORD, JWT_SECRET_KEY, SECRET_TOKEN, ADMIN_PASSWORD, API_BASE_URL…
docker compose up -d --build
```

Open `http://<server>` and log in with `ADMIN_USERNAME` / `ADMIN_PASSWORD`.
The sensor, remote access, updates and every setting are in the
[Deployment Guide](docs/deployment.html).

## Project structure

```
components/, pages/, plugins/, store/, utils/, layouts/, middleware/   Nuxt frontend
server/                     Flask backend (app.py, wsgi.py, blueprints/, migrations/, docs/*.yml)
Host Files/                 Sensor scripts (pcap_server.py, zeek_agent.py, publisher.py)
deploy/k8s/                 Kubernetes testbed manifests and image Dockerfiles
tests/backend, tests/frontend   pytest and Jest suites
docs/                       Documentation (start at docs/index.html)
```

## License

MIT License. Copyright © 2025 University of Thessaly.
