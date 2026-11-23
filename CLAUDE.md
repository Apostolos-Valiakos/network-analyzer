# CLAUDE.md

PENM (Privacy Enhanced Network Profiler/Monitor), a University of Thessaly research platform (XTRUST-6G) that analyses 5G/6G traffic: role classification of IPs (gNB, AMF, UPF, UE, O-RAN…), UE identity extraction, clustering, privacy metrics, continuous monitoring from a capture sensor, and Nmap probing.

Ask clarifying questions before making code changes in this repo (the user's standing request).

## Layout

| Path | What |
|---|---|
| `server/` | Flask backend (Python 3.10 in Docker). Entry: `app.py` (`create_app()`), `wsgi.py` (gunicorn) |
| `server/blueprints/` | All HTTP routes, one blueprint per area: auth, pcaps, privacy, clustering, analysis, monitoring, scan, history. No URL prefixes |
| `server/docs/*.yml` | Swagger (flasgger, Swagger 2.0) per route, attached with `@swag_from(doc("x.yml"))` |
| `server/migrations/` | Alembic (Flask-Migrate). `0001_baseline` is idempotent against pre-Alembic databases |
| `pages/`, `components/`, `store/`, `plugins/`, `utils/`, `layouts/`, `middleware/` | Nuxt 2 / Vue 2.7 / Vuetify 2 SPA (`ssr: false`, built with `nuxt generate`, served by nginx) |
| `Host Files/` | Capture sensor scripts: `pcap_server.py` (:5005 pcap slices + Nmap), `zeek_agent.py` (ships `conn.log` to the backend), `publisher.py` (:5002 raw WebSocket for the Real Time page), `tuning.zeek`, `start_sensor.sh` (bare-metal start) |
| `tests/backend/`, `tests/frontend/` | pytest and jest suites |
| `docker-compose.yml` | Production-style stack: `db` (TimescaleDB pg14), `backend`, `frontend` |
| `docker-compose.sensor.yml` | Sensor container (host network), built from `deploy/k8s/images/sensor/Dockerfile` |
| `deploy/k8s/` | Single-node Kubernetes testbed: Open5GS, srsRAN, FlexRIC (`10-5g`) and PENM (`20-penm`), image Dockerfiles, `scripts/build-images.sh` |
| `r13/` | XTRUST-6G R13 (C-XDR Cluster Manager) worker-node integration. **Gitignored**: no history, back up before big edits |
| `docs/` | **Gitignored** (some files force-added): `DOCKER_SETUP.md`, operator/user/installation guides (HTML), `k8s-testbed/index.html` |

## Commands

```bash
# Backend tests (from repo root; pytest.ini points at tests/backend)
pip install -r server/requirements.txt -r tests/requirements.txt
pytest                              # all
pytest -m "not integration"         # skip tests needing real tshark / scapy
pytest --update-snapshots           # re-record golden files; review the diff before committing
PENM_TEST_POSTGRES_URL=postgresql://.../penm_test pytest   # also run Postgres-only tests (DB name must contain "test"; it is wiped)

# Frontend tests
npx jest --config tests/frontend/jest.config.js

# Run locally
python server/app.py                # dev server on :5555 (needs JWT_SECRET_KEY, DATABASE_URL)
npm run dev                         # Nuxt dev server
NODE_OPTIONS=--openssl-legacy-provider npm run generate   # needed on Node 17+ (webpack 4)

# Docker
docker compose up -d --build
docker compose -f docker-compose.sensor.yml up -d
```

There is no CI and no linter config; run the relevant tests yourself.

## Backend architecture

- **App factory**: `create_app(init_database=True)` builds the app with no import side effects. Pipeline child processes (`multiprocessing`, in `Preprocess.py`) re-import modules and use `db_setup.database_only_app()`. On start, `db_setup.init_database` runs migrations, enables TimescaleDB (`flow_statistics` hypertable) and seeds the admin from `ADMIN_USERNAME`/`ADMIN_PASSWORD`, under a Postgres advisory lock.
- **Production**: gunicorn with **1 worker, 100 threads** (`server/Dockerfile`). One worker on purpose: Socket.IO clients and the rate limiter live in process memory.
- **Extensions** (`extensions.py`): `jwt`, `limiter`, `socketio`, created unbound and bound in `create_app`.
- **Auth**: flask-jwt-extended, `Authorization: Bearer <JWT>`, 8 h tokens from `POST /auth/login`. Admin checks in `access.py`. Sensor <-> backend calls use `X-Internal-Token` = `SECRET_TOKEN` (`settings.sensor_headers()`); `/v1/ingest/zeek` takes that token, not a JWT.
- **Settings** (`settings.py`): absolute output dirs (`uploads`, `generated_pcaps`, `cluster_analysis`, `results`), `doc()`, and `sensor_url()` / `secret_token()` read from the environment **on every call** (tests rely on this).
- **One tshark pass per capture** (`packet_table.py`): a `tshark -T fields` run extracts the union of all modules' fields into a cached `<pcap>.packets.tsv`. The header holds size/mtime/field list, so a changed capture or field list re-extracts. Roles, privacy, graph, clustering features and UE extraction all read it. `tshark.py` finds tshark (`TSHARK_PATH`, PATH, Windows registry/defaults). The backend has no other packet library: pyshark and Scapy are gone (`/analyze-saved-pcap`'s per-IP protocol stacks come from `frame.protocols` via `pcap_analysis.protocol_label`). The sensor's `publisher.py` still uses Scapy, installed in the sensor image only.
- **Role engine** (`role_engine.py`): direction-aware evidence (NGAP 38412 listener = AMF, E2AP 36421/36422 = RIC, PFCP direction from message type, SBI `:path` destination serves that NF; NRF status-notify excluded; ICMP frames skipped), then a declarative rule table gives one best role per IP with confidence, reasoning and runner-ups.
- **Monitoring** (`blueprints/monitoring.py`): Zeek flows ingested into `flow_statistics` (naive UTC datetimes), statistics/export as JSON or CSV, and pcap endpoints that proxy the sensor's `/get-pcap`. `snapshot_scheduler.start_scheduler` is currently a no-op (scheduler commented out).
- **WP5 notices** (`wp5_notices.py`): the analyzer's own alerts as Zeek `Notice::Info` JSON lines in `WP5_NOTICE_LOG`, forwarded to R13. Never let tests or experiments write to the real log.

## Conventions and gotchas

- **Swagger**: every route has a `server/docs/<name>.yml`. Protected routes need `security: [{Bearer: []}]` there, or Swagger UI will not send the token. In `/apidocs` the user must enter `Bearer <token>`: the scheme is `apiKey`, so the value is sent verbatim.
- **Snapshot tests** (`tests/backend/snapshot_utils.py`, `snapshots/*.json`) pin current behaviour, including `web_*` snapshots of the route table, the Swagger spec and CORS. Changing a route, a Swagger yml or analysis output means re-recording with `--update-snapshots` and reviewing the diff. Snapshots record tool versions (tshark). The main file is the dev machine's (tshark 4.6). The production image's version (tshark 4.4) are recorded either as a `same_output_with` mark in the main file or as a `<name>.tshark-4.4.json` variant. Unrecorded versions **skip** (not fail). After changing analysis output, re-record locally first (a changed main file drops its marks), then in the production image:
  ```bash
  docker run --rm -v "<repo>:/repo" -w /repo --entrypoint sh network-analyzer-backend:latest \
    -c 'pip install -q -r tests/requirements.txt && python -m pytest --update-snapshots'
  ```
  The fixtures are `sample.pcap` and `ppc_5g_and_oran.pcap`.
- **Patching in tests**: patch where it is used, e.g. `blueprints.<area>.X`. The pipeline is patched as both `analysis_service.run_ip_role_pipeline` and `blueprints.analysis.run_ip_role_pipeline`. Do not alias blueprint objects to module names in `blueprints/__init__.py`, or patching breaks.
- **Test isolation**: `conftest.py` forces `WP5_NOTICE_LOG` to a temp file. It also turns rate limiting off (`limiter.enabled = False`). Tests running the pipeline must monkeypatch `settings.RESULTS_OUTPUT_DIR`.
- **Partial failures**: never swallow an exception silently. Log it with a traceback (`logger.exception`). If the rest of the request still succeeds, add a user-readable message to a `warnings` list in the response. Add the key only when non-empty, so normal responses and snapshots stay unchanged. The frontend shows it with `components/WarningsAlert.vue`. Role detection passes warnings through `get_or_compute_roles(..., warnings=[])` and the pipeline report, and partial roles are not cached. Bad request parameters are 400, server errors 500.
- **Time**: stored datetimes are naive UTC; API timestamps are Unix epoch seconds. tshark 4.6 `-T json` gives `frame.time_epoch` as an ISO string (use `-T fields`).
- **Frontend**: call the backend through `plugins/api.js` (`this.$api.url()`, `.json()`, `$apiFetch`, which adds the Bearer token and logs out on any 401). `API_BASE_URL` and `WS_URL` are **baked in at build time**, and nginx's CSP (`nginx.conf.template`) allows only those addresses, so changing either means rebuilding the frontend image. `WS_URL` is the Real Time page's `publisher.py` address, not Socket.IO. Jest uses `@vue/vue2-jest`: templates cannot use `?.`. Many Vuetify 3-style props remain and do nothing; fix only what breaks.
- **`package-lock.json` is gitignored**: building the frontend on a clean checkout can resolve different dependency versions (webpack 5 breaks Nuxt 2). Prefer building where the lockfile exists.
- **Incomplete captures**: a capture copied mid-write ends in a partial record or zeros. `pcap_repair.trim_incomplete_tail` trims stored files (on upload, Real Time save, scheduler download, and on load in `packet_table._load`). Never trim the file dumpcap is writing: the sensor uses `pcap_repair.complete_length` and sends or merges only the complete prefix. The sensor image copies `server/pcap_repair.py` (see `deploy/k8s/images/sensor/Dockerfile.dockerignore`).
- **Sensor**: `pcap_server.py` picks ring files `continuous_capture_*.pcap` from `Host Files/generated_pcaps` by time window. Backend env `SENSOR_URL` (default `http://172.18.0.1:5005`, the Docker bridge to the host) must reach it, and `SECRET_TOKEN` must match on both sides.
- **Secrets**: never commit `.env`, tokens, `r13/secrets/`, or Open5GS hnet keys. `Host Files/start_sensor.sh` still has a hardcoded `SECRET_TOKEN` default that is in git history: treat that value as compromised.
- **Dev machine** (Windows): tshark at `E:\Wireshark`, and the C: drive is nearly full (Docker Desktop and `%TEMP%` live there), so large builds or uploads can fail for lack of space.

## Deployment notes

- **Production server** (Docker Compose): images are built on a workstation, shipped with `docker save | gzip`, then `docker load` and `docker compose up -d --no-build backend frontend` run from the folder that holds `docker-compose.yml`. Procedure, backup and rollback are in `docs/DOCKER_SETUP.md` §9; the sensor is in §10.
- **Kubernetes testbed**: `docs/k8s-testbed/index.html` is the step-by-step guide. Namespaces `team-5g` / `team-penm`, Cilium with Hubble, and pinned CU/DU/FlexRIC versions (keep them).
- **R13**: see `r13/README.md` and `r13/INTEGRATION_GUIDE.md`. The node registers as engine `penm`, role `worker`, over HTTPS with OCSP stapling, ships alerts with syslog-ng over TLS on 6514, and is controlled through `penmctl` over SSH on 2222. There is deliberately no switch to skip the TLS/OCSP checks.
