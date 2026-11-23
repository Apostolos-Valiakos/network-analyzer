# PENM — Docker Deployment Guide

Full step-by-step guide for deploying the Privacy Enhanced Network Monitor
(frontend + backend + database) with Docker on a Linux machine.

---

## What gets created automatically

You do **not** need to create the database, user, or tables manually.
Docker and the app handle everything:

| Step                                                            | Who does it                          | When                          |
| --------------------------------------------------------------- | ------------------------------------ | ----------------------------- |
| Create the `network_analyzer` database                          | TimescaleDB container (via env vars) | On first `docker compose up`  |
| Create the `postgres` superuser with your password              | TimescaleDB container                | On first `docker compose up`  |
| Create all tables (`users`, `pcap_files`, `cluster_results`, …) | Alembic (`server/migrations/`)       | When the backend starts, if pending |
| Apply later schema changes                                      | Alembic (`server/migrations/`)       | When the backend starts, if pending |
| Enable TimescaleDB extension                                    | `db_setup.py`                        | Every time the backend starts |
| Create `flow_statistics` hypertable                             | `db_setup.py`                        | Every time the backend starts |

The backend container runs gunicorn (`wsgi:app`) with one worker and many threads.

---

## 1 — Install Docker on Linux (Ubuntu / Debian)

### 1.1 Remove old versions if present

```bash
sudo apt-get remove docker docker-engine docker.io containerd runc
```

### 1.2 Install prerequisites

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
```

### 1.3 Download Docker's official GPG key

```bash
# Ensure the keyrings directory exists
sudo install -m 0755 -d /etc/apt/keyrings

# Download the key directly as .asc
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc

# Grant read permissions
sudo chmod a+r /etc/apt/keyrings/docker.asc
```

### 1.4 Add the Docker repository to APT sources

```bash
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

> **Debian users:** replace `ubuntu` with `debian` in both URLs above.

### 1.5 Install Docker Engine + Compose plugin

```bash
sudo apt-get update
sudo apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin
```

### 1.6 Allow your user to run Docker without sudo

```bash
sudo usermod -aG docker $USER
newgrp docker          # apply group change without logging out
```

### 1.7 Verify the installation

```bash
docker --version          # Docker version 26.x.x …
docker compose version    # Docker Compose version v2.x.x …
docker run hello-world    # should print "Hello from Docker!"
```

---

## 2 — Get the project onto your machine

If you are cloning from a remote repository:

```bash
git clone <your-repo-url> penm
cd penm
```

If you are copying files (e.g. from Windows via SCP):

```bash
scp -r /path/to/project user@linux-host:~/penm
cd ~/penm
```

---

## 3 — Configure the `.env` file

The `.env` file in the project root is read by `docker compose` to fill in
variable values. `.env` itself is never committed (it holds real secrets) —
`.env.example` is the tracked template. Create your real `.env` from it:

```bash
cp .env.example .env
```

Open `.env` in your editor and set the following values:

### 3.1 Generate secure random secrets

Run this command **once** to generate the values for `JWT_SECRET_KEY` and `SECRET_TOKEN`:

```bash
python3 -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_hex(32)); print('SECRET_TOKEN=' + secrets.token_hex(32))"
```

Example output (yours will be different — use your own):

```
JWT_SECRET_KEY=4a7f3c9b2d1e8a6f0c5b9d3e7f2a4c8b1e5d9f3a7c2b6e0d4f8a1c5b9e3d7f2a
SECRET_TOKEN=9b3e7f1a5c2d8e4b0f6a3c9e2d7b5f1a4c8b2e6d0f3a7c9b1e5d2f8a4c7b3e6d
```

### 3.2 Complete `.env` file

Edit `.env` so it contains the following (replace the placeholder values):

```dotenv
# ── Database ──────────────────────────────────────────────────────────────
# Password for the 'postgres' user inside the penm_db container.
# Used by both the db container and the backend container.
DB_PASSWORD=choose_a_strong_password_here

# ── Security secrets ──────────────────────────────────────────────────────
# Generated in step 3.1 — paste your own values here.
JWT_SECRET_KEY=paste_your_generated_jwt_secret_here
SECRET_TOKEN=paste_your_generated_secret_token_here

# ── Admin account ─────────────────────────────────────────────────────────
# Created automatically on first boot if no admin exists.
ADMIN_USERNAME=admin
ADMIN_PASSWORD=choose_a_strong_admin_password

# ── Sensor ────────────────────────────────────────────────────────────────
# Where the backend fetches pcap slices and nmap results (pcap_server.py).
# The default only works when the sensor runs on this Docker host.
# SENSOR_URL=http://<sensor-ip>:5005

# (TSHARK_PATH, listed in .env.example, is not needed here: the backend image
#  installs tshark on PATH, and docker-compose.yml does not pass it through.)

# ── CORS ──────────────────────────────────────────────────────────────────
# Comma-separated list of origins allowed to call the backend.
# If you are deploying on a remote server, add its IP/domain here.
ALLOWED_ORIGINS=http://localhost,http://127.0.0.1

# ── Frontend build-time URLs ──────────────────────────────────────────────
# These are baked into the Nuxt bundle when the frontend image is built.
# If your Linux machine has a real IP (e.g. 192.168.1.50) and you need
# to access the app from another machine, change localhost to that IP.
API_BASE_URL=http://localhost:5555
WS_URL=ws://192.168.1.50:5002   # IP of the Sensor VM running publisher.py — not this Docker host
```

> **Important:** `API_BASE_URL` and `WS_URL` are **baked into the frontend
> image at build time**. If you change them after building, you must rebuild
> the frontend image:
>
> ```bash
> docker compose build frontend
> docker compose up -d frontend
> ```
>
> The frontend's Content-Security-Policy (which governs what origins the
> browser will let the app call out to) is derived from these same two
> values automatically at container startup — you don't need to edit
> `nginx.conf` by hand for a new `API_BASE_URL`/`WS_URL`, rebuilding the
> frontend image is genuinely the only step.

### 3.3 How `DATABASE_URL` is constructed (you do NOT set it manually)

The `docker-compose.yml` constructs the database connection string automatically:

```
postgresql://postgres:<DB_PASSWORD>@db:5432/network_analyzer
```

- `postgres` — the PostgreSQL superuser (fixed, set via `POSTGRES_USER`)
- `<DB_PASSWORD>` — taken from your `.env` `DB_PASSWORD` value
- `db` — the Docker internal hostname of the database container
- `5432` — default PostgreSQL port (internal to Docker network)
- `network_analyzer` — the database name (fixed, set via `POSTGRES_DB`)

---

## 4 — Build and start the containers

```bash
# From the project root directory
docker compose up --build
```

The first build downloads base images and installs all dependencies.
Expected time: **5–10 minutes** depending on your connection.

You will see output from all three containers interleaved.
Wait until you see lines like:

```
penm_backend  | TimescaleDB initialized successfully.
penm_backend  | * Running on http://0.0.0.0:5555
penm_frontend | nginx: master process nginx -g daemon off;
```

To run in the background (detached mode):

```bash
docker compose up --build -d
```

---

## 5 — Access the application

| URL                             | What you see                                |
| ------------------------------- | ------------------------------------------- |
| `http://localhost`              | PENM frontend (login page)                  |
| `http://localhost:5555/apidocs` | Swagger / Flasgger API docs                 |
| `127.0.0.1:5432`                | PostgreSQL (connect with pgAdmin or `psql`) — bound to loopback only, not reachable from other machines |

### Connect to the database with `psql` (optional verification)

```bash
docker exec -it penm_db psql -U postgres -d network_analyzer
```

Once inside, check that tables and the hypertable exist:

```sql
\dt                                         -- list all tables
SELECT * FROM timescaledb_information.hypertables;  -- check hypertable
\q                                          -- exit
```

---

## 6 — First login

1. Open `http://localhost` in your browser
2. Log in with the credentials you set in `.env`:
   - **Username:** value of `ADMIN_USERNAME` (default: `admin`)
   - **Password:** value of `ADMIN_PASSWORD`

---

## 7 — Daily operations

```bash
# Start (if already built)
docker compose up -d

# Stop (containers preserved, data kept)
docker compose stop

# View logs from all containers
docker compose logs -f

# View logs from backend only
docker compose logs -f backend

# Restart just the backend (e.g. after a code change)
docker compose restart backend

# Full stop and remove containers (data volumes kept)
docker compose down

# Full reset including database data
docker compose down -v
```

---

## 8 — Accessing from another machine on the same network

If your Linux server has IP `192.168.1.50` and you want to open the app
from a laptop on the same network:

1. In `.env`, set:
   ```dotenv
   API_BASE_URL=http://192.168.1.50:5555
   ALLOWED_ORIGINS=http://192.168.1.50,http://localhost
   ```
2. Rebuild the frontend image (it bakes the URL at build time):
   ```bash
   docker compose build frontend
   docker compose up -d
   ```
3. Open `http://192.168.1.50` from the other machine.

Make sure the Linux firewall allows ports 80 and 5555:

```bash
sudo ufw allow 80/tcp
sudo ufw allow 5555/tcp
sudo ufw reload
```

---

## 9 — Updating a running server with images built on another machine

Use this when the server already runs PENM with Docker Compose and you want to
deploy newer code without building on the server (no source checkout, no
`npm install` there). You build the two images on your own machine, copy them
over, and recreate only the backend and frontend containers. The database
container and its volume are not touched.

The backend upgrades the database schema on its first start (Alembic). The
first upgrade, `0001 Baseline`, only creates what is missing and keeps all
existing tables and rows, so an older database is upgraded in place. Back it
up anyway (step 9.2).

Placeholders used below:

| Placeholder        | Meaning                                         | Example                    |
| ------------------ | ----------------------------------------------- | -------------------------- |
| `<server>`         | SSH login of the server                         | `user@192.168.1.50`        |
| `<api-base-url>`   | The backend address browsers use                | `http://192.168.1.50:5555` |
| `<ws-url>`         | Default address in the Real-Time page           | `ws://192.168.1.51:5002`   |
| `<project-folder>` | Folder on the server holding `docker-compose.yml` | `~/penm/network-analyzer` |

### 9.1 Find the compose project and the current frontend settings (server)

```bash
docker inspect penm_backend --format '{{index .Config.Labels "com.docker.compose.project"}}  {{index .Config.Labels "com.docker.compose.project.working_dir"}}'
docker inspect penm_frontend --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -E 'API_BASE_URL|WS_URL'
```

The first line prints the project name and `<project-folder>`. Compose names
the images `<project>-backend` and `<project>-frontend`; the commands below
assume the project is `network-analyzer`. If it is different, use that name in
every image tag below.

The second command shows the `API_BASE_URL` and `WS_URL` the running frontend
was built with. Reuse them in step 9.3: the frontend bakes them into its
JavaScript, and nginx allows the browser to connect only to them.

### 9.2 Back up the database and keep the current images (server)

```bash
docker exec penm_db pg_dump -U postgres -Fc network_analyzer > ~/penm_db_$(date +%F).dump
ls -lh ~/penm_db_*.dump          # must not be 0 bytes

docker tag network-analyzer-backend:latest  network-analyzer-backend:old-$(date +%F)
docker tag network-analyzer-frontend:latest network-analyzer-frontend:old-$(date +%F)
```

### 9.3 Build and package the images (your machine)

Run from the project root, in Git Bash on Windows or a Linux/macOS shell (the
line continuations and `gzip` do not work in Windows `cmd`). The build machine
needs Docker and should build for the server's CPU architecture (normally
x86_64).

```bash
docker build -t network-analyzer-backend:latest ./server
docker build -t network-analyzer-frontend:latest \
  --build-arg API_BASE_URL=<api-base-url> \
  --build-arg WS_URL=<ws-url> .
docker save network-analyzer-backend:latest network-analyzer-frontend:latest | gzip > penm-app.tar.gz
sha256sum penm-app.tar.gz
scp penm-app.tar.gz <server>:~/
```

Building the frontend on your machine also uses your local
`package-lock.json`, which avoids dependency drift on the server.

### 9.4 Load the images and recreate the containers (server)

```bash
sha256sum ~/penm-app.tar.gz      # must match the value from 9.3
gunzip -c ~/penm-app.tar.gz | docker load

cd <project-folder>              # the folder with docker-compose.yml, not its parent
docker compose up -d --no-build backend frontend
docker logs -f penm_backend
```

`--no-build` makes Compose use the loaded images instead of building from the
server's (older) source. In the log, expect `Starting gunicorn`, the Alembic
`Running upgrade` lines (first update only) and `TimescaleDB initialized
successfully.`; then press Ctrl+C. The server's existing `.env` keeps
supplying the secrets.

### 9.5 Check

```bash
docker ps --format '{{.Names}}  {{.Image}}  {{.Status}}'   # backend/frontend: "Up ... seconds"
docker logs penm_backend 2>&1 | grep -E "Traceback|Error"   # should print nothing
curl -s http://localhost:5555/apispec_1.json | grep -o '"Bearer": *\[\]' | wc -l   # about 18
```

Then reload the app and `/apidocs` in the browser with Ctrl+F5. In `/apidocs`,
click **Authorize**, enter `Bearer <token>` (the word `Bearer`, a space, then
the token), click **Authorize**, then **Close**. The curl command Swagger shows
for a protected endpoint must contain `-H "Authorization: Bearer ..."`.

### 9.6 Roll back

```bash
cd <project-folder>
docker tag network-analyzer-backend:old-<date>  network-analyzer-backend:latest
docker tag network-analyzer-frontend:old-<date> network-analyzer-frontend:latest
docker compose up -d --no-build backend frontend
```

The older code still runs on the upgraded database, because the baseline
upgrade only added what was missing. To restore the data itself from the dump:

```bash
docker exec -i penm_db pg_restore -U postgres -d network_analyzer --clean --if-exists < ~/penm_db_<date>.dump
```

When everything works, delete `~/penm-app.tar.gz` on the server and keep the
dump for a while.

---

## 10 — Running the capture sensor with Docker

The sensor captures live traffic and serves it to the backend. One container
(`penm_sensor`, defined in `docker-compose.sensor.yml`) runs:

| Process          | Purpose                                                         | Port |
| ---------------- | --------------------------------------------------------------- | ---- |
| `dumpcap`        | ring buffer of capture files (one per `SENSOR_RING_SECONDS`)    | —    |
| Zeek             | flow log (`conn.log`)                                           | —    |
| `zeek_agent.py`  | sends flows to the backend's `/v1/ingest/zeek`                  | —    |
| `pcap_server.py` | pcap slices and Nmap scans for the backend                      | 5005 |
| `publisher.py`   | live packets for the Real Time page                             | 5002 |

If any of them stops, the container exits and Docker restarts it. Capture
files older than `SENSOR_RETENTION_MINUTES` are deleted, and Zeek is restarted
once a day so `conn.log` does not grow without limit. It uses the same image as
the Kubernetes testbed (`deploy/k8s/images/sensor`).

It runs with **host networking** on the machine whose interface you capture,
so it sees the real traffic and its ports 5005 and 5002 are opened directly on
that machine. The backend and the browser reach it at that machine's address.

### 10.1 Build and copy the image (your machine)

As in §9.3, from the project root in Git Bash:

```bash
docker build -f deploy/k8s/images/sensor/Dockerfile -t penm-sensor:latest .
docker save penm-sensor:latest | gzip > penm-sensor.tar.gz
scp penm-sensor.tar.gz docker-compose.sensor.yml <server>:~/
```

The browser connects to `publisher.py` at the frontend's `WS_URL`, and nginx
allows only that address. If the sensor runs on a different machine than the
one the frontend was built for, rebuild the frontend with
`WS_URL=ws://<sensor-ip>:5002` (§9.3).

### 10.2 Settings (server)

Put `docker-compose.sensor.yml` next to the app's `docker-compose.yml` (in
`<project-folder>`), so it reads the same `.env` and shares `SECRET_TOKEN`
with the backend. Add to that `.env`:

```dotenv
# ── Sensor (docker-compose.sensor.yml) ────────────────────────────────────
# Interface to capture on (list them with: ip -br addr)
SENSOR_INTERFACE=enp0s18
# Where zeek_agent.py posts flows. Sensor on the same host as the backend:
SENSOR_HOST_API_URL=http://127.0.0.1:5555/v1/ingest/zeek
# Optional:
# SENSOR_EXCLUDE_PORTS=5002 5005 5555      # never captured (add 22 to drop SSH)
# SENSOR_RETENTION_MINUTES=1440           # keep 24 h of capture files
# SENSOR_RING_SECONDS=3600                # one capture file per hour
# SENSOR_ENABLE_PUBLISHER=true            # false: no Real Time page stream

# Where the backend fetches pcaps and runs Nmap: the sensor host's address
SENSOR_URL=http://<sensor-ip>:5005
```

On a different machine than the backend, create a `.env` next to
`docker-compose.sensor.yml` there with `SECRET_TOKEN` (the backend's value),
`SENSOR_INTERFACE` and `SENSOR_HOST_API_URL=http://<backend-ip>:5555/v1/ingest/zeek`.

Capture files can grow quickly on a busy link: one hour of a 100 Mbit/s link is
up to about 45 GB. Check the free space where Docker keeps volumes
(`df -h /var/lib/docker`) and lower `SENSOR_RETENTION_MINUTES` if needed.

### 10.3 Start (server)

```bash
# nothing else may use ports 5005 / 5002 (e.g. an old start_sensor.sh run)
sudo ss -ltnp | grep -E ':(5005|5002)\b'

gunzip -c ~/penm-sensor.tar.gz | docker load
cd <project-folder>
docker compose -f docker-compose.sensor.yml up -d
docker logs -f penm_sensor          # expect "[sensor] interface=... filter: ..."

# the backend reads SENSOR_URL only at start
docker compose up -d --no-build backend
```

### 10.4 Check

```bash
docker ps --format '{{.Names}}  {{.Status}}' | grep penm_sensor        # Up ... (healthy)
docker exec penm_sensor ls -l /app/sensor/generated_pcaps               # continuous_capture_*.pcap growing
# From the backend container to the sensor, with the shared token: 200 = OK
docker exec penm_backend sh -c 'python3 -c "import os,urllib.request as u; r=u.urlopen(u.Request(os.environ[\"SENSOR_URL\"]+\"/get-pcap\", headers={\"X-Internal-Token\": os.environ[\"SECRET_TOKEN\"]}), timeout=10); print(r.status, len(r.read()), \"bytes\")"'
docker logs penm_backend 2>&1 | grep "ingest/zeek" | tail -3       # flows arriving
```

In the app, Continuous Monitoring should show statistics within a few minutes,
and `GET /v1/network/pcap/latest/full` in `/apidocs` should download a pcap.

If the backend cannot reach the sensor (`Sensor is unreachable`) and the host
firewall is enabled, allow the Docker networks to reach port 5005:

```bash
sudo ufw allow from 172.16.0.0/12 to any port 5005 proto tcp
```

### 10.5 Operate

```bash
cd <project-folder>
docker compose -f docker-compose.sensor.yml logs -f        # logs
docker compose -f docker-compose.sensor.yml restart        # restart capture
docker compose -f docker-compose.sensor.yml down           # stop (capture files kept)
docker compose -f docker-compose.sensor.yml down -v        # stop and delete capture files
```

To update: rebuild and copy the image as in 10.1, `docker load` it, then
`docker compose -f docker-compose.sensor.yml up -d`.

---

## 11 — Summary of required Linux packages

| Package                 | Why                          |
| ----------------------- | ---------------------------- |
| `docker-ce`             | Docker container runtime     |
| `docker-ce-cli`         | `docker` command-line tool   |
| `containerd.io`         | Low-level container runtime  |
| `docker-buildx-plugin`  | Multi-platform image builds  |
| `docker-compose-plugin` | `docker compose` sub-command |

Everything else (Python, Node.js, Nginx, PostgreSQL, TimescaleDB) runs
**inside the containers** — nothing needs to be installed on the host.
