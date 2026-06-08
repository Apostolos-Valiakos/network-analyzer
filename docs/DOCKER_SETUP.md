# PENM — Docker Deployment Guide

Full step-by-step guide for deploying the Privacy Enhanced Network Monitor
(frontend + backend + database) with Docker on a Linux machine.

---

## What gets created automatically

You do **not** need to create the database, user, or tables manually.
Docker and the app handle everything:

| Step | Who does it | When |
|---|---|---|
| Create the `network_analyzer` database | TimescaleDB container (via env vars) | On first `docker compose up` |
| Create the `postgres` superuser with your password | TimescaleDB container | On first `docker compose up` |
| Create all tables (`users`, `pcap_files`, `cluster_results`, …) | `app.py → db.create_all()` | Every time the backend starts |
| Enable TimescaleDB extension | `app.py` | Every time the backend starts |
| Create `flow_statistics` hypertable | `app.py` | Every time the backend starts |
| Run `ALTER TABLE` column migrations | `app.py → _startup_migrations()` | Every time the backend starts |

---

## 1 — Install Docker on Linux (Ubuntu / Debian)

### 1.1 Remove old versions if present

```bash
sudo apt-get remove docker docker-engine docker.io containerd runc
```

### 1.2 Add Docker's official repository

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

> **Debian users:** replace `ubuntu` with `debian` in the URL above.

### 1.3 Install Docker Engine + Compose plugin

```bash
sudo apt-get update
sudo apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin
```

### 1.4 Allow your user to run Docker without sudo

```bash
sudo usermod -aG docker $USER
newgrp docker          # apply group change without logging out
```

### 1.5 Verify the installation

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
variable values. A template is already present; copy it and edit it:

```bash
cp .env .env.backup    # keep the original as reference
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

# ── CORS ──────────────────────────────────────────────────────────────────
# Comma-separated list of origins allowed to call the backend.
# If you are deploying on a remote server, add its IP/domain here.
ALLOWED_ORIGINS=http://localhost,http://127.0.0.1

# ── Frontend build-time URLs ──────────────────────────────────────────────
# These are baked into the Nuxt bundle when the frontend image is built.
# If your Linux machine has a real IP (e.g. 192.168.1.50) and you need
# to access the app from another machine, change localhost to that IP.
API_BASE_URL=http://localhost:5555
WS_URL=ws://10.6.2.135:5002   # IP of the Sensor VM running publisher.py
```

> **Important:** `API_BASE_URL` and `WS_URL` are **baked into the frontend
> image at build time**. If you change them after building, you must rebuild
> the frontend image:
> ```bash
> docker compose build frontend
> docker compose up -d frontend
> ```

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

| URL | What you see |
|---|---|
| `http://localhost` | PENM frontend (login page) |
| `http://localhost:5555/apidocs` | Swagger / Flasgger API docs |
| `http://localhost:5432` | PostgreSQL (connect with pgAdmin or `psql`) |

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

## 9 — Summary of required Linux packages

| Package | Why |
|---|---|
| `docker-ce` | Docker container runtime |
| `docker-ce-cli` | `docker` command-line tool |
| `containerd.io` | Low-level container runtime |
| `docker-buildx-plugin` | Multi-platform image builds |
| `docker-compose-plugin` | `docker compose` sub-command |

Everything else (Python, Node.js, Nginx, PostgreSQL, TimescaleDB) runs
**inside the containers** — nothing needs to be installed on the host.
