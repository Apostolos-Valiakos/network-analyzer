#!/bin/bash
#
# Starts and watches the sensor components inside one pod. Kubernetes restarts
# the pod if this script exits, so any component dying ends the script.
#
# Every 30 seconds it also:
#   - re-reads the PENM pod IPs and restarts capture when they change, so
#     PENM's own traffic (backend, database, UI) stays out of the capture
#   - deletes ring files older than the retention window
#   - restarts Zeek and the flow shipper once a day, so conn.log does not grow
#     without limit (Zeek does not rotate its logs when run like this)
#
# Environment (set by deploy/k8s/30-penm/sensor.yaml):
#   CAPTURE_INTERFACE   interface for dumpcap and Zeek (default "any")
#   EXCLUDE_DNS         headless Service that resolves to every PENM pod IP
#   EXCLUDE_PORTS       ports never captured (cluster control plane, PENM)
#   RETENTION_MINUTES   how long ring files are kept (default 1440 = 24 h)
#   RING_SECONDS        length of one ring file (default 3600)
#   ZEEK_RESTART_SECONDS  how often conn.log starts afresh (default 86400)
#   ENABLE_PUBLISHER    "true" starts publisher.py for the Real Time page
#   DPI_ENABLED         "true" starts dpi_agent.py (live DPI, POST /v1/ingest/dpi);
#                       it reads DPI_WINDOW_SECONDS, DPI_SNAPLEN_UP and the other
#                       DPI_* settings described in dpi_agent.py
#   HUBBLE_ENABLED      "true" starts hubble_agent.py (pod identities from Hubble
#                       Relay, POST /v1/ingest/hubble); the Relay's address is
#                       left out of the capture
#   HUBBLE_SERVER       Hubble Relay host:port (default
#                       hubble-relay.kube-system.svc.cluster.local:80)
#   HOST_API_URL, SECRET_TOKEN  used by zeek_agent.py, dpi_agent.py,
#                       hubble_agent.py and pcap_server.py

set -u

SENSOR_DIR=/app/sensor
PCAP_DIR="$SENSOR_DIR/generated_pcaps"
ZEEK_DIR=/var/lib/penm-sensor/zeek

CAPTURE_INTERFACE="${CAPTURE_INTERFACE:-any}"
EXCLUDE_DNS="${EXCLUDE_DNS:-}"
EXCLUDE_PORTS="${EXCLUDE_PORTS:-}"
RETENTION_MINUTES="${RETENTION_MINUTES:-1440}"
RING_SECONDS="${RING_SECONDS:-3600}"
ZEEK_RESTART_SECONDS="${ZEEK_RESTART_SECONDS:-86400}"
ENABLE_PUBLISHER="${ENABLE_PUBLISHER:-true}"
DPI_ENABLED="${DPI_ENABLED:-false}"
HUBBLE_ENABLED="${HUBBLE_ENABLED:-false}"
HUBBLE_SERVER="${HUBBLE_SERVER:-hubble-relay.kube-system.svc.cluster.local:80}"
export HUBBLE_SERVER

mkdir -p "$PCAP_DIR" "$ZEEK_DIR"

log() { echo "[sensor] $*"; }

excluded_ips() {
    {
        [ -n "$EXCLUDE_DNS" ] && getent ahostsv4 "$EXCLUDE_DNS"
        # hubble_agent's own connection to Hubble Relay (its Service address)
        [ "$HUBBLE_ENABLED" = "true" ] && getent ahostsv4 "${HUBBLE_SERVER%:*}"
    } | awk '{ print $1 }' | sort -u | tr '\n' ' '
}

build_filter() {
    local ips="$1" parts=() terms
    if [ -n "$ips" ]; then
        terms=$(printf 'host %s or ' $ips)
        parts+=("not (${terms% or })")
    fi
    if [ -n "$EXCLUDE_PORTS" ]; then
        terms=$(printf 'port %s or ' $EXCLUDE_PORTS)
        parts+=("not (${terms% or })")
    fi
    local IFS='&'
    local joined="${parts[*]}"
    echo "${joined//&/ and }"
}

DUMPCAP_PID="" ZEEK_PID="" AGENT_PID="" PCAP_SERVER_PID="" PUBLISHER_PID="" DPI_PID="" HUBBLE_PID=""

start_dumpcap() {
    # Ring files rotate by time so pcap_server can pick them by window. A new
    # run starts a new numbering, so old runs' files are removed by age below.
    dumpcap -i "$CAPTURE_INTERFACE" -b "duration:$RING_SECONDS" \
        -w "$PCAP_DIR/continuous_capture.pcap" ${FILTER:+-f "$FILTER"} &
    DUMPCAP_PID=$!
}

start_zeek() {
    # A fresh conn.log each start: zeek_agent reads it from the beginning.
    cd "$ZEEK_DIR" || exit 1
    for f in *.log; do [ -e "$f" ] && mv -f "$f" "$f.previous"; done
    zeek -C -i "$CAPTURE_INTERFACE" LogAscii::use_json=T "$SENSOR_DIR/tuning.zeek" \
        ${FILTER:+-f "$FILTER"} &
    ZEEK_PID=$!
    python3 "$SENSOR_DIR/zeek_agent.py" &
    AGENT_PID=$!
    ZEEK_STARTED=$(date +%s)
    cd "$SENSOR_DIR" || exit 1
}

start_dpi() {
    # Same exclusions as dumpcap and Zeek; the agent adds the protocol filters.
    [ "$DPI_ENABLED" = "true" ] || return 0
    CAPTURE_EXCLUDE="$FILTER" python3 "$SENSOR_DIR/dpi_agent.py" &
    DPI_PID=$!
}

start_hubble() {
    [ "$HUBBLE_ENABLED" = "true" ] || return 0
    python3 "$SENSOR_DIR/hubble_agent.py" &
    HUBBLE_PID=$!
}

stop() {
    for pid in "$@"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
    done
    for pid in "$@"; do
        [ -n "$pid" ] && wait "$pid" 2>/dev/null
    done
}

alive() {
    for pid in "$@"; do
        kill -0 "$pid" 2>/dev/null || return 1
    done
}

shutdown() {
    log "stopping"
    stop "$HUBBLE_PID" "$DPI_PID" "$PUBLISHER_PID" "$PCAP_SERVER_PID" "$AGENT_PID" "$ZEEK_PID" "$DUMPCAP_PID"
    exit 0
}
trap shutdown TERM INT

EXCLUDED=$(excluded_ips)
FILTER=$(build_filter "$EXCLUDED")
log "interface=$CAPTURE_INTERFACE filter: ${FILTER:-<none>}"

start_dumpcap
start_zeek
start_dpi
start_hubble
PORT=5005 python3 "$SENSOR_DIR/pcap_server.py" &
PCAP_SERVER_PID=$!
if [ "$ENABLE_PUBLISHER" = "true" ]; then
    python3 "$SENSOR_DIR/publisher.py" &
    PUBLISHER_PID=$!
fi

while true; do
    sleep 30 &
    wait $!

    if ! alive "$DUMPCAP_PID" "$ZEEK_PID" "$AGENT_PID" "$PCAP_SERVER_PID" ${PUBLISHER_PID:+"$PUBLISHER_PID"} ${DPI_PID:+"$DPI_PID"} ${HUBBLE_PID:+"$HUBBLE_PID"}; then
        log "a component exited; stopping so Kubernetes restarts the pod"
        stop "$HUBBLE_PID" "$DPI_PID" "$PUBLISHER_PID" "$PCAP_SERVER_PID" "$AGENT_PID" "$ZEEK_PID" "$DUMPCAP_PID"
        exit 1
    fi

    now_excluded=$(excluded_ips)
    if [ "$now_excluded" != "$EXCLUDED" ]; then
        EXCLUDED=$now_excluded
        FILTER=$(build_filter "$EXCLUDED")
        log "PENM pod IPs changed; restarting capture with filter: ${FILTER:-<none>}"
        stop "$DPI_PID" "$AGENT_PID" "$ZEEK_PID" "$DUMPCAP_PID"
        start_dumpcap
        start_zeek
        start_dpi
    elif [ $(( $(date +%s) - ZEEK_STARTED )) -ge "$ZEEK_RESTART_SECONDS" ]; then
        log "daily restart of Zeek and the flow shipper"
        stop "$AGENT_PID" "$ZEEK_PID"
        start_zeek
    fi

    find "$PCAP_DIR" -name 'continuous*.pcap' -mmin +"$RETENTION_MINUTES" -delete
done
