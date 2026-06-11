#!/bin/bash

# ─── Configuration ────────────────────────────────────────────────────────────
# Edit these values before deploying to the sensor machine.

# IP address of this sensor VM (used to exclude its own management traffic).
# Override by setting HOST_IP in the environment before running this script.
HOST_IP="${HOST_IP:-$(hostname -I | awk '{print $1}')}"

# Shared secret — must match SECRET_TOKEN in the backend .env file.
export SECRET_TOKEN="${SECRET_TOKEN:-405266d38a2b176a0545f4398d91a29b2dc8fa39dd9ce0ca8f668d90af8fd819}"

# Backend ingest URL.
export HOST_API_URL="${HOST_API_URL:-http://10.250.100.42:5555/v1/ingest/zeek}"

# Ports used by pcap_server.py and zeek_agent.py — excluded from capture.
SENSOR_PORTS="5000 or port 5001 or port 5005"
# ──────────────────────────────────────────────────────────────────────────────

# Activate virtual environment if present
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/venv/bin/activate" ]; then
    source "$SCRIPT_DIR/venv/bin/activate"
fi

if [ -z "$1" ]; then
    echo -e "\n Error: No network interface provided. (e.g., ./start_sensor.sh enp0s3)\n"
    exit 1
fi

INTERFACE=$1

echo -e "\n[*] Cleaning up old PCAP and log files..."
mkdir -p generated_pcaps
sudo rm -rf generated_pcaps/*
rm -f conn.log

echo -e "\n Starting Sensor Node on interface: $INTERFACE"

FILTER="not (host $HOST_IP and (port $SENSOR_PORTS))"

echo -e "\n[*] Starting dumpcap (Ring Buffer)..."
/usr/bin/dumpcap -i $INTERFACE -b filesize:500000 -b files:3 \
  -w generated_pcaps/continuous_capture.pcap \
  -f "$FILTER" > /dev/null 2>&1 &
DUMPCAP_PID=$!

echo -e "\n[*] Starting Zeek..."
sudo /opt/zeek/bin/zeek -C -i $INTERFACE LogAscii::use_json=T tuning.zeek -f "$FILTER" > /dev/null 2>&1 &
ZEEK_PID=$!

sleep 2 

echo -e "\n[*] Starting PCAP Server (Port 5005)..."
python3 pcap_server.py > /dev/null 2>&1 &
PCAP_PID=$!

echo -e "\n[*] Starting Zeek Agent..."
python3 zeek_agent.py &
AGENT_PID=$!

echo -e "\n------------------------------------------------"
echo -e "\nSensor is active! Press [CTRL+C] to stop."
echo -e "\n------------------------------------------------"

trap "echo -e '\n🛑 Shutting down sensor...'; sudo kill $DUMPCAP_PID $ZEEK_PID $PCAP_PID $AGENT_PID; exit" SIGINT SIGTERM
wait
