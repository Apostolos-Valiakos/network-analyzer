#!/bin/bash

if [ -z "$1" ]; then
    echo -e "\n❌ Error: No network interface provided. (e.g., ./start_sensor.sh enp0s3)\n"
    exit 1
fi

INTERFACE=$1

echo -e "\n[*] Cleaning up old PCAP and log files..."
mkdir -p generated_pcaps
sudo rm -rf generated_pcaps/*
rm -f conn.log

echo -e "\n Starting Sensor Node on interface: $INTERFACE"

# Define Host IP and Ports to ignore
HOST_IP="10.16.1.216"
FILTER="not (host $HOST_IP and (port 5000 or port 5001))"

echo -e "\n[*] Starting dumpcap (Ring Buffer)..."
sudo dumpcap -i $INTERFACE -b filesize:500000 -b files:3 \
  -w generated_pcaps/continuous_capture.pcap \
  -f "$FILTER" > /dev/null 2>&1 &
DUMPCAP_PID=$!

echo -e "\n[*] Starting Zeek..."
sudo /opt/zeek/bin/zeek -C -i $INTERFACE LogAscii::use_json=T -f "$FILTER" > /dev/null 2>&1 &
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
