# PENM capture sensor for Kubernetes: dumpcap ring buffer, Zeek, the pcap/Nmap
# API (pcap_server.py), the flow shipper (zeek_agent.py) and the Real Time
# packet stream (publisher.py). Runs with hostNetwork so it sees the traffic
# between the 5G pods on this node.
#
# Build from the REPOSITORY ROOT (needs "Host Files/"):
#   docker build -f deploy/k8s/images/sensor/Dockerfile -t penm-sensor:local .
FROM python:3.10-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive

#   tshark/wireshark-common  dumpcap, editcap, mergecap (pcap_server slices)
#   nmap                     active probing (pcap_server)
#   libpcap0.8               scapy live capture (publisher)
#   procps                   pgrep/kill in the entrypoint
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg tshark wireshark-common nmap libpcap0.8 procps \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key \
        | gpg --dearmor -o /usr/share/keyrings/zeek-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/zeek-archive-keyring.gpg] http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /" \
        > /etc/apt/sources.list.d/zeek.list \
    && apt-get update && apt-get install -y --no-install-recommends zeek \
    && rm -rf /var/lib/apt/lists/*
ENV PATH="/opt/zeek/bin:${PATH}"

# publisher.py needs scapy, websockets and psutil, which are not in
# Host Files/requirements.txt.
COPY ["Host Files/requirements.txt", "/tmp/req-sensor.txt"]
RUN pip install --no-cache-dir -r /tmp/req-sensor.txt scapy websockets psutil

COPY ["Host Files/", "/app/sensor/"]
COPY deploy/k8s/images/sensor/entrypoint.sh /usr/local/bin/sensor-entrypoint.sh
RUN chmod +x /usr/local/bin/sensor-entrypoint.sh \
    && mkdir -p /app/sensor/generated_pcaps /var/lib/penm-sensor/zeek

WORKDIR /app/sensor
ENTRYPOINT ["/usr/local/bin/sensor-entrypoint.sh"]
