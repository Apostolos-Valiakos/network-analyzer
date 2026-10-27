FROM python:3.10-slim

WORKDIR /app

# System packages
#   libpcap0.8  – runtime library required by scapy for reading/writing PCAPs
#   tshark      – required by pyshark for deep packet dissection
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        tshark \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps before copying source for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Directories written at runtime — must exist inside the container
RUN mkdir -p uploads generated_pcaps cluster_analysis results

EXPOSE 5555

CMD ["python3", "app.py"]
