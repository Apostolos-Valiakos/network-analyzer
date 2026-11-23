FROM python:3.10-slim

WORKDIR /app

# System packages
#   tshark      – extracts the packet fields every analysis module reads; the
#                 backend has no other packet library (Scapy was removed)
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        tshark \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps before copying source for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Directories written at runtime — must exist inside the container
RUN mkdir -p uploads generated_pcaps cluster_analysis results

EXPOSE 5555

# One worker: Socket.IO clients and the rate limiter live in process memory.
# Threads serve concurrent requests and websockets.
CMD ["sh", "-c", "exec gunicorn --workers 1 --threads 100 --timeout 120 --bind 0.0.0.0:${PORT:-5555} --access-logfile - wsgi:app"]
