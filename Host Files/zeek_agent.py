import os
import time
import json
import logging
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# --- Configuration (set via environment variables) ---
ZEEK_LOG_PATH = os.getenv("ZEEK_LOG_PATH", "conn.log")
HOST_API_URL = os.getenv("HOST_API_URL", "http://127.0.0.1:5000/v1/ingest/zeek")
SECRET_TOKEN = os.getenv("SECRET_TOKEN", "")

# Batch settings to optimize network traffic
BATCH_SIZE = 50  # Send data when we collect 50 flows...
FLUSH_INTERVAL = 2.0  # ...or send whatever we have every 2 seconds.


def send_batch(batch):
    """Sends a list of flow dictionaries to the Host API securely."""
    if not batch:
        return

    headers = {"X-Internal-Token": SECRET_TOKEN, "Content-Type": "application/json"}
    payload = {"flows": batch}

    try:
        response = requests.post(HOST_API_URL, json=payload, headers=headers, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.warning("Agent network error: %s", e)


def tail_zeek_log():
    """Waits for Zeek to start logging, then tails the file in real-time."""
    logger.info("Starting Zeek Agent. Sending to %s", HOST_API_URL)

    # 1. Wait until Zeek actually creates the log file
    while not os.path.exists(ZEEK_LOG_PATH):
        logger.info("Waiting for Zeek to generate %s...", ZEEK_LOG_PATH)
        time.sleep(2)

    logger.info("Found %s — tailing for new connections...", ZEEK_LOG_PATH)

    with open(ZEEK_LOG_PATH, "r") as f:
        # Since start_sensor.sh deletes the old conn.log on startup,
        # we can safely read from the beginning of the file.

        batch = []
        last_flush = time.time()

        while True:
            line = f.readline()

            # If there's no new line yet, check if we need to flush a partial batch
            if not line:
                if batch and (time.time() - last_flush) > FLUSH_INTERVAL:
                    send_batch(batch)
                    batch = []
                    last_flush = time.time()
                time.sleep(0.5)  # Rest briefly before checking for new lines again
                continue

            # 2. Parse the Zeek JSON line
            try:
                data = json.loads(line)
                batch.append(data)
            except json.JSONDecodeError:
                # Skip any malformed lines (e.g., if Zeek is midway through writing a line)
                continue

            # 3. Send the batch if it reached the size limit
            if len(batch) >= BATCH_SIZE:
                send_batch(batch)
                batch = []
                last_flush = time.time()


if __name__ == "__main__":
    try:
        tail_zeek_log()
    except KeyboardInterrupt:
        logger.info("Shutting down Zeek Agent...")
