import os
import time
import json
import requests

# --- Configuration ---
ZEEK_LOG_PATH = "conn.log"

# IMPORTANT: Make sure this matches your Windows Host IP exactly!
HOST_API_URL = "http://10.16.1.216:5000/v1/ingest/zeek" 
SECRET_TOKEN = "my-super-secret-internal-token-123"

# Batch settings to optimize network traffic
BATCH_SIZE = 50        # Send data when we collect 50 flows...
FLUSH_INTERVAL = 2.0   # ...or send whatever we have every 2 seconds.

def send_batch(batch):
    """Sends a list of flow dictionaries to the Host API securely."""
    if not batch:
        return
        
    headers = {
        "X-Internal-Token": SECRET_TOKEN,
        "Content-Type": "application/json"
    }
    payload = {"flows": batch}
    
    try:
        response = requests.post(HOST_API_URL, json=payload, headers=headers, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        # We catch network errors so the agent doesn't crash if the Host is temporarily restarted
        print(f"Agent network error: {e}")

def tail_zeek_log():
    """Waits for Zeek to start logging, then tails the file in real-time."""
    print(f"Starting Zeek Agent. Sending to {HOST_API_URL}")
    
    # 1. Wait until Zeek actually creates the log file
    while not os.path.exists(ZEEK_LOG_PATH):
        print("Waiting for Zeek to generate conn.log...")
        time.sleep(2)
        
    print(f"Found {ZEEK_LOG_PATH}! Tailing for new connections...")
    
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
        print("\nShutting down Zeek Agent...")
