# server/snapshot_scheduler.py
import os
import requests
import time
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from models import db, RoleSnapshot
from Preprocess import run_ip_role_pipeline

VM_URL = "http://127.0.0.1:5005/get-pcap"  # Replace <YOUR_VM_IP>
SECRET_TOKEN = "my-super-secret-internal-token-123"


def run_role_snapshot(app):
    with app.app_context():
        print(
            f"[{datetime.now()}] Fetching 10-min PCAP slice from VM for persistent storage..."
        )

        # Calculate timeframe (Last 10 minutes)
        end_time = time.time()
        start_time = end_time - 300

        # Ask VM for slice
        vm_url = f"http://127.0.0.1:5005/get-pcap?start_time={start_time}&end_time={end_time}"
        headers = {"X-Internal-Token": "my-super-secret-internal-token-123"}

        try:
            response = requests.get(vm_url, headers=headers, stream=True)
            response.raise_for_status()

            # Save the file persistently
            os.makedirs("server/results", exist_ok=True)
            # Use a static name so it just overwrites itself every 60 mins
            temp_pcap = "server/results/latest_snapshot.pcap"

            with open(temp_pcap, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            print("Slice downloaded and saved for on-demand analysis.")

        except Exception as e:
            print(f"Snapshot Failed: {e}")


def start_scheduler(app):
    scheduler = BackgroundScheduler()
    # Reduced to 5 seconds for rapid testing!
    scheduler.add_job(
        func=run_role_snapshot,
        args=[app],
        trigger="interval",
        minutes=5,
        next_run_time=datetime.now(),
    )
    scheduler.start()
