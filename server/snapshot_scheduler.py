# server/snapshot_scheduler.py
import os
import requests
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from models import db, RoleSnapshot
from Preprocess import run_ip_role_pipeline

VM_URL = "${process.env.CONTINUOUS_PUBLISHER_URL}/get-pcap"  # Replace <YOUR_VM_IP>
SECRET_TOKEN = "my-super-secret-internal-token-123"


def run_role_snapshot(app):
    with app.app_context():
        print(
            f"[{datetime.now()}] Fetching 10-min PCAP slice from VM for ML Analysis..."
        )

        # Calculate timeframe (Last 10 minutes)
        end_time = datetime.utcnow().timestamp()
        start_time = end_time - 600  # 600 seconds = 10 mins

        # Ask VM for the slice (Full payload needed for ML DPI)
        params = {
            "start_time": start_time,
            "end_time": end_time,
            "headers_only": "false",
        }
        headers = {"X-Internal-Token": SECRET_TOKEN}

        temp_pcap = f"server/results/ml_slice_{int(start_time)}.pcap"

        try:
            response = requests.get(VM_URL, params=params, headers=headers, stream=True)
            response.raise_for_status()

            with open(temp_pcap, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            print("Slice downloaded. Running ML Pipeline...")
            report = run_ip_role_pipeline(temp_pcap, "rule_based")

            if report.get("status") == "success":
                ip_roles = report.get("ip_roles", {})
                new_snapshots = [
                    RoleSnapshot(
                        ts=end_time,
                        ip_address=ip,
                        role=role,
                        confidence=1.0,
                        reasoning="10-min ML Slice",
                    )
                    for ip, role in ip_roles.items()
                ]

                if new_snapshots:
                    db.session.bulk_save_objects(new_snapshots)
                    db.session.commit()
                    print(f"[{datetime.now()}] Saved {len(new_snapshots)} roles.")

        except Exception as e:
            print(f"Snapshot Failed: {e}")
        finally:
            if os.path.exists(temp_pcap):
                os.remove(temp_pcap)  # Clean up the temp file


def start_scheduler(app):
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=run_role_snapshot, args=[app], trigger="interval", hours=8)
    scheduler.start()
