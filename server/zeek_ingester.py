import time
import json
import os
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime

# Configuration
ZEEK_CONN_LOG = "/opt/zeek/logs/current/conn.log"  # Update this to your Zeek log path
DB_URL = os.getenv(
    "DATABASE_URL", "postgresql://postgres:pass@localhost:5432/network_analyzer"
)
BATCH_SIZE = 1000


def follow(thefile):
    """Generator function that yields new lines in a file (like tail -f)."""
    thefile.seek(0, 2)  # Go to the end of the file
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.5)  # Sleep briefly
            continue
        yield line


def ingest_zeek_logs():
    print(f"Connecting to database: {DB_URL}")
    conn = psycopg2.connect(DB_URL)
    cursor = conn.cursor()

    print(f"Tailing Zeek log: {ZEEK_CONN_LOG}")
    with open(ZEEK_CONN_LOG, "r") as logfile:
        loglines = follow(logfile)

        batch = []
        for line in loglines:
            try:
                data = json.loads(line)

                # Extract Zeek JSON fields
                ts = data.get("ts")
                uid = data.get("uid")
                id_orig_h = data.get("id.orig_h")
                id_resp_h = data.get("id.resp_h")
                proto = data.get("proto")
                conn_state = data.get("conn_state")
                orig_bytes = data.get("orig_bytes", 0)
                resp_bytes = data.get("resp_bytes", 0)
                orig_pkts = data.get("orig_pkts", 0)
                resp_pkts = data.get("resp_pkts", 0)

                batch.append(
                    (
                        ts,
                        uid,
                        id_orig_h,
                        id_resp_h,
                        proto,
                        conn_state,
                        orig_bytes,
                        resp_bytes,
                        orig_pkts,
                        resp_pkts,
                    )
                )

                # Bulk insert when batch is full
                if len(batch) >= BATCH_SIZE:
                    insert_query = """
                        INSERT INTO flow_statistics 
                        (ts, uid, id_orig_h, id_resp_h, proto, conn_state, orig_bytes, resp_bytes, orig_pkts, resp_pkts) 
                        VALUES %s 
                        ON CONFLICT (ts, uid) DO NOTHING;
                    """
                    execute_values(cursor, insert_query, batch)
                    conn.commit()
                    print(
                        f"[{datetime.now()}] Inserted {len(batch)} flows into TimescaleDB."
                    )
                    batch = []

            except json.JSONDecodeError:
                continue  # Skip invalid lines
            except Exception as e:
                print(f"Database error: {e}")
                conn.rollback()
                batch = []  # Drop batch on error to prevent infinite loop


if __name__ == "__main__":
    # Wait for DB to be ready
    time.sleep(5)
    ingest_zeek_logs()
