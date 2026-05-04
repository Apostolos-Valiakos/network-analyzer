import os
import glob
import io
import subprocess
from flask import Flask, request, send_file, jsonify

app = Flask(__name__)

PCAP_DIR = "generated_pcaps"
SECRET_TOKEN = "my-super-secret-internal-token-123" 
os.makedirs(PCAP_DIR, exist_ok=True)

@app.before_request
def check_auth():
    token = request.headers.get("X-Internal-Token")
    if token != SECRET_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

@app.route("/get-pcap", methods=["GET"])
def get_pcap():
    start_time = request.args.get("start_time")
    end_time = request.args.get("end_time")
    headers_only = request.args.get("headers_only", "false").lower() == "true"
    
    pcap_files = glob.glob(f"{PCAP_DIR}/continuous*.pcap")
    if not pcap_files:
        return jsonify({"error": "No PCAPs found on sensor"}), 404

    if not start_time or not end_time:
        latest_pcap = max(pcap_files, key=os.path.getctime)
        return send_file(latest_pcap, as_attachment=True, download_name="latest_full.pcap")

    from datetime import datetime
    start_dt = datetime.utcfromtimestamp(float(start_time)).strftime('%Y-%m-%d %H:%M:%S')
    end_dt = datetime.utcfromtimestamp(float(end_time)).strftime('%Y-%m-%d %H:%M:%S')
    
    out_filename = f"slice_{int(float(start_time))}.pcap"
    merged_filename = f"merged_{int(float(start_time))}.pcap"
    
    try:
        merge_cmd = ["mergecap", "-w", merged_filename] + pcap_files
        subprocess.run(merge_cmd, check=True, capture_output=True)
        
        cmd = ["editcap", "-A", start_dt, "-B", end_dt]
        if headers_only:
            cmd.extend(["-s", "96"]) 
        
        cmd.extend([merged_filename, out_filename])
        subprocess.run(cmd, check=True, capture_output=True)
        
        with open(out_filename, 'rb') as f:
            return_data = io.BytesIO(f.read())
        
        return send_file(return_data, as_attachment=True, download_name=out_filename)
        
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.decode() if e.stderr else str(e)
        return jsonify({"error": "Slicing failed", "details": err_msg}), 500
    except Exception as e:
        return jsonify({"error": "Unexpected Server Crash", "details": str(e)}), 500
        
    finally:
        if os.path.exists(merged_filename):
            os.remove(merged_filename)
        if os.path.exists(out_filename):
            os.remove(out_filename)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5005)
