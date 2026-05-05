# ============================================================
#  app.py  –  Network Traffic Monitoring Platform
#  Backend: Python 3 + Flask
# ============================================================

from flask import Flask, jsonify, render_template, request
import csv
import os
from data_generator import generate_traffic_data

app = Flask(__name__)
DATA_FILE = os.path.join(os.path.dirname(__file__), "data.csv")
#👉 Yeh mapping hai:

#Port → Service name
PORT_MAP = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    500: "IKE",
    587: "SMTP-TLS",
    993: "IMAPS",
    3306: "MySQL",
    3389: "RDP",
    5353: "mDNS",
    8080: "HTTP-Alt",
    1900: "SSDP",
    4500: "IPSec",
}

monitoring_active = False
capturing = False
generated_count = 0

import threading
import time

def packet_capture_loop():
    global capturing
    while capturing:
        # Mock capture loop
        time.sleep(1)
        if not capturing:
            break


def to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def get_service(port):
    port = to_int(port)
    return "ICMP" if port == 0 else PORT_MAP.get(port, "Unknown")


def load_all_records():
    if not os.path.exists(DATA_FILE):
        return []

    records = []
    with open(DATA_FILE, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            packet = {
                "time": row.get("time", ""),
                "source_ip": row.get("source_ip", ""),
                "destination_ip": row.get("destination_ip", ""),
                "protocol": row.get("protocol", ""),
                "port": to_int(row.get("port")),
                "packet_size": to_int(row.get("packet_size")),
            }
            packet["service"] = get_service(packet["port"])
            records.append(packet)
    return records


import re

def validate_inputs(protocol, source_ip, dest_ip, port_str, min_size_str):
    if protocol and protocol.upper() not in ["TCP", "UDP", "ICMP", "ARP", "DNS"]:
        return "protocol"
    
    ip_pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    if source_ip and not ip_pattern.match(source_ip):
        return "source_ip"
    if dest_ip and not ip_pattern.match(dest_ip):
        return "dest_ip"
    
    if port_str:
        if not port_str.isdigit() or not (0 <= int(port_str) <= 65535):
            return "port"
            
    if min_size_str:
        if not min_size_str.isdigit() or int(min_size_str) <= 0:
            return "min_size"
            
    return None


def filter_records(records, protocol, source_ip, dest_ip, port_str="", min_size_str=""):
    protocol = protocol.strip().upper()
    source_ip = source_ip.strip().lower()
    dest_ip = dest_ip.strip().lower()
    
    port_val = int(port_str) if port_str else None
    min_size_val = int(min_size_str) if min_size_str else None

    filtered = []
    for record in records:
        if protocol and record["protocol"].upper() != protocol:
            continue
        if source_ip and source_ip not in record["source_ip"].lower():
            continue
        if dest_ip and dest_ip not in record["destination_ip"].lower():
            continue
        if port_val is not None and record["port"] != port_val:
            continue
        if min_size_val is not None and record["packet_size"] < min_size_val:
            continue
        filtered.append(record)
    return filtered


def compute_stats(records):
    total = len(records)
    counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "ARP": 0}
    size_sum = 0

    for record in records:
        protocol = record.get("protocol", "").upper()
        if protocol in counts:
            counts[protocol] += 1
        size_sum += to_int(record.get("packet_size"))

    avg_size = round(size_sum / total, 2) if total else 0
    return {
        "total_packets": total,
        "tcp_count": counts["TCP"],
        "udp_count": counts["UDP"],
        "icmp_count": counts["ICMP"],
        "dns_count": counts["DNS"],
        "arp_count": counts["ARP"],
        "avg_packet_size": avg_size,
    }


# ============================================================
#  ROUTES
# ============================================================

@app.route("/")
def index():
    """Serve the main HTML page."""
    return render_template("index.html")


@app.route("/start", methods=["POST"])
def start_monitoring():
    """Start monitoring – set the active flag to True."""
    global monitoring_active, capturing
    monitoring_active = True
    if not capturing:
        capturing = True
        threading.Thread(target=packet_capture_loop, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/stop", methods=["POST"])
def stop_monitoring():
    """Stop monitoring – set the active flag to False."""
    global monitoring_active, capturing
    monitoring_active = False
    capturing = False
    return jsonify({"status": "stopped"})


@app.route("/data", methods=["GET"])
def get_data():
    """
    Main data endpoint.
    Reads optional query parameters from the URL:
      ?protocol=TCP&source_ip=192.168&dest_ip=8.8.8.8&port=80&min_size=500
    Returns JSON with records and statistics.
    """
    # Read filter parameters (empty string if not provided)
    protocol  = request.args.get("protocol",  "").strip()
    source_ip = request.args.get("source_ip", "").strip()
    dest_ip   = request.args.get("dest_ip",   "").strip()
    port_str  = request.args.get("port",      "").strip()
    min_size  = request.args.get("min_size",  "").strip()

    # Apply validation
    global capturing, monitoring_active
    error_field = validate_inputs(protocol, source_ip, dest_ip, port_str, min_size)
    if error_field:
        capturing = False
        monitoring_active = False
        return jsonify({"error": "Invalid input", "data": []})

    # Load all records from CSV
    all_records = load_all_records()

    # Apply filters
    filtered = filter_records(all_records, protocol, source_ip, dest_ip, port_str, min_size)

    # Compute statistics on the filtered set
    stats = compute_stats(filtered)

    return jsonify({
        "monitoring": monitoring_active,
        "records":    filtered,
        "stats":      stats,
    })


# ============================================================
#  AI DATA GENERATION
# ============================================================

def generate_ai_data(num_packets=150):
    global generated_count
    count = len(generate_traffic_data(num_packets, output_file=DATA_FILE))
    generated_count += count
    return count


@app.route("/generate", methods=["POST"])
def generate_new_data():
    count = generate_ai_data(150)
    all_records = load_all_records()
    stats = compute_stats(all_records)
    return jsonify({"status": "generated", "count": count, "stats": stats})


# ============================================================
#  ENTRY POINT
# ============================================================
if __name__ == "__main__":
    print("\n   Network Traffic Monitor is running!")
    print("  Open your browser and go to: http://127.0.0.1:5000\n")
    app.run(debug=True)
