# ============================================================
#  data_generator.py  –  AI Network Traffic Data Generator
# ============================================================

import csv
import random
from datetime import datetime, timedelta

PRIVATE_IP_RANGES = [
    "192.168.1.",
    "192.168.0.",
    "10.0.0.",
    "172.16.0.",
    "172.16.1.",
    "172.16.2.",
]

PUBLIC_IPS = [
    "8.8.8.8", "8.8.4.4",
    "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
    "142.250.80.46", "172.217.14.206",
    "216.58.214.46", "104.18.0.1",
    "93.184.216.34", "151.101.65.140",
    "13.107.42.14", "52.84.13.5",
]

PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP", "DNS"]
PROTOCOL_WEIGHTS = [35, 25, 20, 10, 10]

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    500: "IKE",
    587: "SMTP-TLS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5353: "mDNS",
    8080: "HTTP-Alt",
    1900: "SSDP",
    4500: "IPSec",
}

HIGH_PORTS = list(range(1024, 65535))


def generate_ip(is_private=True):
    if is_private:
        prefix = random.choice(PRIVATE_IP_RANGES)
        return f"{prefix}{random.randint(1, 254)}"
    return random.choice(PUBLIC_IPS)


def generate_port():
    if random.random() < 0.6:
        return random.choice(list(COMMON_PORTS.keys()))
    return random.choice(HIGH_PORTS)


def get_service(port):
    return COMMON_PORTS.get(port, "Unknown")


def generate_packet_size(protocol, port):
    if protocol == "ICMP":
        return random.randint(64, 128)
    if port in [80, 443, 8080]:
        return random.randint(500, 1500)
    if port in [53, 67, 68]:
        return random.randint(50, 300)
    if port in [22, 21, 23]:
        return random.randint(100, 500)
    return random.randint(100, 1400)


def generate_traffic_data(num_packets=100, output_file="data.csv"):
    base_time = datetime.now().replace(hour=8, minute=0, second=0, microsecond=0)
    records = []

    for _ in range(num_packets):
        packet_time = base_time + timedelta(seconds=random.randint(0, 3600 * 4))
        protocol = random.choices(PROTOCOLS, weights=PROTOCOL_WEIGHTS, k=1)[0]
        port = generate_port()

        if protocol == "ICMP":
            packet_size = generate_packet_size(protocol, 0)
            port = 0
            service = "ICMP"
        elif protocol == "ARP":
            packet_size = generate_packet_size(protocol, 0)
            port = 0
            service = "ARP"
        elif protocol == "DNS":
            packet_size = generate_packet_size(protocol, 53)
            port = 53
            service = "DNS"
        else:
            packet_size = generate_packet_size(protocol, port)
            service = get_service(port)

        source_ip = generate_ip(is_private=True)
        dest_ip = generate_ip(is_private=random.random() < 0.3)

        records.append({
            "time": packet_time.strftime("%H:%M:%S"),
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "protocol": protocol,
            "port": port,
            "packet_size": packet_size,
        })

    records.sort(key=lambda row: row["time"])
    fieldnames = ["time", "source_ip", "destination_ip", "protocol", "port", "packet_size"]

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    return records


if __name__ == "__main__":
    generate_traffic_data(num_packets=150)
