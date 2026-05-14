import subprocess
import csv
import json
import os
import uuid
import requests
import time
from collections import Counter

# ------------------------------------------------
# CONFIGURATION
# ------------------------------------------------

INTERFACE = "enp0s3"
CAPTURE_DURATION = 100
THRESHOLD = 40

PCAP_FILE = "/tmp/traffic.pcap"
CSV_FILE = "/tmp/traffic.csv"
ALERT_FILE = "/tmp/alert.json"

# ---- Airia Webhook ----
AIRIA_API_URL = "AIRIA-API-URL"
AIRIA_API_KEY = "AIRIA-API-KEY"

# Metadata
DESTINATION_HOST = "Internal-server"
DESTINATION_IP = "x.x.x.x"


# ------------------------------------------------
# STEP 1 - Capture Traffic (tcpdump, no tshark)
# ------------------------------------------------

def capture_traffic():
    if os.path.exists(PCAP_FILE):
        os.remove(PCAP_FILE)

    capture_cmd = [
        "tcpdump",
        "-i", INTERFACE,
        "-w", PCAP_FILE,
        "icmp", "and", "dst", "host", "x.x.x.x"
    ]

    print(f"[+] Capturing on {INTERFACE} for {CAPTURE_DURATION}s")
    proc = subprocess.Popen(capture_cmd)
    time.sleep(CAPTURE_DURATION)
    proc.terminate()
    proc.wait()

    os.chmod(PCAP_FILE, 0o644)

    if not os.path.exists(PCAP_FILE):
        raise RuntimeError("PCAP capture failed.")

    print(f"[+] Capture saved to {PCAP_FILE}")


# ------------------------------------------------
# STEP 2 - Convert to CSV (tcpdump only, no tshark)
# ------------------------------------------------

def convert_to_csv():
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)

    read_cmd = [
        "tcpdump",
        "-r", PCAP_FILE,
        "-n",
        "-tt",
        "-q"
    ]

    result = subprocess.run(read_cmd, capture_output=True, text=True)

    with open(CSV_FILE, "w", newline="") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(["frame.time_epoch", "ip.src", "ip.dst", "ip.proto", "frame.len"])

        for line in result.stdout.splitlines():
            # tcpdump -tt -q line format:
            # 1715000000.000000 IP 192.168.8.103 > 192.168.8.106: ICMP ...  length 64
            parts = line.split()
            if len(parts) < 5:
                continue
            try:
                timestamp = parts[0]
                if parts[1] != "IP":
                    continue
                src = parts[2]
                dst = parts[4].rstrip(":")
                proto = "1"  # ICMP
                # grab length from end of line
                length = "0"
                if "length" in parts:
                    li = parts.index("length")
                    length = parts[li + 1]
                writer.writerow([timestamp, src, dst, proto, length])
            except Exception:
                continue

    print(f"[+] CSV created at {CSV_FILE}")


# ------------------------------------------------
# STEP 3 - Analyze Traffic
# ------------------------------------------------

def analyze_traffic():
    ip_counter = Counter()

    with open(CSV_FILE, newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            src_ip = (row.get("ip.src") or "").strip().strip('"')
            if src_ip:
                ip_counter[src_ip] += 1

    print("\n[+] Traffic volume per source IP:\n")
    for ip, count in ip_counter.items():
        print(f"{ip}: {count} packets")

    for ip, count in ip_counter.items():
        if count > THRESHOLD:
            print(f"\n[!] Suspicious IP detected: {ip}")
            return ip, count

    print("\n[+] No suspicious activity detected.")
    return None, None


# ------------------------------------------------
# STEP 4 - Generate Alert JSON
# ------------------------------------------------

def generate_alert(ip, count):
    alert_id = f"SOC-{uuid.uuid4().hex[:8].upper()}"

    alert = {
        "alert_id": alert_id,
        "alert_type": "Suspicious Network Volume",
        "indicator_type": "ip",
        "indicator_value": ip,
        "destination_host": DESTINATION_HOST,
        "destination_ip": DESTINATION_IP,
        "evidence": {
            "packet_count": count,
            "time_window_seconds": CAPTURE_DURATION,
            "data_source": os.path.basename(PCAP_FILE)
        },
        "analyst_question": "Is this expected activity or suspicious scanning/noise?"
    }

    with open(ALERT_FILE, "w") as f:
        json.dump(alert, f, indent=4)

    print(f"[+] Alert JSON written to {ALERT_FILE}")
    return alert


# ------------------------------------------------
# STEP 5 - Send to Airia API
# ------------------------------------------------

def send_to_airia(alert):
    headers = {
        "Content-Type": "application/json",
        "X-API-KEY": AIRIA_API_KEY
    }

    payload = {
        "userInput": json.dumps(alert),
        "asyncOutput": False
    }

    print("[+] Sending alert to Airia Agent Execution API...")

    response = requests.post(
        AIRIA_API_URL,
        headers=headers,
        json=payload,
        timeout=100
    )

    response.raise_for_status()

    print(f"[+] Airia responded with status {response.status_code}")

    try:
        data = response.json()
        print("[+] Airia Response JSON:")
        print(json.dumps(data, indent=2))
    except Exception:
        print("[+] Airia response (raw text):")
        print(response.text)


# ------------------------------------------------
# MAIN
# ------------------------------------------------

def main():
    try:
        capture_traffic()
        convert_to_csv()
        ip, count = analyze_traffic()

        if ip:
            alert = generate_alert(ip, count)
            send_to_airia(alert)
        else:
            print("[+] No alert generated, nothing sent to Airia.")

        print("\n[+] Workflow complete.")

    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    main()