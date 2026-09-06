import json
import os
import time
from pathlib import Path

from detectors.ddos  import process_conn_line as ddos_detect
from detectors.recon import process_conn_line as recon_detect
from detectors.c2    import process_conn_line as c2_detect

CONN_LOG    = Path("zeek-logs/conn.log")
ALERTS_FILE = Path("alerts.json")
POLL_INTERVAL = 0.5

def tail_file(filepath: Path):
    while not filepath.exists():
        print(f"[Watcher] Waiting for {filepath}...")
        time.sleep(2)
    print(f"[Watcher] Tailing {filepath}")
    with open(filepath, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(POLL_INTERVAL)

def write_alert(alert: dict):
    with open(ALERTS_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")
    print(f"[ALERT] {alert['threat_class'].upper()} | confidence={alert['confidence']} | src={alert['src_ip']}")

def run():
    ALERTS_FILE.touch()
    detectors = [ddos_detect, recon_detect, c2_detect]
    print("[Watcher] Starting detection engine...")
    for raw_line in tail_file(CONN_LOG):
        try:
            line = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        for detector in detectors:
            alert = detector(line)
            if alert:
                write_alert(alert)

if __name__ == "__main__":
    run()
