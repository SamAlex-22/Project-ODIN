import os
from pathlib import Path

base = Path("/Users/alex/Project-ODIN/ntro-prototype")

files = {
    "docker-compose.yml": """version: "3.8"

services:
  zeek:
    image: zeek/zeek:latest
    container_name: zeek_monitor
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./zeek/local.zeek:/usr/local/zeek/share/zeek/site/local.zeek
      - ./backend/zeek-logs:/usr/local/zeek/logs/current
    command: >
      zeek -i lo
      /usr/local/zeek/share/zeek/site/local.zeek
    restart: unless-stopped
""",
    "zeek/local.zeek": """@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ssl

redef Log::default_writer = Log::WRITER_ASCII;
redef LogAscii::use_json = T;
""",
    "traffic/generate_ddos.sh": """#!/bin/bash
echo "[+] Starting SYN flood to 127.0.0.1:8080 for 30 seconds..."
sudo hping3 -S --flood --rand-source -p 8080 127.0.0.1 &
HPING_PID=$!
sleep 30
sudo kill $HPING_PID
echo "[+] SYN flood stopped."
""",
    "traffic/generate_recon.sh": """#!/bin/bash
echo "[+] Starting port scan on 127.0.0.1..."
nmap -sS -p 1-1000 -T4 127.0.0.1
echo "[+] Port scan complete."
""",
    "traffic/generate_c2.py": """#!/usr/bin/env python3
import socket
import time
import random

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 9999
INTERVAL    = 30
JITTER      = 2
BEACONS     = 8

print(f"[C2 Generator] Sending {BEACONS} beacons to {TARGET_HOST}:{TARGET_PORT}")
for i in range(BEACONS):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((TARGET_HOST, TARGET_PORT))
        s.send(b"beacon\\n")
        s.close()
    except Exception as e:
        pass
    wait = INTERVAL + random.uniform(-JITTER, JITTER)
    if i < BEACONS - 1:
        time.sleep(wait)
print("[C2 Generator] Done.")
""",
    "backend/requirements.txt": """flask==3.0.3
flask-cors==4.0.1
watchdog==4.0.1
""",
    "backend/detectors/__init__.py": "",
    "start_demo.sh": """#!/bin/bash
set -e

echo "======================================"
echo "  NTRO AI Threat Detection Prototype  "
echo "======================================"

echo "[1/4] Starting Zeek..."
docker-compose up -d
sleep 3

echo "[2/4] Starting detection engine..."
cd backend
python3 watcher.py &
WATCHER_PID=$!
echo "      Detection engine PID: $WATCHER_PID"

echo "[3/4] Starting API server..."
python3 app.py &
API_PID=$!
echo "      API server PID: $API_PID"
cd ..

echo "[4/4] Starting dashboard..."
cd frontend
npm start &
cd ..

echo ""
echo "======================================"
echo "  Dashboard: http://localhost:3000    "
echo "  API:       http://localhost:5000    "
echo "======================================"
echo ""
echo "Press Ctrl+C to stop all services."

trap "kill $WATCHER_PID $API_PID; docker-compose down" EXIT
wait
"""
}

for filepath, content in files.items():
    p = base / filepath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    if filepath.endswith(".sh") or filepath.endswith(".py"):
        p.chmod(0o755)

print("Scaffolded basic files.")
