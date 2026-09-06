#!/usr/bin/env python3
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
        s.send(b"beacon\n")
        s.close()
    except Exception as e:
        pass
    wait = INTERVAL + random.uniform(-JITTER, JITTER)
    if i < BEACONS - 1:
        time.sleep(wait)
print("[C2 Generator] Done.")
