#!/bin/bash
echo "[+] Starting port scan on 127.0.0.1..."
nmap -sS -p 1-1000 -T4 127.0.0.1
echo "[+] Port scan complete."
