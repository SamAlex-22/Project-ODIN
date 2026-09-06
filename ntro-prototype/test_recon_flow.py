import json
import time
from scapy.all import rdpcap, TCP, IP
import sys
sys.path.append("backend")
from detectors.recon import process_conn_line

print("Loading attack_recon.pcap...")
packets = rdpcap("traffic_pcaps/attack_recon.pcap")

print(f"Simulating Zeek parsing for {len(packets)} packets...")
alerts = []
for pkt in packets:
    if IP in pkt and TCP in pkt:
        # Simulate Zeek JSON log line
        line = {
            "ts": float(pkt.time),
            "id.orig_h": pkt[IP].src,
            "id.resp_h": pkt[IP].dst,
            "id.resp_p": pkt[TCP].dport,
            "proto": "tcp"
        }
        alert = process_conn_line(line)
        if alert:
            alerts.append(alert)

if alerts:
    print(f"\\nSUCCESS! Recon detector fired {len(alerts)} alerts.")
    print("Latest Alert Evidence:")
    print(json.dumps(alerts[-1], indent=2))
else:
    print("\\nFAILED: No alerts fired.")
