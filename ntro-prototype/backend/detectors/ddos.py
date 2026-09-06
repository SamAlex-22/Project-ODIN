"""
DDoS / SYN Flood Detector
-------------------------
Primary evidence:   packet rate over a sliding window (the only condition
                     that actually triggers an alert).
Supporting evidence: unique source IP count, source-IP entropy.

Earlier version of this detector required low source-IP entropy alongside
a high unique-IP count, on the theory "spoofed flood = many IPs but all
hitting one dst = low entropy". That assumption doesn't hold: hping3
--rand-source draws source IPs uniformly at random, and uniformly random
values *maximize* entropy rather than lowering it (each of N packets gets
a distinct source, so entropy grows with N). Gating on low entropy would
mean the detector never fires against the exact attack it's meant to catch.
Packet-rate anomaly is the reliable signal regardless of source
distribution; entropy is now reported as context, never as a gate.
"""

from collections import defaultdict, deque

from .base import Detector

WINDOW_SECONDS       = 10
PACKET_RATE_THRESHOLD = 200   # primary trigger: connections seen in WINDOW_SECONDS
UNIQUE_IP_SUPPORT     = 50    # supporting evidence only


def _shannon_entropy(values):
    if not values:
        return 0.0
    import math
    counts = defaultdict(int)
    for v in values:
        counts[v] += 1
    total = len(values)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class DDoSDetector(Detector):
    name = "ddos"
    threat_class = "ddos"
    threat_label = "DDoS / SYN Flood"

    def __init__(self):
        self._window = deque()   # [(ts, src_ip, dst_port)]

    def process(self, event: dict) -> dict | None:
        if event.get("proto") != "tcp":
            return None

        ts       = event["ts"]
        src_ip   = event["src_ip"]
        dst_ip   = event["dst_ip"]
        dst_port = event["dst_port"]

        self._window.append((ts, src_ip, dst_port))
        cutoff = ts - WINDOW_SECONDS
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()

        recent      = self._window
        recent_ips  = [e[1] for e in recent]
        packet_rate = len(recent)
        unique_ips  = len(set(recent_ips))
        entropy     = _shannon_entropy(recent_ips)

        if packet_rate <= PACKET_RATE_THRESHOLD:
            return None

        evidence = [
            f"Packet rate: {packet_rate} connections/{WINDOW_SECONDS}s (threshold>{PACKET_RATE_THRESHOLD})",
            f"Unique source IPs: {unique_ips}",
            f"Source IP entropy: {entropy} bits (informational, not a trigger condition)",
            f"Destination port: {dst_port}",
            f"Observation window: {WINDOW_SECONDS}s",
        ]
        if unique_ips > UNIQUE_IP_SUPPORT:
            evidence.append(f"Supporting evidence: {unique_ips} unique sources exceeds {UNIQUE_IP_SUPPORT}")
        if unique_ips > 1:
            evidence.append("src_ip reflects only the most recent packet -- sources appear randomized/spoofed")

        confidence = 0.6 + min((packet_rate / PACKET_RATE_THRESHOLD - 1) * 0.15, 0.35)
        severity = "CRITICAL" if packet_rate > PACKET_RATE_THRESHOLD * 3 else "HIGH"

        return self.alert(
            src_ip=src_ip, src_port=None, dst_ip=dst_ip, dst_port=dst_port,
            flow_id=event.get("uid"), severity=severity, confidence=confidence,
            evidence=evidence, window_seconds=WINDOW_SECONDS,
        )
