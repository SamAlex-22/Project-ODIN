import json
import math
import time
from collections import defaultdict, deque
from datetime import datetime

WINDOW_SECONDS       = 10
UNIQUE_IP_THRESHOLD  = 50
ENTROPY_THRESHOLD    = 2.5
PACKET_RATE_THRESHOLD = 200

_window = deque()

def _shannon_entropy(values):
    if not values:
        return 0.0
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

def process_conn_line(line: dict) -> dict | None:
    try:
        ts      = float(line.get("ts", 0))
        src_ip  = line.get("id.orig_h", "")
        proto   = line.get("proto", "")
    except (ValueError, TypeError):
        return None

    if proto not in ("tcp",):
        return None

    now = ts
    _window.append((ts, src_ip))

    cutoff = now - WINDOW_SECONDS
    while _window and _window[0][0] < cutoff:
        _window.popleft()

    recent_ips    = [entry[1] for entry in _window]
    unique_ips    = len(set(recent_ips))
    packet_rate   = len(recent_ips)
    entropy       = _shannon_entropy(recent_ips)

    triggered = False
    reasons   = []

    if unique_ips > UNIQUE_IP_THRESHOLD and entropy < ENTROPY_THRESHOLD:
        triggered = True
        reasons.append(f"src_ip_entropy={entropy} (threshold<{ENTROPY_THRESHOLD}), {unique_ips} unique sources in {WINDOW_SECONDS}s")

    if packet_rate > PACKET_RATE_THRESHOLD:
        triggered = True
        reasons.append(f"packet_rate={packet_rate}/10s (threshold>{PACKET_RATE_THRESHOLD})")

    if not triggered:
        return None

    confidence = min(0.5 + (unique_ips / UNIQUE_IP_THRESHOLD) * 0.25 + ((ENTROPY_THRESHOLD - entropy) / ENTROPY_THRESHOLD) * 0.25, 0.99)

    return {
        "timestamp":    datetime.utcnow().isoformat() + "Z",
        "threat_class": "ddos",
        "severity":     3,
        "confidence":   round(confidence, 2),
        "src_ip":       src_ip,
        "evidence": {
            "unique_source_ips":  unique_ips,
            "packet_rate_10s":    packet_rate,
            "source_ip_entropy":  entropy,
            "entropy_threshold":  ENTROPY_THRESHOLD,
            "window_seconds":     WINDOW_SECONDS,
            "explanation": "; ".join(reasons)
        }
    }
