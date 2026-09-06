import time
from collections import defaultdict
from datetime import datetime

WINDOW_SECONDS = 60
PORT_THRESHOLD = 15
HOST_THRESHOLD = 10

_state = defaultdict(list)
_last_alerted = {}

def process_conn_line(line: dict) -> dict | None:
    try:
        ts       = float(line.get("ts", 0))
        src_ip   = line.get("id.orig_h", "")
        dst_ip   = line.get("id.resp_h", "")
        dst_port = int(line.get("id.resp_p", 0))
        proto    = line.get("proto", "")
    except (ValueError, TypeError):
        return None

    if not src_ip or dst_port == 0:
        return None

    now = ts
    if not hasattr(process_conn_line, "last_ts"):
        process_conn_line.last_ts = 0
    if now < process_conn_line.last_ts - 5:
        _state.clear()
        _last_alerted.clear()
    process_conn_line.last_ts = now

    _state[src_ip].append((ts, dst_port, dst_ip))

    cutoff = now - WINDOW_SECONDS
    _state[src_ip] = [e for e in _state[src_ip] if e[0] >= cutoff]

    entries       = _state[src_ip]
    unique_ports  = len(set(e[1] for e in entries))
    unique_hosts  = len(set(e[2] for e in entries))

    triggered = False
    reasons   = []

    if unique_ports > PORT_THRESHOLD:
        triggered = True
        reasons.append(f"{unique_ports} unique dst ports in {WINDOW_SECONDS}s (threshold>{PORT_THRESHOLD})")

    if unique_hosts > HOST_THRESHOLD:
        triggered = True
        reasons.append(f"{unique_hosts} unique dst hosts in {WINDOW_SECONDS}s (threshold>{HOST_THRESHOLD})")

    if not triggered:
        return None

    if now - _last_alerted.get(src_ip, 0) < 20:
        return None
    _last_alerted[src_ip] = now

    confidence = min(0.5 + (unique_ports / PORT_THRESHOLD) * 0.4, 0.99)

    return {
        "timestamp":    datetime.utcnow().isoformat() + "Z",
        "threat_class": "recon",
        "severity":     2,
        "confidence":   round(confidence, 2),
        "src_ip":       src_ip,
        "evidence": {
            "unique_dst_ports":   unique_ports,
            "unique_dst_hosts":   unique_hosts,
            "window_seconds":     WINDOW_SECONDS,
            "port_threshold":     PORT_THRESHOLD,
            "sample_ports":       sorted(set(e[1] for e in entries))[:10],
            "explanation": "; ".join(reasons)
        }
    }
