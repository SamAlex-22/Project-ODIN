import math
import time
from collections import defaultdict
from datetime import datetime

MIN_OBSERVATIONS  = 5
CV_THRESHOLD      = 0.35
MIN_INTERVAL      = 5
MAX_INTERVAL      = 600

_connections = defaultdict(list)
_alerted     = set()

def _statistics(timestamps):
    if len(timestamps) < 2:
        return None, None, None
    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
    n    = len(intervals)
    mean = sum(intervals) / n
    variance = sum((x - mean) ** 2 for x in intervals) / n
    std  = math.sqrt(variance)
    cv   = std / mean if mean > 0 else float("inf")
    return round(mean, 2), round(std, 2), round(cv, 4)

def process_conn_line(line: dict) -> dict | None:
    try:
        ts       = float(line.get("ts", 0))
        src_ip   = line.get("id.orig_h", "")
        dst_ip   = line.get("id.resp_h", "")
        dst_port = int(line.get("id.resp_p", 0))
    except (ValueError, TypeError):
        return None

    if not src_ip or not dst_ip:
        return None

    key = (src_ip, dst_ip, dst_port)
    _connections[key].append(ts)
    _connections[key].sort()

    if len(_connections[key]) > 20:
        _connections[key] = _connections[key][-20:]

    observations = _connections[key]

    if len(observations) < MIN_OBSERVATIONS:
        return None

    mean_interval, std_interval, cv = _statistics(observations)
    if mean_interval is None:
        return None

    if not (MIN_INTERVAL <= mean_interval <= MAX_INTERVAL):
        return None

    if cv > CV_THRESHOLD:
        return None

    if key in _alerted:
        return None
    _alerted.add(key)

    confidence = min(0.5 + (CV_THRESHOLD - cv) / CV_THRESHOLD * 0.45, 0.99)

    return {
        "timestamp":    datetime.utcnow().isoformat() + "Z",
        "threat_class": "c2",
        "severity":     4,
        "confidence":   round(confidence, 2),
        "src_ip":       src_ip,
        "evidence": {
            "dst_ip":             dst_ip,
            "dst_port":           dst_port,
            "observations":       len(observations),
            "mean_interval_s":    mean_interval,
            "std_interval_s":     std_interval,
            "coefficient_of_variation": cv,
            "cv_threshold":       CV_THRESHOLD,
            "explanation": f"Regular beaconing detected: {len(observations)} connections to {dst_ip}:{dst_port}, mean interval={mean_interval}s, CV={cv} (threshold<{CV_THRESHOLD})"
        }
    }
