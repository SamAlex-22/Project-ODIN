import os
from pathlib import Path

base = Path("/Users/alex/Project-ODIN/ntro-prototype")

files = {
    "backend/detectors/ddos.py": """import json
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

    now = time.time()
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
""",
    "backend/detectors/recon.py": """import time
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

    now = time.time()
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
""",
    "backend/detectors/c2.py": """import math
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
""",
    "backend/watcher.py": """import json
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
        f.write(json.dumps(alert) + "\\n")
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
""",
    "backend/app.py": """import json
import os
import time
from pathlib import Path
from flask import Flask, jsonify, request, Response
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

ALERTS_FILE = Path("alerts.json")
ALERTS_FILE.touch()

def read_alerts(limit: int = 100) -> list:
    try:
        lines = ALERTS_FILE.read_text().strip().splitlines()
        parsed = []
        for line in lines:
            try:
                parsed.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return parsed[-limit:]
    except Exception:
        return []

@app.route("/api/alerts")
def get_alerts():
    limit = int(request.args.get("limit", 100))
    alerts = read_alerts(limit)
    return jsonify(alerts)

@app.route("/api/stats")
def get_stats():
    alerts = read_alerts(500)
    stats = {"ddos": 0, "recon": 0, "c2": 0, "total": len(alerts)}
    for a in alerts:
        tc = a.get("threat_class", "")
        if tc in stats:
            stats[tc] += 1
    return jsonify(stats)

@app.route("/api/clear", methods=["POST"])
def clear_alerts():
    ALERTS_FILE.write_text("")
    return jsonify({"status": "cleared"})

@app.route("/api/stream")
def stream():
    def event_generator():
        last_size = ALERTS_FILE.stat().st_size if ALERTS_FILE.exists() else 0
        yield "data: {\\"type\\": \\"connected\\"}\\n\\n"
        while True:
            time.sleep(0.5)
            try:
                current_size = ALERTS_FILE.stat().st_size
            except FileNotFoundError:
                continue
            if current_size > last_size:
                with open(ALERTS_FILE, "r") as f:
                    f.seek(last_size)
                    new_content = f.read()
                last_size = current_size
                for raw_line in new_content.strip().splitlines():
                    if raw_line:
                        yield f"data: {raw_line}\\n\\n"

    return Response(event_generator(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
"""
}

for filepath, content in files.items():
    p = base / filepath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)

print("Scaffolded backend files.")
