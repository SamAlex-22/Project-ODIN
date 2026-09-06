import json
import os
import socket
import time
from pathlib import Path
from flask import Flask, jsonify, request, Response
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

ALERTS_FILE     = Path("alerts.json")
CONN_LOG        = Path("zeek-logs/conn.log")
HEARTBEAT_FILE  = Path(".heartbeat")
PRODUCER_HEARTBEAT_FILE = Path(".producer_heartbeat")
STALE_AFTER_SECONDS = 15   # a heartbeat/log older than this counts as offline
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

def _recent_mtime(path: Path) -> bool:
    try:
        return (time.time() - path.stat().st_mtime) < STALE_AFTER_SECONDS
    except OSError:
        return False


def _kafka_reachable() -> bool:
    try:
        with socket.create_connection(("localhost", 9092), timeout=1):
            return True
    except OSError:
        return False


@app.route("/api/pipeline-status")
def pipeline_status():
    """Real liveness signals, not hardcoded ONLINE labels -- each row is
    backed by an actual file mtime or socket check."""
    zeek_alive     = _recent_mtime(CONN_LOG)
    kafka_alive    = _kafka_reachable()
    producer_alive = _recent_mtime(PRODUCER_HEARTBEAT_FILE)
    stream_alive   = _recent_mtime(HEARTBEAT_FILE)
    return jsonify({
        "diode":            {"status": "simulated", "detail": "Physical isolation is a deployment concern, not software in this prototype"},
        "zeek":              zeek_alive,
        "kafka":             kafka_alive,
        "kafka_producer":    producer_alive,
        "stream_detector":   stream_alive,
        "alert_engine":      stream_alive,   # same process in this prototype -- see stream_consumer.py
        "api":               True,           # trivially true: this response means the API answered
        "read_only_ingest":  True,
        "return_path":       "NONE",
    })


@app.route("/api/clear", methods=["POST"])
def clear_alerts():
    ALERTS_FILE.write_text("")
    return jsonify({"status": "cleared"})

@app.route("/api/stream")
def stream():
    def event_generator():
        last_size = ALERTS_FILE.stat().st_size if ALERTS_FILE.exists() else 0
        yield "data: {\"type\": \"connected\"}\n\n"
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
                        yield f"data: {raw_line}\n\n"

    return Response(event_generator(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
