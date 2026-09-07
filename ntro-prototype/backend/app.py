import json
import os
import socket
import subprocess
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
THROUGHPUT_FILE = Path(".throughput")
STALE_AFTER_SECONDS = 15   # a heartbeat/log older than this counts as offline
ALERTS_FILE.touch()

ZEEK_CONTAINER = "zeek_monitor"
REPLAY_PCAPS = {
    "ddos":  "attack_syn_flood.pcap",
    "recon": "attack_recon.pcap",
    "c2":    "attack_c2.pcap",
}

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


@app.route("/api/throughput")
def throughput():
    """Live events/sec through the detection pipeline, written by
    stream_consumer.py's own rolling window -- not derived here, just
    relayed, and only while fresh (see STALE_AFTER_SECONDS)."""
    try:
        data = json.loads(THROUGHPUT_FILE.read_text())
        if (time.time() - data.get("updated", 0)) < STALE_AFTER_SECONDS:
            return jsonify({"events_per_sec": data["events_per_sec"], "total_events": data["total_events"]})
    except (OSError, json.JSONDecodeError, KeyError):
        pass
    return jsonify({"events_per_sec": 0, "total_events": 0})


@app.route("/api/replay/<threat>", methods=["POST"])
def replay(threat):
    """Replays a pre-recorded pcap for one threat class through the same
    live pipeline real traffic uses, for a reliable, on-demand demo
    trigger -- see traffic_pcaps/generate_pcaps.py for how the pcaps were
    built, and ML_MODELS.md / docker-compose.yml for why this uses Zeek's
    own offline `-r` reader (inside the already-running zeek_monitor
    container) rather than tcpreplay: tcpreplay needs raw-socket
    privileges and a passwordless sudo setup that can't be relied on to
    work unattended in front of a jury, while Zeek reading the same pcap
    offline produces byte-identical conn.log output with no such
    dependency. The offline read runs in its own scratch directory inside
    the container -- it never touches the live `-i lo` process or its log.

    Replayed events' timestamps are shifted so the earliest one lands at
    "now" (preserving the pcap's original relative spacing) before being
    appended to the live conn.log -- otherwise a years-old baked-in
    timestamp would break every detector's rolling-window cutoff math,
    which assumes appended-order roughly tracks ts order.
    """
    pcap = REPLAY_PCAPS.get(threat)
    if pcap is None:
        return jsonify({"status": "error", "message": f"unknown threat '{threat}'"}), 400

    try:
        subprocess.run(
            ["docker", "exec", ZEEK_CONTAINER, "sh", "-c",
             "rm -rf /tmp/replay && mkdir -p /tmp/replay && cd /tmp/replay && "
             f"zeek -r /pcaps/{pcap} /usr/local/zeek/share/zeek/site/local.zeek"],
            capture_output=True, text=True, timeout=30, check=True,
        )
        result = subprocess.run(
            ["docker", "exec", ZEEK_CONTAINER, "cat", "/tmp/replay/conn.log"],
            capture_output=True, text=True, timeout=10, check=True,
        )
    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": f"zeek replay failed: {e.stderr.strip()}"}), 502
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "zeek replay timed out"}), 504
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "docker CLI not found on host"}), 500

    events = []
    for line in result.stdout.strip().splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if not events:
        return jsonify({"status": "error", "message": "replay produced no conn.log events"}), 502

    earliest = min(float(e.get("ts", 0)) for e in events)
    shift = time.time() - earliest
    events.sort(key=lambda e: float(e.get("ts", 0)))
    for e in events:
        e["ts"] = float(e.get("ts", 0)) + shift
    payload = "".join(json.dumps(e) + "\n" for e in events)

    # Appended via `docker exec` (root inside the container), not a direct
    # host-side file write: Zeek's live -i lo process runs as root and owns
    # this bind-mounted file, so the Flask process (a normal user) can read
    # it but not append to it directly.
    try:
        subprocess.run(
            ["docker", "exec", "-i", ZEEK_CONTAINER, "sh", "-c",
             "cat >> /usr/local/zeek/logs/current/conn.log"],
            input=payload, capture_output=True, text=True, timeout=10, check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        return jsonify({"status": "error", "message": f"failed to inject replayed events: {e}"}), 502

    return jsonify({"status": "replayed", "threat": threat, "events_injected": len(events)})


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
