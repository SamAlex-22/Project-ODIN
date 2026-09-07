"""
Kafka -> stateful stream processing -> detectors -> alerts.

This is the prototype stand-in for the Flink/Spark layer in the full
Hybrid 1 architecture. It deliberately does exactly one job on top of
consuming from Kafka: normalize the raw Zeek event into a stable schema,
then hand it to each detector plugin unchanged. Swapping this file for a
Flink job later means reimplementing this loop in Flink's API -- the
normalized event shape and the detector classes in detectors/ do not
change.

    Kafka Consumer -> normalize_event() -> Detector.process(event) -> alert
"""

import json
import time
from collections import deque
from pathlib import Path

from kafka import KafkaConsumer

from detectors import ACTIVE_DETECTORS

KAFKA_BOOTSTRAP = "localhost:9092"
TOPIC           = "zeek-conn"
GROUP_ID        = "ntro-stream-consumer"
ALERTS_FILE     = Path("alerts.json")
HEARTBEAT_FILE  = Path(".heartbeat")
THROUGHPUT_FILE = Path(".throughput")
THROUGHPUT_WINDOW_SECONDS = 10


def normalize_event(raw: dict) -> dict | None:
    """Zeek's dotted conn.log keys -> a stable, Zeek-independent event shape.
    Every detector depends on this shape, not on Zeek's field names -- this
    is the seam that would let a Suricata EVE JSON source feed the same
    detectors with only this function changing."""
    try:
        return {
            "ts":         float(raw.get("ts", 0)),
            "uid":        raw.get("uid"),
            "src_ip":     raw.get("id.orig_h", ""),
            "src_port":   int(raw.get("id.orig_p", 0)) or None,
            "dst_ip":     raw.get("id.resp_h", ""),
            "dst_port":   int(raw.get("id.resp_p", 0)) or None,
            "proto":      raw.get("proto", ""),
            "conn_state": raw.get("conn_state", ""),
        }
    except (ValueError, TypeError):
        return None


def connect_consumer(retries=30, delay=2):
    for attempt in range(1, retries + 1):
        try:
            consumer = KafkaConsumer(
                TOPIC,
                bootstrap_servers=KAFKA_BOOTSTRAP,
                group_id=GROUP_ID,
                auto_offset_reset="latest",
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            )
            print(f"[STREAM] Connected to Kafka topic '{TOPIC}'")
            return consumer
        except Exception as e:
            print(f"[STREAM] Kafka not ready yet ({attempt}/{retries}): {e}")
            time.sleep(delay)
    raise RuntimeError(f"Could not connect to Kafka at {KAFKA_BOOTSTRAP} after {retries} attempts")


def write_alert(alert: dict):
    with open(ALERTS_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")
    print(f"[ALERT] {alert['threat_label']} detected | confidence={alert['confidence']} | src={alert['src_ip']}")


def touch_heartbeat():
    try:
        HEARTBEAT_FILE.write_text(str(time.time()))
    except OSError:
        pass


def write_throughput(rate: float, total: int):
    try:
        THROUGHPUT_FILE.write_text(json.dumps({
            "events_per_sec": round(rate, 1),
            "total_events": total,
            "updated": time.time(),
        }))
    except OSError:
        pass


def run():
    ALERTS_FILE.touch()
    consumer = connect_consumer()
    detectors = [cls() for cls in ACTIVE_DETECTORS]
    print(f"[STREAM] Detection engine active with {len(detectors)} detectors: "
          + ", ".join(d.name for d in detectors))

    consumed = 0
    recent_arrivals = deque()   # wall-clock times of recently consumed events
    for message in consumer:
        touch_heartbeat()
        event = normalize_event(message.value)
        if event is None:
            continue
        consumed += 1

        now = time.time()
        recent_arrivals.append(now)
        cutoff = now - THROUGHPUT_WINDOW_SECONDS
        while recent_arrivals and recent_arrivals[0] < cutoff:
            recent_arrivals.popleft()
        write_throughput(len(recent_arrivals) / THROUGHPUT_WINDOW_SECONDS, consumed)

        if consumed % 25 == 0:
            print(f"[STREAM] {consumed} events consumed from Kafka")

        for detector in detectors:
            alert = detector.process(event)
            if alert:
                write_alert(alert)


if __name__ == "__main__":
    run()
