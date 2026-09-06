"""
Zeek -> Kafka producer.

Tails Zeek's conn.log (JSON lines) and publishes each raw event onto the
"zeek-conn" Kafka topic. This is the boundary between the NSM layer and the
streaming layer in the Hybrid 1 architecture: everything downstream of
Kafka (the stream consumer, the detectors) only ever sees events that came
off the bus, never the log file directly -- which is exactly what makes it
possible to swap this producer for a real Filebeat/Kafka Connect pipeline,
or the consumer for Flink, without touching anything else.
"""

import json
import time
from pathlib import Path

from kafka import KafkaProducer

KAFKA_BOOTSTRAP = "localhost:9092"
TOPIC           = "zeek-conn"
CONN_LOG        = Path("zeek-logs/conn.log")
HEARTBEAT_FILE  = Path(".producer_heartbeat")
POLL_INTERVAL   = 0.5


def touch_heartbeat():
    try:
        HEARTBEAT_FILE.write_text(str(time.time()))
    except OSError:
        pass


def connect_producer(retries=30, delay=2):
    for attempt in range(1, retries + 1):
        try:
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                retries=5,
            )
            print(f"[PRODUCER] Connected to Kafka at {KAFKA_BOOTSTRAP}")
            return producer
        except Exception as e:
            print(f"[PRODUCER] Kafka not ready yet ({attempt}/{retries}): {e}")
            time.sleep(delay)
    raise RuntimeError(f"Could not connect to Kafka at {KAFKA_BOOTSTRAP} after {retries} attempts")


def tail_file(filepath: Path):
    while not filepath.exists():
        print(f"[PRODUCER] Waiting for {filepath}...")
        time.sleep(2)
    print(f"[PRODUCER] Tailing {filepath}")
    with open(filepath, "r") as f:
        f.seek(0, 2)   # only new lines from here on
        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(POLL_INTERVAL)


def run():
    producer = connect_producer()
    sent = 0
    for raw_line in tail_file(CONN_LOG):
        if not raw_line:
            continue
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        producer.send(TOPIC, event)
        touch_heartbeat()
        sent += 1
        if sent % 25 == 0:
            print(f"[ZEEK] Event received | [KAFKA] {sent} events published to '{TOPIC}'")


if __name__ == "__main__":
    run()
