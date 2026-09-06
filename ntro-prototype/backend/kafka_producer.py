import json
import time
from pathlib import Path
from kafka import KafkaProducer
from sh import tail

KAFKA_BROKER = 'localhost:9092'
TOPIC = 'zeek-raw'
ZEEK_LOG = Path("backend/zeek-logs/conn.log")

print(f"[Kafka Producer] Waiting for {ZEEK_LOG}...")
while not ZEEK_LOG.exists():
    time.sleep(1)

print(f"[Kafka Producer] Connected. Tailing {ZEEK_LOG} and publishing to Kafka topic '{TOPIC}'...")

producer = KafkaProducer(
    bootstrap_servers=[KAFKA_BROKER],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

# Send a dummy message to forcefully create the topic before PySpark boots
print(f"[Kafka Producer] Initializing topic '{TOPIC}'...")
producer.send(TOPIC, {"_init": True})
producer.flush()

for line in tail("-F", ZEEK_LOG, _iter=True):
    line = line.strip()
    if not line:
        continue
    try:
        data = json.loads(line)
        producer.send(TOPIC, data)
    except json.JSONDecodeError:
        continue
