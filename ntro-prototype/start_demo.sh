#!/bin/bash
set -e

echo "======================================"
echo "  NTRO AI Threat Detection Prototype  "
echo "======================================"

echo "[1/4] Starting Zeek & Kafka..."
docker rm -f zeek_monitor 2>/dev/null || true
docker-compose down 2>/dev/null || true
docker-compose up -d --remove-orphans
echo "Waiting for Kafka (9092)..."
while ! nc -z localhost 9092; do   
  sleep 1
done
sleep 3

echo "[2/4] Starting detection engine (Phase 2: Kafka + PySpark)..."
python3 backend/kafka_producer.py &
PRODUCER_PID=$!

python3 backend/spark_processor.py &
SPARK_PID=$!

echo "[3/4] Starting API server..."
cd backend
python3 app.py &
API_PID=$!
echo "      API server PID: $API_PID"
cd ..

echo "[4/4] Starting dashboard..."
cd frontend
npm start &
cd ..

echo ""
echo "======================================"
echo "  Dashboard: http://localhost:3000    "
echo "  API:       http://localhost:5000    "
echo "======================================"
echo ""
echo "Press Ctrl+C to stop all services."

trap "kill $PRODUCER_PID $SPARK_PID $API_PID; docker-compose down" EXIT
wait
