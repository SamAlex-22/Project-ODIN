#!/bin/bash
set -e

echo "======================================"
echo "  NTRO AI Threat Detection Prototype  "
echo "======================================"

echo "[1/4] Starting Zeek..."
docker-compose up -d
sleep 3

echo "[2/4] Starting detection engine..."
cd backend
python3 watcher.py &
WATCHER_PID=$!
echo "      Detection engine PID: $WATCHER_PID"

echo "[3/4] Starting API server..."
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

trap "kill $WATCHER_PID $API_PID; docker-compose down" EXIT
wait
