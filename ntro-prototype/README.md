# NTRO Unidirectional Threat Monitoring — Hybrid 1 Prototype

A passive, real-time cyberthreat detection pipeline built for **NTRO Problem
26145**: detect attacks in one-way-mirrored IP traffic — inside a monitoring
enclave that has no return path to the network it observes — using an
AI/ML pipeline, and present the results on a live, evidence-backed
dashboard.

This is a working prototype, not a simulation of one. Every piece described
below is real code that runs: a real Zeek instance captures real packets, a
real Kafka broker moves real events, three trained ML classifiers score
real traffic, and the dashboard shows what the backend actually reports —
never a hardcoded "online".

---

## 1. What problem this solves

Critical-infrastructure operators mirror their network traffic — via a
hardware data diode or passive tap — into an isolated monitoring enclave.
That enclave can *see* everything crossing the link but has no protocol-level
way to send anything back. The problem statement names six attack classes
that must be detected from that passive vantage point alone:

| # | Threat class | Named detection approach |
|---|---|---|
| a | Volumetric / protocol DDoS | Flow-level rate + source-IP entropy |
| b | Botnet C2 beaconing | Periodicity / inter-arrival analysis |
| c | DGA domains / DNS tunnelling | Entropy / n-gram analysis of DNS names |
| d | Malware in encrypted sessions | JA3/JA4 TLS fingerprints, no decryption |
| e | Reconnaissance / port scanning | Fan-out patterns from one source |
| f | Data exfiltration | Byte-ratio / flow-volume asymmetry |

**This prototype implements and ML-validates three of the six (a, b, e) —
DDoS, C2 beaconing, and reconnaissance.** The other three (c, d, f) are
architecturally designed but not yet built: the dashboard's Architecture
page names exactly what Zeek already logs that a future detector for each
would build on. Nothing in this project claims coverage it doesn't have —
see the Architecture page's Threat Coverage matrix for the honest,
side-by-side breakdown.

---

## 2. Why "Hybrid 1" — the architecture in one paragraph

The design combines two component families that each cover the other's
weak spot. A network security monitor (**Zeek**) is protocol-aware and
turns raw packets into structured records (`conn.log`, `dns.log`,
`ssl.log`) — but has no native ML inference and doesn't scale horizontally.
A streaming pipeline (**Kafka** + a stream processor) scales and handles
stateful windowed computation natively — but can't parse a TLS handshake
or a DNS query from raw bytes on its own. Chaining them — Zeek's structured
output becomes the streaming layer's input — means protocol parsing is
solved exactly once, and feature computation scales independently of
Zeek's own throughput ceiling. The full reasoning (and what the complete,
non-prototype-scale version of this design would look like — Apache Flink,
a time-series database, Suricata, JA3/JA4) is laid out on the dashboard's
own **Architecture** page, which distinguishes "implemented" from
"designed" at every stage, not just for the detectors.

---

## 3. End-to-end data flow

```
Real network traffic (loopback, standing in for a mirrored production link)
        │
        ▼
Zeek  (docker-compose.yml: zeek/zeek:latest, network_mode: host, -i lo)
  writes JSON-lines conn.log to backend/zeek-logs/conn.log
        │
        ▼
kafka_producer.py   — tails conn.log, publishes each raw event to the
                       "zeek-conn" Kafka topic verbatim
        │
        ▼
Apache Kafka   (docker-compose.yml: apache/kafka:latest, single-node KRaft)
        │
        ▼
stream_consumer.py  — the prototype's stand-in for Apache Flink: a single
                       Python process consuming "zeek-conn", normalizing
                       each raw Zeek field into a stable event shape
                       (normalize_event()), then handing it to every
                       detector in turn
        │
        ▼
detectors/{ddos,recon,c2}.py  — each returns a standardized alert dict, or
                                 None, per event
        │
        ▼
alerts.json   — one JSON object per line, appended by stream_consumer.py
        │
        ▼
app.py (Flask)  — reads alerts.json for /api/alerts and /api/stats,
                   streams new lines over SSE at /api/stream
        │
        ▼
React dashboard  — polls the API every 2s (primary, reliable path) and
                    also listens on the SSE stream (fast path, deduped by
                    flow_id) — see §7 for why both exist
```

Every arrow above is a real file, socket, or HTTP call you can inspect
independently — `docker exec zeek_monitor tail -f
/usr/local/zeek/logs/current/conn.log`, `curl localhost:5000/api/alerts`,
etc.

---

## 4. The three detectors

All three follow the same shape: a shared `Detector` base class
(`backend/detectors/base.py`) with one method, `process(event) -> alert |
None`. This interface is deliberate — it's what would let the processing
layer underneath (currently a plain Kafka consumer) be swapped for a real
Apache Flink job later without changing a single line of detection logic.

Each detector was originally a hand-picked fixed threshold. **All three
now load a trained RandomForest classifier and use it as the primary
decision-maker**, falling back to the original rule if the model file is
missing or fails to load — a demo failing outright is worse than briefly
running the less-accurate rule.

### DDoS / SYN Flood (`backend/detectors/ddos.py`)
- **Window:** trailing 10 seconds of TCP connection events (global, not
  per-source).
- **Features fed to the model:** `packet_rate`, `unique_dst_ports`,
  `dst_port_entropy`, `mean_inter_arrival`, `std_inter_arrival`.
- **Validated result:** F1 0.994 vs. 0.921 for the old `packet_rate > 200`
  rule. The rule missed 566 of 3,870 flood windows in cross-validation
  (mostly "low and slow" floods under its fixed rate threshold); the model
  catches nearly all of them by weighing port entropy and connection
  timing more heavily than raw rate.

### Reconnaissance / Port Scan (`backend/detectors/recon.py`)
- **Window:** trailing 60 seconds, tracked per source IP.
- **Features fed to the model:** `unique_ports`, `unique_hosts`,
  `connection_count`, `port_entropy`, `port_range_span`,
  `mean_inter_arrival`, `std_inter_arrival`.
- **Validated result:** F1 1.000 vs. 0.984 for the old
  `unique_ports > 15 OR unique_hosts > 10` rule.

### C2 Beaconing (`backend/detectors/c2.py`)
- **State:** per `(src_ip, dst_ip, dst_port)` key, last 20 connection
  timestamps.
- **Features fed to the model:** `observation_count`, `mean_interval`,
  `std_interval`, `cv` (coefficient of variation).
- **Validated result:** F1 0.966 vs. 0.739 for the old `cv <= 0.35` rule —
  **but only within a specific, deliberately gated input range**
  (`observation_count <= 11` and `mean_interval <= 7.0s`). Outside that
  range the detector falls back to the rule. This gate isn't cosmetic: the
  unrestricted model was found to false-positive 93% of the time on
  traffic outside its training data's coverage (verified empirically, not
  assumed) before the gate was added. Full story in `ML_MODELS.md`.

**All three detectors' evidence lists say which path fired** — every alert's
`evidence[0]` reads either `"ML classifier (RandomForest) flagged..."` with
a real confidence percentage, or `"...fixed-threshold rule"` — so nothing
in the dashboard implies a model decision that didn't actually happen.

The models themselves were trained and cross-validated (GroupKFold by
capture session, pooled confusion matrices, honest reporting of every
false-positive trade-off) in a separate standalone repo,
`recon-ml-poc/`, kept deliberately outside this project until validated.
See **`ML_MODELS.md`** for the full per-model numbers, feature importances,
and every bug found and fixed along the way — including two real,
verified failure modes in the C2 model that a clean cross-validation score
alone didn't catch.

---

## 5. The alert schema

Every detector emits the same shape (`Detector.alert()` in `base.py`):

```json
{
  "timestamp": "2026-09-07T08:21:03.952Z",
  "flow_id": "CfzyiZ11rLp4oPVmFa",
  "src_ip": "203.0.113.7", "src_port": null,
  "dst_ip": "10.0.0.1", "dst_port": 8080,
  "threat_class": "ddos",
  "threat_label": "DDoS / SYN Flood",
  "severity": "CRITICAL",
  "confidence": 0.68,
  "evidence": ["ML classifier (RandomForest) flagged this window as a flood (model confidence: 68%)", "..."],
  "detector": "ddos",
  "window_seconds": 10
}
```

`evidence` is always a flat array of ready-to-read sentences — never a
structured object requiring the frontend to guess at field meanings, and
never a fabricated explanation beyond what the detector actually computed.

---

## 6. Backend API (`backend/app.py`, Flask)

| Route | Method | Purpose |
|---|---|---|
| `/api/alerts?limit=N` | GET | Last N alerts (default 100) |
| `/api/stats` | GET | Counts per threat class over the last 500 alerts |
| `/api/pipeline-status` | GET | Real per-component health — see §7 |
| `/api/throughput` | GET | Live events/sec through the pipeline |
| `/api/replay/<threat>` | POST | Replays a pre-recorded pcap for one threat class — see §8 |
| `/api/clear` | POST | Wipes `alerts.json` (demo reset) |
| `/api/stream` | GET | Server-Sent Events — pushes new alerts as they're appended |

The dev server runs with `threaded=True` — without it, an open SSE
connection blocks every other request on the single-threaded Flask dev
server, which was a real, previously-diagnosed source of "Zeek Offline"
flakiness in the dashboard.

---

## 7. Reliability: real health checks, not hardcoded status

`/api/pipeline-status` never reports a row as "ONLINE" by assumption:

- **Zeek** — is `zeek-logs/conn.log`'s mtime younger than 15 seconds?
- **Kafka** — can the API open a TCP socket to `localhost:9092` right now?
- **Kafka producer / stream detector** — are their heartbeat files
  (`.producer_heartbeat`, `.heartbeat`) fresh?
- **Alert engine** — same process as the stream detector in this
  prototype, so same signal (documented as such, not hidden).
- **Diode** — explicitly labeled `"simulated"` with a note that physical
  isolation is a deployment concern this software cannot verify — the one
  row that is deliberately never shown as a green health check.

The dashboard's live-update path is **polling-first, SSE-second**: every
2 seconds the frontend re-fetches alerts/stats/throughput from the API
regardless of SSE state, and only trusts SSE to push updates *faster* in
between polls (deduped by `flow_id`). This was a deliberate fix for
browser-side `EventSource` flakiness discovered mid-project — polling
never silently stops working, so the dashboard can't get stuck "connected"
while actually stale.

---

## 8. Running the demo

### Prerequisites
Docker + Docker Compose, Python 3, Node.js/npm.

### One-time setup
```bash
cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cd ../frontend && npm install
```

### Start everything
```bash
./start_demo.sh
```
This is not a thin wrapper — it's a real health-check sequence: it refuses
to run as root (a recurring source of file-permission bugs during
development), waits for the Kafka broker to actually accept connections
(not just for the container to report "up"), creates the `zeek-conn`
topic, confirms Zeek is running, then starts the Kafka producer, the
stream consumer, the Flask API, and the dashboard in order — verifying
each one is actually alive before starting the next.

- Dashboard: `http://localhost:5173`
- API: `http://localhost:5000`

### Generating threat traffic
Two ways, both flow through the exact same live pipeline:

1. **Manual traffic scripts** (`traffic/generate_ddos.sh`,
   `traffic/generate_recon.sh`, `traffic/generate_c2.py`) — real traffic
   generators against loopback. `generate_ddos.sh` is deliberately
   rate-limited (`hping3` capped at ~500pps via `nice`/`timeout`) after an
   earlier unbounded `--flood` run hung the machine entirely — see the
   script's own comments.
2. **Replay buttons** (Threat Analysis page, one per threat class) — the
   more reliable option for a live demo. Pressing one has Zeek re-read a
   pre-recorded pcap (`traffic_pcaps/*.pcap`) **offline**, inside the
   already-running container, and injects the resulting log lines into the
   *live* `conn.log` the real pipeline already tails. Deliberately does
   **not** use `tcpreplay` — that needs raw-socket privileges and
   passwordless `sudo`, which can't be relied on to work unattended in
   front of a jury. Full reasoning in `ML_MODELS.md`.

---

## 9. Frontend (`frontend/`, React + Vite)

| Page | Shows |
|---|---|
| **Overview** | Headline stats, threat distribution, live alert feed, compact pipeline diagram |
| **Alerts** | Full alert feed with search + threat/severity filters |
| **Threat Analysis** | Per-threat-class detail, detection signals used, and the replay button |
| **Architecture** | Full system design: the Hybrid-1 rationale, detailed pipeline diagram (implemented vs. full-design per stage), live pipeline status, the six-threat coverage matrix, and the one-way security boundary |

The dev proxy (`vite.config.js`) forwards `/api/*` to the Flask backend
unchanged, so the same relative `fetch()`/`EventSource` calls work whether
the dashboard is opened on `localhost` or from another device on the LAN.

---

## 10. Repository layout

```
backend/
  app.py                 Flask API (§6)
  kafka_producer.py       Zeek conn.log → Kafka
  stream_consumer.py      Kafka → detectors → alerts.json, plus throughput tracking
  detectors/
    base.py               shared Detector interface + alert schema builder
    features.py            shared entropy/timing-stats math (ddos.py + recon.py)
    ddos.py / recon.py / c2.py    the three detectors (§4)
  ml_models/              trained .joblib classifiers, copied in from recon-ml-poc/
zeek/local.zeek            Zeek config (JSON logging, conn/dns/ssl analyzers)
traffic/                   live traffic generators for a manual demo
traffic_pcaps/             pre-recorded pcaps for the Replay buttons + generator script
frontend/                  React dashboard (§9)
docker-compose.yml         Kafka + Zeek containers
start_demo.sh               orchestration script (§8)
ML_MODELS.md               full ML integration writeup: features, validation, bugs found & fixed
```

`recon-ml-poc/` (a sibling directory, not inside this repo) is where the
three models were trained and cross-validated before being copied into
`backend/ml_models/` — kept separate so the exploratory ML work never
risked destabilizing the working prototype while it was still unvalidated.

---

## 11. Honest limitations

- **Three of six threat classes implemented.** DGA/DNS tunnelling, TLS
  malware, and data exfiltration are architecturally designed (see the
  Architecture page) but have no detector built yet.
- **Single-host validation.** All ML training/validation traffic ran
  against loopback (`127.0.0.1`) with one generator per class (`nmap` for
  recon, Python `connect()` bursts for DDoS, a scripted beacon for C2).
  Real multi-host attack traffic and other tools' timing signatures are
  unvalidated.
- **C2's ML model is range-gated**, not universally trusted — see §4 and
  `ML_MODELS.md` for exactly why.
- **No Apache Flink, no Suricata, no real time-series database.** The
  Architecture page names what each of these would be in the full design;
  this prototype uses lighter stand-ins chosen so the interface (the
  `Detector` class, the alert schema) doesn't have to change if they're
  swapped in later.
- **Flask's development server**, not a production WSGI server — fine for
  a demo, not for production traffic volumes.
- **The data diode is simulated in software** (loopback capture), not a
  physical device — `/api/pipeline-status` labels this row `"simulated"`
  rather than pretending otherwise.

Nothing above is hidden — the dashboard's own Architecture page and
System Notes section state the same limitations live, in front of whoever
is using it.
