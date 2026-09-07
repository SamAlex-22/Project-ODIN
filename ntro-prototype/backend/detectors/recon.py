"""
Reconnaissance / Port Scan Detector
-----------------------------------
Stateful per-source aggregation: tracks unique destination ports and hosts
each source IP touches within a rolling window, exactly as before. The
trigger condition is now a trained RandomForestClassifier
(recon-ml-poc/train_model_v3.py, GroupKFold-validated: F1 1.000 vs the
old fixed-threshold rule's F1 0.984 -- see ../../ML_MODELS.md) instead of
the hand-picked `unique_ports > 15 OR unique_hosts > 10` threshold.

Feature vector matches recon-ml-poc/build_dataset_v3.py's
features_for_window() exactly -- unique_ports, unique_hosts,
connection_count, port_entropy, port_range_span, mean_inter_arrival,
std_inter_arrival over the same 60s window this detector already
maintains. Getting this vector wrong (wrong order, wrong window) would
silently feed the model inputs it was never trained on.

If the model file is missing or fails to load (e.g. scikit-learn not
installed), falls back to the original fixed-threshold rule rather than
disabling the detector -- a live demo failing is worse than a slightly
less accurate detector.
"""

from collections import defaultdict
from pathlib import Path

from .base import Detector
from .features import shannon_entropy, interval_stats

WINDOW_SECONDS = 60
ALERT_COOLDOWN = 20   # don't re-alert the same source more than once per this many seconds

# Fallback-only thresholds, used solely if the ML model can't be loaded.
PORT_THRESHOLD = 15
HOST_THRESHOLD = 10

MODEL_PATH = Path(__file__).parent.parent / "ml_models" / "recon_model_v3.joblib"
FEATURES = [
    "unique_ports", "unique_hosts", "connection_count",
    "port_entropy", "port_range_span", "mean_inter_arrival", "std_inter_arrival",
]


class ReconDetector(Detector):
    name = "recon"
    threat_class = "recon"
    threat_label = "Reconnaissance"

    def __init__(self):
        self._state = defaultdict(list)   # src_ip -> [(ts, dst_port, dst_ip)]
        self._last_alerted = {}
        self.model = self._load_model()

    @staticmethod
    def _load_model():
        try:
            import joblib
            return joblib.load(MODEL_PATH)
        except Exception as e:
            print(f"[recon] ML model unavailable ({e}) -- falling back to fixed-threshold rule")
            return None

    def _features(self, entries):
        ports = [e[1] for e in entries]
        hosts = [e[2] for e in entries]
        mean_iat, std_iat = interval_stats(e[0] for e in entries)
        return {
            "unique_ports": len(set(ports)),
            "unique_hosts": len(set(hosts)),
            "connection_count": len(entries),
            "port_entropy": shannon_entropy(ports),
            "port_range_span": (max(ports) - min(ports)) if ports else 0,
            "mean_inter_arrival": mean_iat,
            "std_inter_arrival": std_iat,
        }

    def process(self, event: dict) -> dict | None:
        src_ip   = event["src_ip"]
        dst_ip   = event["dst_ip"]
        dst_port = event["dst_port"]
        ts       = event["ts"]

        if not src_ip or not dst_port:
            return None

        self._state[src_ip].append((ts, dst_port, dst_ip))
        cutoff = ts - WINDOW_SECONDS
        self._state[src_ip] = [e for e in self._state[src_ip] if e[0] >= cutoff]

        entries = self._state[src_ip]
        feat = self._features(entries)

        if self.model is not None:
            vector = [[feat[name] for name in FEATURES]]
            prediction = self.model.predict(vector)[0]
            confidence = float(self.model.predict_proba(vector)[0][1])
            triggered = prediction == 1
            detection_line = (
                f"ML classifier (RandomForest) flagged this window as reconnaissance "
                f"(model confidence: {confidence:.0%})"
            )
        else:
            triggered = feat["unique_ports"] > PORT_THRESHOLD or feat["unique_hosts"] > HOST_THRESHOLD
            confidence = 0.6 + min(feat["unique_ports"] / PORT_THRESHOLD * 0.3, 0.35)
            detection_line = "Detection reason: horizontal/vertical scanning behavior (fixed-threshold rule)"

        if not triggered:
            return None

        if ts - self._last_alerted.get(src_ip, 0) < ALERT_COOLDOWN:
            return None
        self._last_alerted[src_ip] = ts

        evidence = [
            detection_line,
            f"Unique destination ports: {feat['unique_ports']}",
            f"Unique destination hosts: {feat['unique_hosts']}",
            f"Connection attempts: {feat['connection_count']}",
            f"Port entropy: {feat['port_entropy']:.2f} bits",
            f"Observation window: {WINDOW_SECONDS}s",
        ]

        severity = "MEDIUM" if feat["unique_ports"] <= PORT_THRESHOLD * 2 else "HIGH"

        return self.alert(
            src_ip=src_ip, src_port=None, dst_ip=dst_ip, dst_port=dst_port,
            flow_id=event.get("uid"), severity=severity, confidence=confidence,
            evidence=evidence, window_seconds=WINDOW_SECONDS,
        )
