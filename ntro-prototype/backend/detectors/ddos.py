"""
DDoS / SYN Flood Detector
-------------------------
Trigger condition is now a trained RandomForestClassifier
(recon-ml-poc/train_model_ddos.py, GroupKFold-validated: F1 0.994 vs the
old fixed-threshold rule's F1 0.921 -- see ../../ML_MODELS.md) instead of
the hand-picked `packet_rate > 200` threshold. The rule missed 566/3870
"low and slow" floods in validation (rate below the fixed threshold but
still mechanically regular); the model catches almost all of them by
weighing port entropy and connection timing alongside rate, not rate alone.

Feature vector matches recon-ml-poc/build_dataset_ddos.py's
features_for_window() exactly -- packet_rate, unique_dst_ports,
dst_port_entropy, mean_inter_arrival, std_inter_arrival over the same 10s
window this detector already maintains. Source-IP entropy/unique-IP count
(the original rule's supporting evidence) are kept purely as
human-readable context below -- they were never part of the trained
feature set (in this test rig every capture source is the same loopback
address, so that signal was zero-variance during training; see
ML_MODELS.md).

If the model file is missing or fails to load, falls back to the original
fixed-threshold rule rather than disabling the detector.
"""

from collections import defaultdict, deque
from pathlib import Path

from .base import Detector
from .features import shannon_entropy, interval_stats

WINDOW_SECONDS        = 10
PACKET_RATE_THRESHOLD = 200   # fallback-only: primary trigger if ML model unavailable
UNIQUE_IP_SUPPORT     = 50    # supporting evidence only, never a trigger condition

MODEL_PATH = Path(__file__).parent.parent / "ml_models" / "ddos_model.joblib"
FEATURES = [
    "packet_rate", "unique_dst_ports", "dst_port_entropy",
    "mean_inter_arrival", "std_inter_arrival",
]


class DDoSDetector(Detector):
    name = "ddos"
    threat_class = "ddos"
    threat_label = "DDoS / SYN Flood"

    def __init__(self):
        self._window = deque()   # [(ts, src_ip, dst_port)]
        self.model = self._load_model()

    @staticmethod
    def _load_model():
        try:
            import joblib
            return joblib.load(MODEL_PATH)
        except Exception as e:
            print(f"[ddos] ML model unavailable ({e}) -- falling back to fixed-threshold rule")
            return None

    def process(self, event: dict) -> dict | None:
        if event.get("proto") != "tcp":
            return None

        ts       = event["ts"]
        src_ip   = event["src_ip"]
        dst_ip   = event["dst_ip"]
        dst_port = event["dst_port"]

        self._window.append((ts, src_ip, dst_port))
        cutoff = ts - WINDOW_SECONDS
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()

        recent      = self._window
        recent_ips  = [e[1] for e in recent]
        recent_ports = [e[2] for e in recent]
        packet_rate = len(recent)
        unique_ips  = len(set(recent_ips))
        src_entropy = round(shannon_entropy(recent_ips), 4)
        mean_iat, std_iat = interval_stats(e[0] for e in recent)

        feat = {
            "packet_rate": packet_rate,
            "unique_dst_ports": len(set(recent_ports)),
            "dst_port_entropy": shannon_entropy(recent_ports),
            "mean_inter_arrival": mean_iat,
            "std_inter_arrival": std_iat,
        }

        if self.model is not None:
            vector = [[feat[name] for name in FEATURES]]
            prediction = self.model.predict(vector)[0]
            confidence = float(self.model.predict_proba(vector)[0][1])
            triggered = prediction == 1
            detection_line = f"ML classifier (RandomForest) flagged this window as a flood (model confidence: {confidence:.0%})"
        else:
            triggered = packet_rate > PACKET_RATE_THRESHOLD
            confidence = 0.6 + min((packet_rate / PACKET_RATE_THRESHOLD - 1) * 0.15, 0.35)
            detection_line = "Detection reason: packet-rate threshold exceeded (fixed-threshold rule)"

        if not triggered:
            return None

        evidence = [
            detection_line,
            f"Packet rate: {packet_rate} connections/{WINDOW_SECONDS}s",
            f"Unique destination ports: {feat['unique_dst_ports']}",
            f"Destination port entropy: {feat['dst_port_entropy']:.2f} bits",
            f"Unique source IPs: {unique_ips}",
            f"Source IP entropy: {src_entropy} bits (informational, not a model input)",
            f"Destination port: {dst_port}",
            f"Observation window: {WINDOW_SECONDS}s",
        ]
        if unique_ips > UNIQUE_IP_SUPPORT:
            evidence.append(f"Supporting evidence: {unique_ips} unique sources exceeds {UNIQUE_IP_SUPPORT}")
        if unique_ips > 1:
            evidence.append("src_ip reflects only the most recent packet -- sources appear randomized/spoofed")

        severity = "CRITICAL" if packet_rate > PACKET_RATE_THRESHOLD * 3 else "HIGH"

        return self.alert(
            src_ip=src_ip, src_port=None, dst_ip=dst_ip, dst_port=dst_port,
            flow_id=event.get("uid"), severity=severity, confidence=confidence,
            evidence=evidence, window_seconds=WINDOW_SECONDS,
        )
