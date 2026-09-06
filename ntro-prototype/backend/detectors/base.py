"""
Common detector interface.

A detector only needs a normalized event dict in, and an alert dict (or
None) out. Everything else -- state, windowing, thresholds -- is the
detector's own business. This is deliberate: it's what lets the processing
layer underneath (currently a plain Python Kafka consumer) be swapped for
Apache Flink/Spark in production without changing a single line of
detection logic or the alert contract the dashboard consumes.
"""

from datetime import datetime, timezone


class Detector:
    name = "base"
    threat_class = "unknown"
    threat_label = "Unknown"

    def process(self, event: dict) -> dict | None:
        """event is a normalized flow record (see stream_consumer.normalize_event).
        Return a standardized alert dict, or None if nothing fired."""
        raise NotImplementedError

    def alert(self, *, src_ip, src_port, dst_ip, dst_port, flow_id,
              severity, confidence, evidence, window_seconds):
        return {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "flow_id": flow_id,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "threat_class": self.threat_class,
            "threat_label": self.threat_label,
            "severity": severity,
            "confidence": round(min(confidence, 0.99), 2),
            "evidence": evidence,
            "detector": self.name,
            "window_seconds": window_seconds,
        }
