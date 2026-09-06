"""
C2 Beaconing Detector
---------------------
Groups connections by (src, dst, dst_port) and looks for statistically
regular inter-arrival timing -- the signature of programmatic beaconing
rather than human-driven traffic. Still uses the real statistical test
(mean interval + coefficient of variation over >=MIN_OBSERVATIONS
connections); only the *bounds* are relaxed so a compressed demo interval
still qualifies. Nothing about the detection principle itself is weakened.

MIN_INTERVAL is lower than a production deployment would use (which might
require e.g. >=30s between beacons to rule out normal keep-alives) purely
so a live demo doesn't have to wait several minutes. This is a demo-timing
compromise, not a detection-logic compromise -- CV thresholding still does
the real work.
"""

import math
from collections import defaultdict

from .base import Detector

MIN_OBSERVATIONS = 5      # need at least this many connections to judge periodicity
CV_THRESHOLD     = 0.35   # coefficient of variation: std/mean < this = regular
MIN_INTERVAL     = 3      # ignore pairs faster than this (too fast to be a deliberate beacon)
MAX_INTERVAL     = 600    # ignore pairs slower than this (10 min, too slow for a live demo)


def _statistics(timestamps):
    if len(timestamps) < 2:
        return None, None, None
    intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    n = len(intervals)
    mean = sum(intervals) / n
    variance = sum((x - mean) ** 2 for x in intervals) / n
    std = math.sqrt(variance)
    cv = std / mean if mean > 0 else float("inf")
    return round(mean, 2), round(std, 2), round(cv, 4)


class C2Detector(Detector):
    name = "c2"
    threat_class = "c2"
    threat_label = "C2 Beaconing"

    def __init__(self):
        self._connections = defaultdict(list)
        self._alerted = set()

    def process(self, event: dict) -> dict | None:
        src_ip   = event["src_ip"]
        dst_ip   = event["dst_ip"]
        dst_port = event["dst_port"]
        ts       = event["ts"]

        if not src_ip or not dst_ip:
            return None

        key = (src_ip, dst_ip, dst_port)
        self._connections[key].append(ts)
        self._connections[key].sort()
        if len(self._connections[key]) > 20:
            self._connections[key] = self._connections[key][-20:]

        observations = self._connections[key]
        if len(observations) < MIN_OBSERVATIONS:
            return None

        mean_interval, std_interval, cv = _statistics(observations)
        if mean_interval is None:
            return None
        if not (MIN_INTERVAL <= mean_interval <= MAX_INTERVAL):
            return None
        if cv > CV_THRESHOLD:
            return None
        if key in self._alerted:
            return None
        self._alerted.add(key)

        evidence = [
            f"Repeated connections: {len(observations)} to {dst_ip}:{dst_port}",
            f"Mean inter-arrival interval: {mean_interval}s",
            f"Standard deviation: {std_interval}s",
            f"Coefficient of variation: {cv} (threshold<{CV_THRESHOLD}, low = regular/programmatic)",
            "Detection reason: stable periodic beaconing interval",
        ]

        confidence = 0.6 + min((CV_THRESHOLD - cv) / CV_THRESHOLD * 0.35, 0.35)
        severity = "HIGH"

        return self.alert(
            src_ip=src_ip, src_port=None, dst_ip=dst_ip, dst_port=dst_port,
            flow_id=event.get("uid"), severity=severity, confidence=confidence,
            evidence=evidence, window_seconds=MAX_INTERVAL,
        )
