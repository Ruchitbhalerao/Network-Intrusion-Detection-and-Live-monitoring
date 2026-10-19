"""Traffic anomaly: a source sending too many packets in a short window.

The threshold (``packet_rate_threshold``) is the number of packets from a
single source allowed inside ``window_seconds``. Timestamps come from the
records themselves, so tests are deterministic. One alert is raised per
source until the window slides and the count falls below the threshold.
"""

from collections import deque

from .base import Detector, prune


class RateAnomalyDetector(Detector):
    section = "traffic_anomaly"
    alert_type = "traffic_anomaly"
    severity = "medium"

    def __init__(self, config):
        super().__init__(config)
        self.window_seconds = self.settings["window_seconds"]
        self.packet_rate_threshold = self.settings["packet_rate_threshold"]
        self._history = {}
        self._alerted = set()

    def inspect(self, record):
        if record.src_ip is None:
            return None

        history = self._history.setdefault(record.src_ip, deque())
        history.append((record.timestamp, None))
        prune(history, record.timestamp - self.window_seconds)

        count = len(history)
        if count < self.packet_rate_threshold:
            self._alerted.discard(record.src_ip)
            return None

        if record.src_ip in self._alerted:
            return None

        self._alerted.add(record.src_ip)
        message = (
            f"Traffic anomaly: {count} packets from {record.src_ip} within "
            f"{self.window_seconds}s (threshold {self.packet_rate_threshold})"
        )
        return self.build_alert(record, message)
