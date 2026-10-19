"""Possible port scan: one source contacting many destination ports.

For each source IP we remember the destination ports it touched inside the
time window. When the number of *unique* ports reaches the threshold we raise
a single alert for that source and stay quiet until the window slides far
enough that the unique-port count drops below the threshold again.
"""

from collections import deque

from .base import Detector, prune


class PortScanDetector(Detector):
    section = "port_scan"
    alert_type = "port_scan"
    severity = "high"

    def __init__(self, config):
        super().__init__(config)
        self.window_seconds = self.settings["window_seconds"]
        self.unique_ports_threshold = self.settings["unique_ports_threshold"]
        self._history = {}
        self._alerted = set()

    def inspect(self, record):
        if record.src_ip is None or record.dst_port is None:
            return None

        history = self._history.setdefault(record.src_ip, deque())
        history.append((record.timestamp, record.dst_port))
        prune(history, record.timestamp - self.window_seconds)

        unique_ports = {port for _, port in history}
        if len(unique_ports) < self.unique_ports_threshold:
            self._alerted.discard(record.src_ip)
            return None

        if record.src_ip in self._alerted:
            return None

        self._alerted.add(record.src_ip)
        message = (
            f"Possible port scan: {len(unique_ports)} unique destination ports "
            f"from {record.src_ip} within {self.window_seconds}s"
        )
        return self.build_alert(record, message)
