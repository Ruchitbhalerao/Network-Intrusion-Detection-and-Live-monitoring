"""Repeated connections: many attempts to the same destination service.

A "connection" is identified by the source IP, destination IP, protocol and
destination port. Each attempt adds to a sliding-window count for that key;
when the count reaches ``attempts_threshold`` a single alert is raised and
stays quiet until the window slides below the threshold. Records missing the
fields needed to identify a connection are ignored.
"""

from collections import deque

from .base import Detector, prune


class RepeatedConnectionsDetector(Detector):
    section = "repeated_connections"
    alert_type = "repeated_connections"
    severity = "medium"

    def __init__(self, config):
        super().__init__(config)
        self.window_seconds = self.settings["window_seconds"]
        self.attempts_threshold = self.settings["attempts_threshold"]
        self._history = {}
        self._alerted = set()

    def inspect(self, record):
        if record.src_ip is None or record.dst_ip is None or record.dst_port is None:
            return None

        key = (record.src_ip, record.dst_ip, record.protocol, record.dst_port)
        history = self._history.setdefault(key, deque())
        history.append((record.timestamp, None))
        prune(history, record.timestamp - self.window_seconds)

        count = len(history)
        if count < self.attempts_threshold:
            self._alerted.discard(key)
            return None

        if key in self._alerted:
            return None

        self._alerted.add(key)
        message = (
            f"Repeated connection attempts: {count} times from {record.src_ip} to "
            f"{record.dst_ip}:{record.dst_port} within {self.window_seconds}s"
        )
        return self.build_alert(record, message)
