"""Shared interface for the five detection rules.

A detector is a small object that looks at one :class:`~nids.models.PacketRecord`
at a time and returns an :class:`~nids.models.Alert` when it sees something
suspicious, or ``None`` otherwise. Detectors keep their own in-memory history
and never read from or write to the database.

A detector is built from the full configuration dict and reads its own section
using the class attribute ``section``. For example ``PortScanDetector`` reads
``config["port_scan"]``. Each detector also respects its section's ``enabled``
flag.
"""

from ..models import Alert


class Detector:
    """Base class for all detection rules.

    Subclasses set ``section``, ``alert_type`` and ``severity`` and implement
    :meth:`inspect`. They should not override :meth:`check`.
    """

    section = None
    alert_type = "unknown"
    severity = "medium"

    def __init__(self, config):
        self.config = config
        self.settings = config.get(self.section, {}) if self.section else config
        self.enabled = bool(self.settings.get("enabled", True))

    def check(self, record):
        """Return an ``Alert`` for one record, or ``None``.

        Returns ``None`` when the detector is disabled or the record is empty.
        """
        if not self.enabled or record is None:
            return None
        return self.inspect(record)

    def inspect(self, record):
        """Rule-specific logic implemented by each subclass."""
        raise NotImplementedError

    def build_alert(self, record, message, **overrides):
        """Create an ``Alert`` from a record, with optional field overrides."""
        fields = {
            "alert_type": self.alert_type,
            "severity": self.severity,
            "message": message,
            "timestamp": record.timestamp,
            "src_ip": record.src_ip,
            "dst_ip": record.dst_ip,
            "src_port": record.src_port,
            "dst_port": record.dst_port,
            "protocol": record.protocol,
        }
        fields.update(overrides)
        return Alert(**fields)


def prune(events, cutoff):
    """Remove leading ``(timestamp, value)`` entries older than ``cutoff``.

    ``events`` is a ``collections.deque`` filled in roughly chronological
    order, so old entries are always at the front.
    """
    while events and events[0][0] < cutoff:
        events.popleft()
