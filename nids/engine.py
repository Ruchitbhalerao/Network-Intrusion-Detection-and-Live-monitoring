"""The detection engine ties the detectors and deduplication together.

It builds the five detectors from the configuration, feeds each
:class:`~nids.models.PacketRecord` to them, drops duplicate alerts with the
:class:`~nids.dedup.Deduplicator`, and stores the survivors with
:func:`nids.db.insert_alert`. Detector history stays in memory; only alerts
reach the database. This module never imports Scapy.
"""

from . import db
from .dedup import Deduplicator
from .detectors.arp_anomaly import ArpAnomalyDetector
from .detectors.port_scan import PortScanDetector
from .detectors.rate_anomaly import RateAnomalyDetector
from .detectors.repeated_connections import RepeatedConnectionsDetector
from .detectors.unknown_device import UnknownDeviceDetector
from .metrics import TrafficMeter


class DetectionEngine:
    def __init__(self, config, db_path=db.DEFAULT_DB_PATH, detectors=None, meter=None):
        self.config = config
        self.db_path = db_path
        self.detectors = detectors if detectors is not None else _build_detectors(config)
        self.deduplicator = Deduplicator(config)
        self.meter = meter if meter is not None else _build_meter(config, db_path)
        db.init_db(db_path)

    def process_record(self, record):
        """Run one record through every detector.

        Also feeds the record to the traffic meter so the live portal can show
        bandwidth and protocol usage. Returns the list of alerts that were
        emitted (not suppressed) for this record. Those alerts are also
        persisted. Returns ``[]`` when nothing suspicious is found.
        """
        if self.meter is not None:
            self.meter.record(record)
        emitted = []
        for detector in self.detectors:
            alert = detector.check(record)
            if alert is None:
                continue
            if self.deduplicator.should_emit(alert):
                db.insert_alert(alert, self.db_path)
                emitted.append(alert)
        return emitted


def _build_detectors(config):
    return [
        PortScanDetector(config),
        RateAnomalyDetector(config),
        ArpAnomalyDetector(config),
        UnknownDeviceDetector(config),
        RepeatedConnectionsDetector(config),
    ]


def _build_meter(config, db_path):
    settings = config.get("traffic_monitor", {})
    if not settings.get("enabled", True):
        return None
    return TrafficMeter(
        db_path=db_path,
        retention_seconds=settings.get("retention_seconds", 900),
        enabled=True,
    )
