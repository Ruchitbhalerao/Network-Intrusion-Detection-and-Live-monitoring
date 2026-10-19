"""Background synthetic traffic feed for a live dashboard demonstration.

This drives the real detection engine with synthetic packet records on a timer
so the read-only dashboard shows alerts and devices appearing over time,
without live capture and without administrator privileges. It imports no Scapy
and generates no real network traffic; every record comes from
:mod:`nids.synthetic`.

It never starts on import. ``run.py`` starts it only when ``--live-demo`` is
passed, and stops it cleanly on shutdown.
"""

from threading import Event, Thread
from time import time

from . import db
from .engine import DetectionEngine
from .models import Device
from .synthetic import (
    arp_mapping_change,
    background_traffic,
    packet_burst,
    port_scan_packets,
    repeated_connections,
    unknown_device_traffic,
)

DEFAULT_INTERVAL_SECONDS = 4.0


def _scenarios(cycle):
    suffix = cycle % 250 + 2
    scanner = f"10.0.{cycle % 250}.{suffix}"
    unknown = f"192.168.7.{suffix}"
    return (
        background_traffic(start_time=time()),
        port_scan_packets(src_ip=scanner, start_time=time()),
        background_traffic(start_time=time()),
        packet_burst(src_ip=scanner, count=250, start_time=time()),
        arp_mapping_change(sender_ip=f"10.0.0.{suffix}", start_time=time()),
        unknown_device_traffic(src_ip=unknown, start_time=time()),
        repeated_connections(src_ip=scanner, start_time=time()),
    )


def _known_inventory(config):
    return {
        entry["ip"]: entry
        for entry in config.get("known_devices", [])
        if entry.get("ip")
    }


def _observed_device(record, inventory):
    ip = record.arp_sender_ip or record.src_ip
    if ip is None:
        return None
    entry = inventory.get(ip)
    return Device(
        ip=ip,
        mac=record.arp_sender_mac or record.src_mac,
        label=entry.get("label") if entry else None,
        known=entry is not None,
        first_seen=record.timestamp,
        last_seen=record.timestamp,
    )


class LiveFeed:
    """Feed synthetic records through the engine on a background thread."""

    def __init__(self, config, db_path=None, interval=DEFAULT_INTERVAL_SECONDS):
        self.config = config
        self.db_path = db_path if db_path is not None else db.DEFAULT_DB_PATH
        self.interval = interval
        self._inventory = _known_inventory(config)
        self._stop_event = Event()
        self._thread = None

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self.is_running():
            return
        self._stop_event.clear()
        self._thread = Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self, timeout=2.0):
        if not self.is_running():
            return
        self._stop_event.set()
        self._thread.join(timeout=timeout)

    def _run(self):
        engine = DetectionEngine(self.config, db_path=self.db_path)
        cycle = 0
        while not self._stop_event.is_set():
            for records in _scenarios(cycle):
                if self._stop_event.is_set():
                    return
                for record in records:
                    device = _observed_device(record, self._inventory)
                    if device is not None:
                        db.insert_device(device, self.db_path)
                    engine.process_record(record)
                self._stop_event.wait(self.interval)
            cycle += 1
