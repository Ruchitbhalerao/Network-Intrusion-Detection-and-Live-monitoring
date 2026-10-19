"""Aggregate packet records into traffic metrics for the live portal.

The detection engine sees every :class:`~nids.models.PacketRecord` exactly
once, so this is where traffic is measured. A :class:`TrafficMeter` keeps
running totals in memory, grouped into one-second buckets (per protocol, and
per source address for top-talker ranking), and flushes completed seconds to
SQLite through :mod:`nids.db`. The current second stays in memory until a later
second arrives, which keeps writes to roughly one batch per second instead of
one per packet.

This module performs no detection and imports no Scapy.
"""

from . import db

DEFAULT_RETENTION_SECONDS = 900


class TrafficMeter:
    """Accumulate per-second traffic totals and flush them to the database."""

    def __init__(self, db_path=None, retention_seconds=DEFAULT_RETENTION_SECONDS, enabled=True):
        self.db_path = db_path if db_path is not None else db.DEFAULT_DB_PATH
        self.retention_seconds = retention_seconds
        self.enabled = enabled
        self._protocols = {}
        self._talkers = {}
        self._latest_second = None

    def record(self, record):
        """Count one packet record into the current second's totals."""
        if not self.enabled or record is None:
            return

        bucket = int(record.timestamp)
        length = record.length or 0
        protocol = (record.protocol or "OTHER").upper()

        _add(self._protocols, (bucket, protocol), length)
        if record.src_ip:
            _add(self._talkers, (bucket, record.src_ip), length)

        if self._latest_second is None or bucket > self._latest_second:
            self._latest_second = bucket
            self._flush_before(bucket)

    def flush(self):
        """Write every pending bucket, including the current second."""
        self._write(self._protocols, self._talkers)
        self._protocols = {}
        self._talkers = {}

    def _flush_before(self, bucket):
        protocols = {key: value for key, value in self._protocols.items() if key[0] < bucket}
        talkers = {key: value for key, value in self._talkers.items() if key[0] < bucket}
        if not protocols and not talkers:
            return
        for key in protocols:
            del self._protocols[key]
        for key in talkers:
            del self._talkers[key]
        self._write(protocols, talkers)

    def _write(self, protocols, talkers):
        if not protocols and not talkers:
            return
        protocol_rows = [
            (bucket, protocol, totals[0], totals[1])
            for (bucket, protocol), totals in protocols.items()
        ]
        talker_rows = [
            (bucket, src_ip, totals[0], totals[1])
            for (bucket, src_ip), totals in talkers.items()
        ]
        db.record_traffic(protocol_rows, talker_rows, db_path=self.db_path)
        if self.retention_seconds and self._latest_second is not None:
            cutoff = self._latest_second - self.retention_seconds
            db.prune_traffic(cutoff, db_path=self.db_path)


def _add(totals, key, length):
    slot = totals.get(key)
    if slot is None:
        totals[key] = [1, length]
    else:
        slot[0] += 1
        slot[1] += length
