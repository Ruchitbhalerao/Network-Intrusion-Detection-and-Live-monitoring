"""Thin SQLite layer for storing alerts and devices.

All SQL lives here so the rest of the project never talks to the database
directly. Every public function accepts an optional ``db_path`` (defaulting to
``nids.db`` next to the project root) so tests can point at a temporary file.
Timestamps are stored as floating-point Unix epoch seconds, matching
:mod:`nids.models`.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from time import time

from .models import Alert, Device

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "nids.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    message TEXT NOT NULL DEFAULT '',
    timestamp REAL NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);

CREATE TABLE IF NOT EXISTS devices (
    ip TEXT PRIMARY KEY,
    mac TEXT,
    hostname TEXT,
    label TEXT,
    known INTEGER NOT NULL DEFAULT 0,
    first_seen REAL,
    last_seen REAL
);

CREATE TABLE IF NOT EXISTS traffic (
    bucket INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    packets INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, protocol)
);

CREATE INDEX IF NOT EXISTS idx_traffic_bucket ON traffic (bucket);

CREATE TABLE IF NOT EXISTS talkers (
    bucket INTEGER NOT NULL,
    src_ip TEXT NOT NULL,
    packets INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, src_ip)
);

CREATE INDEX IF NOT EXISTS idx_talkers_bucket ON talkers (bucket);
"""

_UPSERT_DEVICE = """
INSERT INTO devices (ip, mac, hostname, label, known, first_seen, last_seen)
VALUES (:ip, :mac, :hostname, :label, :known, :first_seen, :last_seen)
ON CONFLICT (ip) DO UPDATE SET
    mac = COALESCE(excluded.mac, devices.mac),
    hostname = COALESCE(excluded.hostname, devices.hostname),
    label = COALESCE(excluded.label, devices.label),
    known = excluded.known,
    first_seen = COALESCE(devices.first_seen, excluded.first_seen),
    last_seen = COALESCE(excluded.last_seen, devices.last_seen)
"""

_ALERT_COLUMNS = (
    "alert_type, severity, message, timestamp, "
    "src_ip, dst_ip, src_port, dst_port, protocol"
)

_UPSERT_TRAFFIC = """
INSERT INTO traffic (bucket, protocol, packets, bytes)
VALUES (?, ?, ?, ?)
ON CONFLICT (bucket, protocol) DO UPDATE SET
    packets = traffic.packets + excluded.packets,
    bytes = traffic.bytes + excluded.bytes
"""

_UPSERT_TALKER = """
INSERT INTO talkers (bucket, src_ip, packets, bytes)
VALUES (?, ?, ?, ?)
ON CONFLICT (bucket, src_ip) DO UPDATE SET
    packets = talkers.packets + excluded.packets,
    bytes = talkers.bytes + excluded.bytes
"""


def init_db(db_path=DEFAULT_DB_PATH):
    """Create the database file and required tables if they do not exist."""
    with _connection(db_path) as connection:
        connection.executescript(SCHEMA)


def insert_alert(alert, db_path=DEFAULT_DB_PATH):
    """Insert an :class:`~nids.models.Alert` and return its new row id."""
    with _connection(db_path) as connection:
        cursor = connection.execute(
            f"INSERT INTO alerts ({_ALERT_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert.alert_type,
                alert.severity,
                alert.message,
                alert.timestamp,
                alert.src_ip,
                alert.dst_ip,
                alert.src_port,
                alert.dst_port,
                alert.protocol,
            ),
        )
        return cursor.lastrowid


def insert_device(device, db_path=DEFAULT_DB_PATH):
    """Insert a device, or update it if the IP already exists.

    The original ``first_seen`` is preserved; missing optional values on the
    new record do not overwrite values already stored.
    """
    with _connection(db_path) as connection:
        connection.execute(
            _UPSERT_DEVICE,
            {
                "ip": device.ip,
                "mac": device.mac,
                "hostname": device.hostname,
                "label": device.label,
                "known": int(bool(device.known)),
                "first_seen": device.first_seen,
                "last_seen": device.last_seen,
            },
        )


def get_alerts(limit=100, db_path=DEFAULT_DB_PATH):
    """Return the newest alerts first, up to ``limit``, as ``Alert`` objects."""
    with _connection(db_path) as connection:
        rows = connection.execute(
            f"SELECT {_ALERT_COLUMNS} FROM alerts ORDER BY timestamp DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_row_to_alert(row) for row in rows]


def get_devices(db_path=DEFAULT_DB_PATH):
    """Return all tracked devices, ordered by IP address, as ``Device`` objects."""
    with _connection(db_path) as connection:
        rows = connection.execute(
            "SELECT ip, mac, hostname, label, known, first_seen, last_seen "
            "FROM devices ORDER BY ip"
        ).fetchall()
    return [_row_to_device(row) for row in rows]


def get_stats(db_path=DEFAULT_DB_PATH):
    """Return simple dashboard statistics.

    Keys: ``total_alerts``, ``alerts_by_severity`` (a dict) and
    ``tracked_devices``.
    """
    with _connection(db_path) as connection:
        total_alerts = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        severity_rows = connection.execute(
            "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity"
        ).fetchall()
        tracked_devices = connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0]

    by_severity = {row["severity"]: row["count"] for row in severity_rows}
    return {
        "total_alerts": total_alerts,
        "alerts_by_severity": by_severity,
        "tracked_devices": tracked_devices,
    }


def record_traffic(protocol_rows, talker_rows, db_path=DEFAULT_DB_PATH):
    """Accumulate per-second traffic totals.

    ``protocol_rows`` are ``(bucket, protocol, packets, bytes)`` tuples and
    ``talker_rows`` are ``(bucket, src_ip, packets, bytes)`` tuples. Existing
    buckets are added to rather than replaced, so the same second may be
    flushed more than once.
    """
    protocol_rows = list(protocol_rows)
    talker_rows = list(talker_rows)
    if not protocol_rows and not talker_rows:
        return
    with _connection(db_path) as connection:
        if protocol_rows:
            connection.executemany(_UPSERT_TRAFFIC, protocol_rows)
        if talker_rows:
            connection.executemany(_UPSERT_TALKER, talker_rows)


def prune_traffic(cutoff, db_path=DEFAULT_DB_PATH):
    """Delete traffic and talker buckets at or before ``cutoff`` (epoch second)."""
    with _connection(db_path) as connection:
        connection.execute("DELETE FROM traffic WHERE bucket <= ?", (int(cutoff),))
        connection.execute("DELETE FROM talkers WHERE bucket <= ?", (int(cutoff),))


def get_traffic_series(window_seconds, now=None, db_path=DEFAULT_DB_PATH):
    """Return per-second totals over the last ``window_seconds``.

    Each item is ``{"bucket", "packets", "bytes"}`` ordered oldest to newest.
    Only seconds that actually carried traffic appear.
    """
    start = _window_start(window_seconds, now)
    with _connection(db_path) as connection:
        rows = connection.execute(
            "SELECT bucket, SUM(packets) AS packets, SUM(bytes) AS bytes "
            "FROM traffic WHERE bucket >= ? GROUP BY bucket ORDER BY bucket",
            (start,),
        ).fetchall()
    return [
        {"bucket": row["bucket"], "packets": row["packets"], "bytes": row["bytes"]}
        for row in rows
    ]


def get_protocol_breakdown(window_seconds, now=None, db_path=DEFAULT_DB_PATH):
    """Return totals per protocol over the window, busiest (by bytes) first."""
    start = _window_start(window_seconds, now)
    with _connection(db_path) as connection:
        rows = connection.execute(
            "SELECT protocol, SUM(packets) AS packets, SUM(bytes) AS bytes "
            "FROM traffic WHERE bucket >= ? GROUP BY protocol "
            "ORDER BY bytes DESC, packets DESC, protocol",
            (start,),
        ).fetchall()
    return [
        {"protocol": row["protocol"], "packets": row["packets"], "bytes": row["bytes"]}
        for row in rows
    ]


def get_top_talkers(window_seconds, limit=5, now=None, db_path=DEFAULT_DB_PATH):
    """Return the busiest source addresses over the window, by bytes then packets."""
    start = _window_start(window_seconds, now)
    with _connection(db_path) as connection:
        rows = connection.execute(
            "SELECT src_ip, SUM(packets) AS packets, SUM(bytes) AS bytes "
            "FROM talkers WHERE bucket >= ? GROUP BY src_ip "
            "ORDER BY bytes DESC, packets DESC, src_ip LIMIT ?",
            (start, limit),
        ).fetchall()
    return [
        {"src_ip": row["src_ip"], "packets": row["packets"], "bytes": row["bytes"]}
        for row in rows
    ]


def get_traffic_summary(window_seconds, now=None, db_path=DEFAULT_DB_PATH):
    """Return aggregate traffic figures for the window.

    Keys: ``window_seconds``, ``total_packets``, ``total_bytes``,
    ``active_seconds``, ``protocols``, ``peak_packets_per_second``,
    ``peak_bytes_per_second``, ``avg_packets_per_second`` and
    ``avg_bytes_per_second`` (averaged over the whole window, idle seconds
    included).
    """
    start = _window_start(window_seconds, now)
    with _connection(db_path) as connection:
        totals = connection.execute(
            "SELECT COALESCE(SUM(packets), 0) AS packets, "
            "COALESCE(SUM(bytes), 0) AS bytes, "
            "COUNT(DISTINCT bucket) AS seconds, "
            "COUNT(DISTINCT protocol) AS protocols "
            "FROM traffic WHERE bucket >= ?",
            (start,),
        ).fetchone()
        peaks = connection.execute(
            "SELECT COALESCE(MAX(packets), 0) AS peak_packets, "
            "COALESCE(MAX(bytes), 0) AS peak_bytes FROM ("
            "SELECT SUM(packets) AS packets, SUM(bytes) AS bytes "
            "FROM traffic WHERE bucket >= ? GROUP BY bucket)",
            (start,),
        ).fetchone()

    total_packets = totals["packets"]
    total_bytes = totals["bytes"]
    return {
        "window_seconds": window_seconds,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "active_seconds": totals["seconds"],
        "protocols": totals["protocols"],
        "peak_packets_per_second": peaks["peak_packets"],
        "peak_bytes_per_second": peaks["peak_bytes"],
        "avg_packets_per_second": total_packets / window_seconds,
        "avg_bytes_per_second": total_bytes / window_seconds,
    }


def _window_start(window_seconds, now):
    reference = int(now if now is not None else time())
    return reference - int(window_seconds)


@contextmanager
def _connection(db_path):
    path = Path(db_path)
    if not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _row_to_alert(row):
    return Alert(
        alert_type=row["alert_type"],
        severity=row["severity"],
        message=row["message"],
        timestamp=row["timestamp"],
        src_ip=row["src_ip"],
        dst_ip=row["dst_ip"],
        src_port=row["src_port"],
        dst_port=row["dst_port"],
        protocol=row["protocol"],
    )


def _row_to_device(row):
    return Device(
        ip=row["ip"],
        mac=row["mac"],
        hostname=row["hostname"],
        label=row["label"],
        known=bool(row["known"]),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
    )
