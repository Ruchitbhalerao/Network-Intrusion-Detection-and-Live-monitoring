import pytest

from nids import db
from nids.metrics import TrafficMeter
from nids.models import PacketRecord


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "metrics.db"
    db.init_db(path)
    return path


def record(timestamp, protocol="TCP", length=100, src_ip="10.0.0.1"):
    return PacketRecord(
        timestamp=timestamp, protocol=protocol, length=length, src_ip=src_ip
    )


def test_flush_writes_protocol_totals(db_path):
    meter = TrafficMeter(db_path=db_path)
    meter.record(record(100.0, protocol="TCP", length=100))
    meter.record(record(100.4, protocol="TCP", length=200))
    meter.record(record(100.9, protocol="UDP", length=50))
    meter.flush()

    breakdown = db.get_protocol_breakdown(60, now=100, db_path=db_path)
    by_protocol = {item["protocol"]: item for item in breakdown}
    assert by_protocol["TCP"]["packets"] == 2
    assert by_protocol["TCP"]["bytes"] == 300
    assert by_protocol["UDP"]["packets"] == 1
    assert by_protocol["UDP"]["bytes"] == 50


def test_protocol_defaults_to_other_and_uppercases(db_path):
    meter = TrafficMeter(db_path=db_path)
    meter.record(record(5.0, protocol=None, length=10))
    meter.record(record(5.0, protocol="tcp", length=10))
    meter.flush()

    protocols = {item["protocol"] for item in db.get_protocol_breakdown(60, now=5, db_path=db_path)}
    assert protocols == {"OTHER", "TCP"}


def test_a_new_second_flushes_the_previous_one(db_path):
    meter = TrafficMeter(db_path=db_path)
    meter.record(record(100.0, length=100))
    meter.record(record(101.0, length=100))

    series = db.get_traffic_series(60, now=101, db_path=db_path)
    buckets = {item["bucket"] for item in series}
    assert buckets == {100}

    meter.flush()
    buckets = {item["bucket"] for item in db.get_traffic_series(60, now=101, db_path=db_path)}
    assert buckets == {100, 101}


def test_top_talkers_track_source_bytes(db_path):
    meter = TrafficMeter(db_path=db_path)
    meter.record(record(10.0, length=500, src_ip="10.0.0.5"))
    meter.record(record(10.0, length=100, src_ip="10.0.0.6"))
    meter.record(record(10.0, length=100, src_ip="10.0.0.6"))
    meter.flush()

    talkers = db.get_top_talkers(60, limit=5, now=10, db_path=db_path)
    assert [item["src_ip"] for item in talkers] == ["10.0.0.5", "10.0.0.6"]
    assert talkers[0]["bytes"] == 500
    assert talkers[1]["packets"] == 2


def test_records_without_source_ip_are_counted_in_traffic_only(db_path):
    meter = TrafficMeter(db_path=db_path)
    meter.record(record(10.0, protocol="ARP", length=42, src_ip=None))
    meter.flush()

    assert db.get_top_talkers(60, now=10, db_path=db_path) == []
    breakdown = db.get_protocol_breakdown(60, now=10, db_path=db_path)
    assert breakdown == [{"protocol": "ARP", "packets": 1, "bytes": 42}]


def test_retention_prunes_old_buckets(db_path):
    meter = TrafficMeter(db_path=db_path, retention_seconds=5)
    meter.record(record(100.0, length=100))
    meter.record(record(106.0, length=100))
    meter.flush()

    buckets = {item["bucket"] for item in db.get_traffic_series(1000, now=106, db_path=db_path)}
    assert 100 not in buckets
    assert 106 in buckets


def test_disabled_meter_writes_nothing(db_path):
    meter = TrafficMeter(db_path=db_path, enabled=False)
    meter.record(record(100.0, length=100))
    meter.flush()

    assert db.get_traffic_series(60, now=100, db_path=db_path) == []
