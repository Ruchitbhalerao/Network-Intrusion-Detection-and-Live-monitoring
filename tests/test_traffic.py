from time import time

import pytest

from nids import db
from nids.api import create_app
from nids.config import ConfigError, load_config
from nids.engine import DetectionEngine
from nids.models import PacketRecord


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "traffic.db"
    db.init_db(path)
    return path


def test_record_traffic_accumulates_across_flushes(db_path):
    db.record_traffic([(100, "TCP", 2, 200)], [], db_path=db_path)
    db.record_traffic([(100, "TCP", 3, 300)], [], db_path=db_path)

    breakdown = db.get_protocol_breakdown(60, now=100, db_path=db_path)
    assert breakdown == [{"protocol": "TCP", "packets": 5, "bytes": 500}]


def test_series_excludes_buckets_outside_window(db_path):
    db.record_traffic([(100, "TCP", 1, 100), (200, "TCP", 1, 100)], [], db_path=db_path)

    series = db.get_traffic_series(60, now=200, db_path=db_path)
    assert [item["bucket"] for item in series] == [200]


def test_summary_reports_totals_and_peaks(db_path):
    db.record_traffic(
        [
            (100, "TCP", 2, 200),
            (100, "UDP", 1, 50),
            (101, "TCP", 5, 1000),
        ],
        [],
        db_path=db_path,
    )

    summary = db.get_traffic_summary(60, now=101, db_path=db_path)
    assert summary["total_packets"] == 8
    assert summary["total_bytes"] == 1250
    assert summary["active_seconds"] == 2
    assert summary["protocols"] == 2
    assert summary["peak_packets_per_second"] == 5
    assert summary["peak_bytes_per_second"] == 1000
    assert summary["avg_bytes_per_second"] == pytest.approx(1250 / 60)


def test_empty_summary_is_zeroed(db_path):
    summary = db.get_traffic_summary(60, now=100, db_path=db_path)
    assert summary["total_packets"] == 0
    assert summary["total_bytes"] == 0
    assert summary["peak_bytes_per_second"] == 0
    assert summary["avg_packets_per_second"] == 0


def test_prune_traffic_removes_old_rows(db_path):
    db.record_traffic([(100, "TCP", 1, 100), (200, "TCP", 1, 100)], [], db_path=db_path)
    db.prune_traffic(150, db_path=db_path)

    buckets = {item["bucket"] for item in db.get_traffic_series(1000, now=200, db_path=db_path)}
    assert buckets == {200}


def test_engine_feeds_the_traffic_meter(config, db_path):
    engine = DetectionEngine(config, db_path=db_path)
    engine.process_record(PacketRecord(timestamp=100.0, protocol="TCP", length=120, src_ip="10.0.0.1"))
    engine.process_record(PacketRecord(timestamp=101.0, protocol="TCP", length=120, src_ip="10.0.0.1"))

    series = db.get_traffic_series(60, now=101, db_path=db_path)
    assert [item["bucket"] for item in series] == [100]


# ---- API ----


@pytest.fixture
def client(db_path):
    return create_app(config=load_config(), db_path=db_path).test_client()


def test_traffic_endpoint_empty_database(client):
    body = client.get("/api/traffic").get_json()

    assert body["window_seconds"] == 60
    assert body["series"] == []
    assert body["protocols"] == []
    assert body["top_talkers"] == []
    assert body["summary"]["total_packets"] == 0


def test_traffic_endpoint_returns_recent_data(client, db_path):
    now = int(time())
    db.record_traffic(
        [(now - 1, "TCP", 4, 400), (now - 1, "UDP", 1, 60)],
        [(now - 1, "10.0.0.7", 5, 460)],
        db_path=db_path,
    )

    body = client.get("/api/traffic?window=30").get_json()

    assert body["window_seconds"] == 30
    assert body["summary"]["total_packets"] == 5
    assert body["summary"]["total_bytes"] == 460
    protocols = {item["protocol"] for item in body["protocols"]}
    assert protocols == {"TCP", "UDP"}
    assert body["top_talkers"][0]["src_ip"] == "10.0.0.7"


@pytest.mark.parametrize("value", ["abc", "0", "-5", "100000", "1.5"])
def test_traffic_endpoint_invalid_window_returns_400(client, value):
    response = client.get(f"/api/traffic?window={value}")

    assert response.status_code == 400
    assert "error" in response.get_json()


def test_traffic_endpoint_respects_top_talkers_limit(db_path):
    config = load_config()
    config["traffic_monitor"]["top_talkers"] = 2
    client = create_app(config=config, db_path=db_path).test_client()
    now = int(time())
    db.record_traffic(
        [],
        [
            (now - 1, "10.0.0.1", 1, 300),
            (now - 1, "10.0.0.2", 1, 200),
            (now - 1, "10.0.0.3", 1, 100),
        ],
        db_path=db_path,
    )

    body = client.get("/api/traffic?window=30").get_json()
    assert len(body["top_talkers"]) == 2


# ---- config ----


def test_config_has_traffic_monitor_defaults():
    config = load_config()
    monitor = config["traffic_monitor"]
    assert monitor["enabled"] is True
    assert monitor["default_window_seconds"] <= monitor["max_window_seconds"]


def test_config_rejects_window_larger_than_max(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        '{"traffic_monitor": {"default_window_seconds": 1000, "max_window_seconds": 60}}',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(path)
