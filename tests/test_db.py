import sqlite3

import pytest

from nids.db import (
    get_alerts,
    get_devices,
    get_stats,
    init_db,
    insert_alert,
    insert_device,
)
from nids.models import Alert, Device


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "test.db"
    init_db(path)
    return path


def test_init_db_creates_tables(tmp_path):
    path = tmp_path / "nids.db"
    init_db(path)

    connection = sqlite3.connect(path)
    names = {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    connection.close()

    assert {"alerts", "devices"} <= names
    assert path.exists()


def test_init_db_is_idempotent(tmp_path):
    path = tmp_path / "nids.db"
    init_db(path)
    init_db(path)

    assert get_alerts(db_path=path) == []


def test_insert_and_retrieve_alert(db_path):
    alert = Alert(
        alert_type="port_scan",
        severity="high",
        message="Possible port scan",
        timestamp=100.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=40000,
        dst_port=80,
        protocol="TCP",
    )

    row_id = insert_alert(alert, db_path)
    assert isinstance(row_id, int)

    alerts = get_alerts(db_path=db_path)
    assert len(alerts) == 1
    stored = alerts[0]
    assert isinstance(stored, Alert)
    assert stored.alert_type == "port_scan"
    assert stored.severity == "high"
    assert stored.message == "Possible port scan"
    assert stored.timestamp == 100.0
    assert stored.src_ip == "10.0.0.1"
    assert stored.dst_ip == "10.0.0.2"
    assert stored.src_port == 40000
    assert stored.dst_port == 80
    assert stored.protocol == "TCP"


def test_alert_optional_fields_round_trip(db_path):
    insert_alert(Alert(alert_type="traffic_anomaly", timestamp=1.0), db_path)

    stored = get_alerts(db_path=db_path)[0]
    assert stored.severity == "medium"
    assert stored.message == ""
    assert stored.src_ip is None
    assert stored.dst_port is None


def test_alerts_are_returned_newest_first(db_path):
    for index in range(5):
        insert_alert(Alert(alert_type="test", timestamp=float(index)), db_path)

    alerts = get_alerts(db_path=db_path)
    assert [alert.timestamp for alert in alerts] == [4.0, 3.0, 2.0, 1.0, 0.0]


def test_get_alerts_respects_limit(db_path):
    for index in range(5):
        insert_alert(Alert(alert_type="test", timestamp=float(index)), db_path)

    alerts = get_alerts(limit=2, db_path=db_path)
    assert [alert.timestamp for alert in alerts] == [4.0, 3.0]


def test_alerts_with_equal_timestamps_tie_break_by_id(db_path):
    insert_alert(Alert(alert_type="first", timestamp=1.0), db_path)
    insert_alert(Alert(alert_type="second", timestamp=1.0), db_path)

    alerts = get_alerts(db_path=db_path)
    assert [alert.alert_type for alert in alerts] == ["second", "first"]


def test_insert_and_update_device_preserves_first_seen(db_path):
    insert_device(
        Device(
            ip="10.0.0.1",
            mac="aa:aa:aa:aa:aa:aa",
            label="old",
            known=True,
            first_seen=100.0,
            last_seen=100.0,
        ),
        db_path,
    )
    insert_device(
        Device(
            ip="10.0.0.1",
            mac="bb:bb:bb:bb:bb:bb",
            label="new",
            known=True,
            first_seen=500.0,
            last_seen=500.0,
        ),
        db_path,
    )

    devices = get_devices(db_path)
    assert len(devices) == 1
    device = devices[0]
    assert device.ip == "10.0.0.1"
    assert device.mac == "bb:bb:bb:bb:bb:bb"
    assert device.label == "new"
    assert device.first_seen == 100.0
    assert device.last_seen == 500.0
    assert device.known is True


def test_update_device_keeps_existing_optional_values(db_path):
    insert_device(Device(ip="10.0.0.2", mac="cc:cc:cc:cc:cc:cc", last_seen=1.0), db_path)
    insert_device(Device(ip="10.0.0.2", last_seen=2.0), db_path)

    device = get_devices(db_path)[0]
    assert device.mac == "cc:cc:cc:cc:cc:cc"
    assert device.last_seen == 2.0


def test_device_known_flag_round_trips(db_path):
    insert_device(Device(ip="10.0.0.3", known=True), db_path)
    insert_device(Device(ip="10.0.0.4", known=False), db_path)

    devices = {device.ip: device for device in get_devices(db_path)}
    assert devices["10.0.0.3"].known is True
    assert devices["10.0.0.4"].known is False


def test_empty_database_behavior(db_path):
    assert get_alerts(db_path=db_path) == []
    assert get_devices(db_path) == []
    assert get_stats(db_path) == {
        "total_alerts": 0,
        "alerts_by_severity": {},
        "tracked_devices": 0,
    }


def test_statistics(db_path):
    insert_alert(Alert(alert_type="a", severity="high", timestamp=1.0), db_path)
    insert_alert(Alert(alert_type="b", severity="high", timestamp=2.0), db_path)
    insert_alert(Alert(alert_type="c", severity="low", timestamp=3.0), db_path)
    insert_device(Device(ip="10.0.0.1"), db_path)
    insert_device(Device(ip="10.0.0.2"), db_path)

    stats = get_stats(db_path)
    assert stats["total_alerts"] == 3
    assert stats["alerts_by_severity"] == {"high": 2, "low": 1}
    assert stats["tracked_devices"] == 2


def test_temporary_databases_are_independent(tmp_path):
    path_a = tmp_path / "a.db"
    path_b = tmp_path / "b.db"
    init_db(path_a)
    init_db(path_b)

    insert_alert(Alert(alert_type="only-a", timestamp=1.0), path_a)

    assert len(get_alerts(db_path=path_a)) == 1
    assert get_alerts(db_path=path_b) == []
