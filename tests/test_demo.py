import demo

from nids import db
from nids.api import create_app


def run_demo(tmp_path):
    path = tmp_path / "demo.db"
    demo.main(db_path=path)
    return path


def test_demo_records_devices(tmp_path):
    path = run_demo(tmp_path)

    devices = {device.ip: device for device in db.get_devices(db_path=path)}

    assert set(devices) == {"10.0.0.1", "192.168.1.50"}
    assert devices["10.0.0.1"].mac == "11:22:33:44:55:66"
    assert devices["192.168.1.50"].known is False


def test_demo_stats_count_devices(tmp_path):
    path = run_demo(tmp_path)

    assert db.get_stats(db_path=path)["tracked_devices"] == 2


def test_demo_devices_available_via_api(tmp_path):
    path = run_demo(tmp_path)
    client = create_app(db_path=path).test_client()

    body = client.get("/api/devices").get_json()

    assert body["count"] == 2
    assert {device["ip"] for device in body["devices"]} == {
        "10.0.0.1",
        "192.168.1.50",
    }


def test_demo_still_generates_all_five_alert_types(tmp_path):
    path = run_demo(tmp_path)

    types = {alert.alert_type for alert in db.get_alerts(db_path=path)}

    assert types == {
        "port_scan",
        "traffic_anomaly",
        "arp_anomaly",
        "unknown_device",
        "repeated_connections",
    }
