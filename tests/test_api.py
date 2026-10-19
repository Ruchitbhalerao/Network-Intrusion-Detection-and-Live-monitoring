import pytest

from nids import db
from nids.api import MAX_ALERT_LIMIT, create_app
from nids.models import Alert, Device


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "api.db"


@pytest.fixture
def client(db_path):
    app = create_app(db_path=db_path)
    return app.test_client()


def make_alert(alert_type="port_scan", timestamp=1.0, src_ip="10.0.0.1"):
    return Alert(
        alert_type=alert_type,
        severity="high",
        message="possible event",
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip="10.0.0.2",
        src_port=40000,
        dst_port=80,
        protocol="TCP",
    )


def test_health_reports_running(client):
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_alerts_empty_database(client):
    response = client.get("/api/alerts")

    assert response.status_code == 200
    assert response.get_json() == {"count": 0, "alerts": []}


def test_alerts_returns_stored_records(client, db_path):
    db.insert_alert(make_alert(alert_type="port_scan", timestamp=1.0), db_path)
    db.insert_alert(make_alert(alert_type="unknown_device", timestamp=2.0), db_path)

    body = client.get("/api/alerts").get_json()

    assert body["count"] == 2
    assert [alert["alert_type"] for alert in body["alerts"]] == [
        "unknown_device",
        "port_scan",
    ]
    first = body["alerts"][0]
    assert first["severity"] == "high"
    assert first["message"] == "possible event"
    assert first["timestamp"] == 2.0
    assert first["src_ip"] == "10.0.0.1"
    assert first["dst_ip"] == "10.0.0.2"
    assert first["src_port"] == 40000
    assert first["dst_port"] == 80
    assert first["protocol"] == "TCP"


def test_alerts_limit_query_parameter(client, db_path):
    for index in range(3):
        db.insert_alert(make_alert(timestamp=float(index)), db_path)

    body = client.get("/api/alerts?limit=2").get_json()

    assert body["count"] == 2


def test_alerts_default_limit_applies(client, db_path):
    for index in range(5):
        db.insert_alert(make_alert(timestamp=float(index)), db_path)

    body = client.get("/api/alerts").get_json()

    assert body["count"] == 5


@pytest.mark.parametrize("value", ["abc", "0", "-5", str(MAX_ALERT_LIMIT + 1), "1.5"])
def test_alerts_invalid_limit_returns_400(client, value):
    response = client.get(f"/api/alerts?limit={value}")

    assert response.status_code == 400
    assert "error" in response.get_json()


def test_devices_empty_database(client):
    response = client.get("/api/devices")

    assert response.status_code == 200
    assert response.get_json() == {"count": 0, "devices": []}


def test_devices_returns_stored_records(client, db_path):
    db.insert_device(Device(ip="10.0.0.5", mac="aa:bb:cc:dd:ee:ff", known=True), db_path)

    body = client.get("/api/devices").get_json()

    assert body["count"] == 1
    device = body["devices"][0]
    assert device["ip"] == "10.0.0.5"
    assert device["mac"] == "aa:bb:cc:dd:ee:ff"
    assert device["known"] is True


def test_stats_empty_database(client):
    response = client.get("/api/stats")

    assert response.status_code == 200
    assert response.get_json() == {
        "total_alerts": 0,
        "alerts_by_severity": {},
        "tracked_devices": 0,
    }


def test_stats_reflects_stored_data(client, db_path):
    db.insert_alert(make_alert(alert_type="a"), db_path)
    db.insert_alert(make_alert(alert_type="b"), db_path)
    db.insert_device(Device(ip="10.0.0.5"), db_path)

    body = client.get("/api/stats").get_json()

    assert body["total_alerts"] == 2
    assert body["alerts_by_severity"] == {"high": 2}
    assert body["tracked_devices"] == 1


def test_unknown_route_returns_json_404(client):
    response = client.get("/api/does-not-exist")

    assert response.status_code == 404
    assert "error" in response.get_json()


def test_unexpected_error_is_generic(client, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("secret database path /Users/private/nids.db")

    monkeypatch.setattr("nids.api.db.get_alerts", boom)

    response = client.get("/api/alerts")

    assert response.status_code == 500
    body = response.get_json()
    assert body == {"error": "internal server error"}
    assert "RuntimeError" not in response.get_data(as_text=True)
    assert "nids.db" not in response.get_data(as_text=True)


def test_create_app_does_not_start_capture(monkeypatch, db_path):
    def boom(*args, **kwargs):
        raise AssertionError("capture must not start")

    monkeypatch.setattr("nids.capture.sniff", boom)

    client = create_app(db_path=db_path).test_client()

    assert client.get("/api/health").status_code == 200
    assert client.get("/api/alerts").status_code == 200
