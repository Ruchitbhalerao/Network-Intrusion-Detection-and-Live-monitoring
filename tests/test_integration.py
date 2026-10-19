import run

from nids import db
from nids.api import create_app
from nids.config import ConfigError
from nids.models import Alert, Device


def make_alert(alert_type="port_scan", severity="high", timestamp=1.0):
    return Alert(
        alert_type=alert_type,
        severity=severity,
        message="possible event",
        timestamp=timestamp,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=40000,
        dst_port=80,
        protocol="TCP",
    )


def test_empty_database_endpoints(tmp_path):
    client = create_app(db_path=tmp_path / "nids.db").test_client()

    assert client.get("/api/health").get_json() == {"status": "ok"}
    assert client.get("/api/alerts").get_json() == {"count": 0, "alerts": []}
    assert client.get("/api/devices").get_json() == {"count": 0, "devices": []}
    assert client.get("/api/stats").get_json() == {
        "total_alerts": 0,
        "alerts_by_severity": {},
        "tracked_devices": 0,
    }


def test_alerts_written_to_temp_db_appear_via_api(tmp_path):
    path = tmp_path / "nids.db"
    app = create_app(db_path=path)
    db.insert_alert(make_alert(alert_type="port_scan", timestamp=1.0), path)
    db.insert_alert(make_alert(alert_type="unknown_device", timestamp=2.0), path)

    body = app.test_client().get("/api/alerts").get_json()

    assert body["count"] == 2
    assert body["alerts"][0]["alert_type"] == "unknown_device"
    assert set(body["alerts"][0]) == {
        "alert_type",
        "severity",
        "message",
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
    }


def test_devices_written_to_temp_db_appear_via_api(tmp_path):
    path = tmp_path / "nids.db"
    app = create_app(db_path=path)
    db.insert_device(Device(ip="10.0.0.5", mac="aa:bb:cc:dd:ee:ff", known=True), path)

    body = app.test_client().get("/api/devices").get_json()

    assert body["count"] == 1
    assert body["devices"][0]["ip"] == "10.0.0.5"
    assert set(body["devices"][0]) == {
        "ip",
        "mac",
        "hostname",
        "label",
        "known",
        "first_seen",
        "last_seen",
    }


def test_stats_reflect_temp_db(tmp_path):
    path = tmp_path / "nids.db"
    app = create_app(db_path=path)
    db.insert_alert(make_alert(severity="high", timestamp=1.0), path)
    db.insert_alert(make_alert(severity="low", timestamp=2.0), path)
    db.insert_device(Device(ip="10.0.0.9"), path)

    stats = app.test_client().get("/api/stats").get_json()

    assert stats["total_alerts"] == 2
    assert stats["alerts_by_severity"] == {"high": 1, "low": 1}
    assert stats["tracked_devices"] == 1


def test_dashboard_and_api_served_by_same_app(tmp_path):
    client = create_app(db_path=tmp_path / "nids.db").test_client()

    page = client.get("/")
    assert page.status_code == 200
    assert "text/html" in page.content_type
    assert client.get("/api/health").status_code == 200
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/style.css").status_code == 200


def test_app_uses_supplied_database_path(tmp_path):
    path = tmp_path / "custom.db"

    app = create_app(db_path=path)

    assert app.config["DB_PATH"] == path


def test_temp_app_does_not_touch_real_database(tmp_path):
    real = db.DEFAULT_DB_PATH
    existed_before = real.exists()

    client = create_app(db_path=tmp_path / "isolated.db").test_client()
    client.get("/api/alerts")

    assert real.exists() == existed_before


def test_run_binds_to_localhost(monkeypatch):
    calls = {}

    class FakeApp:
        def run(self, host=None, port=None, debug=None):
            calls["host"] = host
            calls["port"] = port
            calls["debug"] = debug

    monkeypatch.setattr(run, "build_app", lambda **kwargs: FakeApp())

    assert run.main([]) == 0
    assert calls["host"] == "127.0.0.1"
    assert calls["host"] == run.HOST
    assert calls["port"] == run.PORT


def test_run_reports_config_error(monkeypatch, capsys):
    def boom():
        raise ConfigError("bad config")

    monkeypatch.setattr(run, "load_config", boom)

    assert run.main([]) == 1
    assert "Configuration error" in capsys.readouterr().out


def test_run_build_app_accepts_database_path(tmp_path):
    app = run.build_app(db_path=tmp_path / "run.db")

    assert app.test_client().get("/api/health").get_json() == {"status": "ok"}
