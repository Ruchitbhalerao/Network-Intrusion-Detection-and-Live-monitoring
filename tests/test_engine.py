from nids import db
from nids.engine import DetectionEngine
from nids.models import Alert, PacketRecord
from nids.synthetic import port_scan_packets


class AlwaysAlertDetector:
    """A stand-in detector that always returns the same alert shape."""

    def check(self, record):
        return Alert(
            alert_type="stub",
            severity="low",
            message="stub alert",
            timestamp=record.timestamp,
            src_ip=record.src_ip,
        )


class FieldDetector:
    """A stand-in detector that copies every record field onto the alert."""

    def check(self, record):
        return Alert(
            alert_type="field_check",
            severity="high",
            message="field fidelity",
            timestamp=record.timestamp,
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            src_port=record.src_port,
            dst_port=record.dst_port,
            protocol=record.protocol,
        )


def unknown_source_record(timestamp=1.0):
    return PacketRecord(
        timestamp=timestamp,
        src_ip="192.168.1.50",
        src_mac="cc:cc:cc:cc:cc:cc",
        dst_ip="10.0.0.1",
        src_port=40000,
        dst_port=80,
        protocol="TCP",
    )


def make_aggressive(config):
    config["port_scan"]["unique_ports_threshold"] = 1
    config["traffic_anomaly"]["packet_rate_threshold"] = 1
    config["repeated_connections"]["attempts_threshold"] = 1
    return config


def test_record_is_processed_by_all_detectors(config, tmp_path):
    engine = DetectionEngine(make_aggressive(config), db_path=tmp_path / "nids.db")

    alerts = engine.process_record(unknown_source_record())

    assert {alert.alert_type for alert in alerts} == {
        "port_scan",
        "traffic_anomaly",
        "unknown_device",
        "repeated_connections",
    }


def test_generated_alerts_are_saved_to_database(config, tmp_path):
    path = tmp_path / "nids.db"
    engine = DetectionEngine(make_aggressive(config), db_path=path)

    engine.process_record(unknown_source_record())

    stored = db.get_alerts(db_path=path)
    assert len(stored) == 4
    assert {alert.alert_type for alert in stored} == {
        "port_scan",
        "traffic_anomaly",
        "unknown_device",
        "repeated_connections",
    }


def test_record_without_alerts_returns_empty_list(config, tmp_path):
    config["known_devices"] = [{"ip": "10.0.0.1"}]
    path = tmp_path / "nids.db"
    engine = DetectionEngine(config, db_path=path)
    record = PacketRecord(
        timestamp=1.0,
        src_ip="10.0.0.1",
        src_mac="aa:aa:aa:aa:aa:aa",
        dst_ip="10.0.0.2",
        src_port=40000,
        dst_port=80,
        protocol="TCP",
    )

    assert engine.process_record(record) == []
    assert db.get_alerts(db_path=path) == []


def test_duplicate_alerts_are_not_inserted_repeatedly(config, tmp_path):
    path = tmp_path / "nids.db"
    engine = DetectionEngine(config, db_path=path, detectors=[AlwaysAlertDetector()])

    first = engine.process_record(PacketRecord(timestamp=1.0, src_ip="10.0.0.1"))
    second = engine.process_record(PacketRecord(timestamp=2.0, src_ip="10.0.0.1"))

    assert len(first) == 1
    assert second == []
    assert len(db.get_alerts(db_path=path)) == 1


def test_alert_emitted_again_after_dedup_window(config, tmp_path):
    config["dedup"]["window_seconds"] = 10
    path = tmp_path / "nids.db"
    engine = DetectionEngine(config, db_path=path, detectors=[AlwaysAlertDetector()])

    assert len(engine.process_record(PacketRecord(timestamp=1.0, src_ip="10.0.0.1"))) == 1
    assert engine.process_record(PacketRecord(timestamp=5.0, src_ip="10.0.0.1")) == []
    assert len(engine.process_record(PacketRecord(timestamp=20.0, src_ip="10.0.0.1"))) == 1
    assert len(db.get_alerts(db_path=path)) == 2


def test_disabled_detectors_generate_no_alerts(config, tmp_path):
    for section in (
        "port_scan",
        "traffic_anomaly",
        "arp_anomaly",
        "unknown_device",
        "repeated_connections",
    ):
        config[section]["enabled"] = False
    path = tmp_path / "nids.db"
    engine = DetectionEngine(config, db_path=path)

    emitted = []
    for record in port_scan_packets(port_count=30):
        emitted.extend(engine.process_record(record))

    assert emitted == []
    assert db.get_alerts(db_path=path) == []


def test_engine_works_with_synthetic_records(config, tmp_path):
    path = tmp_path / "nids.db"
    engine = DetectionEngine(config, db_path=path)

    emitted = []
    for record in port_scan_packets(port_count=25):
        emitted.extend(engine.process_record(record))

    assert any(alert.alert_type == "port_scan" for alert in emitted)
    assert len(db.get_alerts(db_path=path)) >= 1


def test_alert_fields_and_timestamp_survive_dedup_and_storage(config, tmp_path):
    path = tmp_path / "nids.db"
    engine = DetectionEngine(config, db_path=path, detectors=[FieldDetector()])
    record = PacketRecord(
        timestamp=123.5,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=40000,
        dst_port=443,
        protocol="TCP",
    )

    emitted = engine.process_record(record)

    assert len(emitted) == 1
    stored = db.get_alerts(db_path=path)
    assert len(stored) == 1
    assert stored[0].alert_type == "field_check"
    assert stored[0].severity == "high"
    assert stored[0].message == "field fidelity"
    assert stored[0].timestamp == 123.5
    assert stored[0].src_ip == "10.0.0.1"
    assert stored[0].dst_ip == "10.0.0.2"
    assert stored[0].src_port == 40000
    assert stored[0].dst_port == 443
    assert stored[0].protocol == "TCP"
