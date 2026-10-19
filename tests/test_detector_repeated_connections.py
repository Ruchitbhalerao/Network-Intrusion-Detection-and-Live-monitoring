from nids.detectors.repeated_connections import RepeatedConnectionsDetector
from nids.models import PacketRecord


def make_detector(config, threshold=3, window=10):
    config["repeated_connections"]["attempts_threshold"] = threshold
    config["repeated_connections"]["window_seconds"] = window
    return RepeatedConnectionsDetector(config)


def attempt(timestamp, src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=22, protocol="TCP", src_port=40000):
    return PacketRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
    )


def collect_alerts(detector, records):
    return [alert for alert in (detector.check(item) for item in records) if alert]


def test_no_alert_below_threshold(config):
    detector = make_detector(config, threshold=3)

    assert collect_alerts(detector, [attempt(0.0), attempt(1.0)]) == []


def test_alert_when_threshold_reached(config):
    detector = make_detector(config, threshold=3)
    records = [attempt(0.0, src_port=40000), attempt(1.0, src_port=40001), attempt(2.0, src_port=40002)]

    alerts = collect_alerts(detector, records)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "repeated_connections"
    assert alert.severity == "medium"
    assert alert.src_ip == "10.0.0.1"
    assert alert.dst_ip == "10.0.0.2"
    assert alert.dst_port == 22
    assert alert.timestamp == 2.0


def test_further_attempts_emit_one_alert(config):
    detector = make_detector(config, threshold=3)
    records = [attempt(float(index)) for index in range(8)]

    assert len(collect_alerts(detector, records)) == 1


def test_different_destination_ports_are_separate_connections(config):
    detector = make_detector(config, threshold=3)
    records = [
        attempt(0.0, dst_port=22),
        attempt(1.0, dst_port=22),
        attempt(2.0, dst_port=22),
        attempt(3.0, dst_port=80),
    ]

    alerts = collect_alerts(detector, records)

    assert len(alerts) == 1
    assert alerts[0].dst_port == 22


def test_window_expiration_allows_a_new_alert(config):
    detector = make_detector(config, threshold=3, window=5)
    first = [attempt(0.0), attempt(1.0), attempt(2.0)]
    second = [attempt(20.0), attempt(21.0), attempt(22.0)]

    assert len(collect_alerts(detector, first + second)) == 2


def test_missing_fields_are_ignored(config):
    detector = make_detector(config, threshold=1)

    assert detector.check(attempt(0.0, dst_ip=None)) is None
    assert detector.check(attempt(0.0, dst_port=None)) is None
    assert detector.check(PacketRecord(timestamp=0.0, src_ip=None, dst_port=22)) is None


def test_disabled_detector_returns_none(config):
    config["repeated_connections"]["enabled"] = False
    detector = RepeatedConnectionsDetector(config)
    records = [attempt(float(index)) for index in range(20)]

    assert collect_alerts(detector, records) == []
