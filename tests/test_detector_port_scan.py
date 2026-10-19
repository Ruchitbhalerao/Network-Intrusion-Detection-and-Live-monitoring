from nids.detectors.port_scan import PortScanDetector
from nids.models import PacketRecord
from nids.synthetic import port_scan_packets


def make_detector(config, threshold=3, window=10):
    config["port_scan"]["unique_ports_threshold"] = threshold
    config["port_scan"]["window_seconds"] = window
    return PortScanDetector(config)


def collect_alerts(detector, records):
    return [alert for alert in (detector.check(record) for record in records) if alert]


def test_no_alert_below_threshold(config):
    detector = make_detector(config, threshold=3)
    records = port_scan_packets(port_count=2, start_port=1, start_time=0.0, interval=1.0)

    assert collect_alerts(detector, records) == []


def test_alert_when_threshold_reached(config):
    detector = make_detector(config, threshold=3)
    records = port_scan_packets(port_count=3, start_port=1, start_time=0.0, interval=1.0)

    alerts = collect_alerts(detector, records)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "port_scan"
    assert alert.severity == "high"
    assert alert.src_ip == "10.0.0.1"
    assert alert.protocol == "TCP"
    assert alert.timestamp == 2.0


def test_repeated_packets_after_threshold_emit_one_alert(config):
    detector = make_detector(config, threshold=3)
    records = port_scan_packets(port_count=6, start_port=1, start_time=0.0, interval=1.0)

    alerts = collect_alerts(detector, records)

    assert len(alerts) == 1


def test_window_expiration_allows_a_new_alert(config):
    detector = make_detector(config, threshold=3, window=5)
    first = port_scan_packets(port_count=3, start_port=1, start_time=0.0, interval=1.0)
    second = port_scan_packets(port_count=3, start_port=10, start_time=20.0, interval=1.0)

    alerts = collect_alerts(detector, first + second)

    assert len(alerts) == 2


def test_duplicate_ports_do_not_count_as_unique(config):
    detector = make_detector(config, threshold=3)
    records = [
        PacketRecord(timestamp=0.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80, protocol="TCP"),
        PacketRecord(timestamp=1.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80, protocol="TCP"),
        PacketRecord(timestamp=2.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80, protocol="TCP"),
    ]

    assert collect_alerts(detector, records) == []


def test_missing_fields_are_ignored(config):
    detector = make_detector(config, threshold=1)

    assert detector.check(PacketRecord(timestamp=0.0, src_ip="10.0.0.1", dst_port=None)) is None
    assert detector.check(PacketRecord(timestamp=0.0, src_ip=None, dst_port=80)) is None


def test_disabled_detector_returns_none(config):
    config["port_scan"]["enabled"] = False
    detector = PortScanDetector(config)
    records = port_scan_packets(port_count=50, start_port=1, interval=0.1)

    assert collect_alerts(detector, records) == []
