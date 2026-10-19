from nids.detectors.rate_anomaly import RateAnomalyDetector
from nids.models import PacketRecord


def make_detector(config, threshold=3, window=5):
    config["traffic_anomaly"]["packet_rate_threshold"] = threshold
    config["traffic_anomaly"]["window_seconds"] = window
    return RateAnomalyDetector(config)


def record(timestamp, src_ip="10.0.0.1"):
    return PacketRecord(timestamp=timestamp, src_ip=src_ip, dst_ip="10.0.0.2", protocol="TCP")


def collect_alerts(detector, records):
    return [alert for alert in (detector.check(item) for item in records) if alert]


def test_no_alert_below_threshold(config):
    detector = make_detector(config, threshold=3)
    records = [record(0.0), record(1.0)]

    assert collect_alerts(detector, records) == []


def test_alert_when_threshold_reached(config):
    detector = make_detector(config, threshold=3)
    records = [record(0.0), record(1.0), record(2.0)]

    alerts = collect_alerts(detector, records)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "traffic_anomaly"
    assert alert.severity == "medium"
    assert alert.src_ip == "10.0.0.1"
    assert alert.timestamp == 2.0


def test_repeated_packets_after_threshold_emit_one_alert(config):
    detector = make_detector(config, threshold=3)
    records = [record(float(index)) for index in range(10)]

    alerts = collect_alerts(detector, records)

    assert len(alerts) == 1


def test_window_expiration_allows_a_new_alert(config):
    detector = make_detector(config, threshold=3, window=5)
    first = [record(0.0), record(1.0), record(2.0)]
    second = [record(20.0), record(21.0), record(22.0)]

    alerts = collect_alerts(detector, first + second)

    assert len(alerts) == 2


def test_sources_are_tracked_independently(config):
    detector = make_detector(config, threshold=3)
    records = [
        record(0.0, src_ip="10.0.0.1"),
        record(1.0, src_ip="10.0.0.1"),
        record(2.0, src_ip="10.0.0.1"),
        record(3.0, src_ip="10.0.0.2"),
    ]

    alerts = collect_alerts(detector, records)

    assert len(alerts) == 1
    assert alerts[0].src_ip == "10.0.0.1"


def test_missing_source_is_ignored(config):
    detector = make_detector(config, threshold=1)

    assert detector.check(PacketRecord(timestamp=0.0, src_ip=None, protocol="TCP")) is None


def test_disabled_detector_returns_none(config):
    config["traffic_anomaly"]["enabled"] = False
    detector = RateAnomalyDetector(config)
    records = [record(float(index)) for index in range(50)]

    assert collect_alerts(detector, records) == []
