from nids.detectors.unknown_device import UnknownDeviceDetector
from nids.models import PacketRecord


def make_record(src_ip=None, src_mac=None, timestamp=0.0):
    return PacketRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        src_mac=src_mac,
        dst_ip="10.0.0.254",
        protocol="TCP",
    )


def make_inventory_detector(config):
    config["known_devices"] = [
        {"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:aa", "label": "laptop"},
        {"ip": "10.0.0.2", "label": "printer"},
    ]
    return UnknownDeviceDetector(config)


def test_known_ip_with_matching_mac_is_not_alerted(config):
    detector = make_inventory_detector(config)

    assert detector.check(make_record("10.0.0.1", "aa:aa:aa:aa:aa:aa")) is None


def test_known_ip_without_observed_mac_is_not_alerted(config):
    detector = make_inventory_detector(config)

    assert detector.check(make_record("10.0.0.1")) is None


def test_inventory_entry_without_mac_matches_by_ip(config):
    detector = make_inventory_detector(config)

    assert detector.check(make_record("10.0.0.2", "ff:ff:ff:ff:ff:ff")) is None


def test_unknown_ip_raises_one_alert(config):
    detector = make_inventory_detector(config)
    records = [
        make_record("192.168.1.50", "cc:cc:cc:cc:cc:cc", 0.0),
        make_record("192.168.1.50", "cc:cc:cc:cc:cc:cc", 1.0),
    ]

    alerts = [alert for alert in (detector.check(item) for item in records) if alert]

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "unknown_device"
    assert alert.severity == "medium"
    assert alert.src_ip == "192.168.1.50"
    assert alert.timestamp == 0.0
    assert "192.168.1.50" in alert.message


def test_known_ip_with_mismatched_mac_is_alerted(config):
    detector = make_inventory_detector(config)

    alert = detector.check(make_record("10.0.0.1", "ee:ee:ee:ee:ee:ee"))

    assert alert is not None
    assert alert.alert_type == "unknown_device"


def test_missing_source_ip_is_ignored(config):
    detector = make_inventory_detector(config)

    assert detector.check(make_record(src_ip=None, src_mac="aa:aa:aa:aa:aa:aa")) is None


def test_disabled_detector_returns_none(config):
    config["unknown_device"]["enabled"] = False
    detector = make_inventory_detector(config)

    assert detector.check(make_record("192.168.1.50", "cc:cc:cc:cc:cc:cc")) is None
