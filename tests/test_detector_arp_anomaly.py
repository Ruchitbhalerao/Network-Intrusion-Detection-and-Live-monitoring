from nids.detectors.arp_anomaly import ArpAnomalyDetector
from nids.models import PacketRecord


def arp(ip, mac, timestamp=0.0):
    return PacketRecord(
        timestamp=timestamp,
        protocol="ARP",
        src_ip=ip,
        arp_sender_ip=ip,
        arp_sender_mac=mac,
    )


def collect_alerts(detector, records):
    return [alert for alert in (detector.check(item) for item in records) if alert]


def test_first_mapping_raises_no_alert(config):
    detector = ArpAnomalyDetector(config)

    assert collect_alerts(detector, [arp("10.0.0.1", "aa:aa:aa:aa:aa:aa")]) == []


def test_same_mapping_repeated_raises_no_alert(config):
    detector = ArpAnomalyDetector(config)
    records = [
        arp("10.0.0.1", "aa:aa:aa:aa:aa:aa", 0.0),
        arp("10.0.0.1", "aa:aa:aa:aa:aa:aa", 1.0),
    ]

    assert collect_alerts(detector, records) == []


def test_conflicting_mapping_raises_one_alert(config):
    detector = ArpAnomalyDetector(config)
    records = [
        arp("10.0.0.1", "aa:aa:aa:aa:aa:aa", 0.0),
        arp("10.0.0.1", "bb:bb:bb:bb:bb:bb", 1.0),
        arp("10.0.0.1", "bb:bb:bb:bb:bb:bb", 2.0),
    ]

    alerts = collect_alerts(detector, records)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "arp_anomaly"
    assert alert.severity == "high"
    assert alert.src_ip == "10.0.0.1"
    assert alert.protocol == "ARP"
    assert alert.timestamp == 1.0


def test_conflict_then_restore_then_conflict_alerts_again(config):
    detector = ArpAnomalyDetector(config)
    records = [
        arp("10.0.0.1", "aa:aa:aa:aa:aa:aa", 0.0),
        arp("10.0.0.1", "bb:bb:bb:bb:bb:bb", 1.0),
        arp("10.0.0.1", "aa:aa:aa:aa:aa:aa", 2.0),
        arp("10.0.0.1", "bb:bb:bb:bb:bb:bb", 3.0),
    ]

    alerts = collect_alerts(detector, records)

    assert len(alerts) == 2


def test_incomplete_arp_records_are_ignored(config):
    detector = ArpAnomalyDetector(config)

    assert detector.check(PacketRecord(timestamp=0.0, protocol="ARP", arp_sender_ip="10.0.0.1")) is None
    assert detector.check(PacketRecord(timestamp=0.0, protocol="ARP", arp_sender_mac="aa:aa:aa:aa:aa:aa")) is None
    assert detector.check(PacketRecord(timestamp=0.0, protocol="TCP", src_ip="10.0.0.1")) is None


def test_disabled_detector_returns_none(config):
    config["arp_anomaly"]["enabled"] = False
    detector = ArpAnomalyDetector(config)
    records = [
        arp("10.0.0.1", "aa:aa:aa:aa:aa:aa", 0.0),
        arp("10.0.0.1", "bb:bb:bb:bb:bb:bb", 1.0),
    ]

    assert collect_alerts(detector, records) == []
