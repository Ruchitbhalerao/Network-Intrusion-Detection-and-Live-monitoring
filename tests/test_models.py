from nids.models import Alert, Device, PacketRecord


def test_packet_record_with_valid_values():
    record = PacketRecord(
        timestamp=100.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=80,
        protocol="TCP",
    )
    assert record.timestamp == 100.0
    assert record.src_ip == "10.0.0.1"
    assert record.dst_port == 80
    assert record.protocol == "TCP"


def test_packet_record_optional_fields_default_to_none():
    record = PacketRecord()
    assert record.timestamp > 0
    assert record.src_ip is None
    assert record.dst_ip is None
    assert record.src_port is None
    assert record.dst_port is None
    assert record.protocol is None
    assert record.arp_sender_ip is None


def test_packet_record_arp_fields():
    record = PacketRecord(
        protocol="ARP",
        arp_operation=1,
        arp_sender_ip="10.0.0.1",
        arp_sender_mac="aa:bb:cc:dd:ee:ff",
        arp_target_ip="10.0.0.2",
    )
    assert record.arp_operation == 1
    assert record.arp_sender_mac == "aa:bb:cc:dd:ee:ff"
    assert record.arp_target_ip == "10.0.0.2"
    assert record.arp_target_mac is None


def test_alert_with_valid_values():
    alert = Alert(
        alert_type="port_scan",
        severity="high",
        message="Possible port scan detected",
        timestamp=200.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.9",
    )
    assert alert.alert_type == "port_scan"
    assert alert.severity == "high"
    assert alert.src_ip == "10.0.0.1"


def test_alert_defaults():
    alert = Alert(alert_type="traffic_anomaly", message="High packet rate")
    assert alert.severity == "medium"
    assert alert.message == "High packet rate"
    assert alert.timestamp > 0
    assert alert.dst_ip is None


def test_device_with_valid_values():
    device = Device(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff", label="laptop")
    assert device.ip == "192.168.1.10"
    assert device.mac == "aa:bb:cc:dd:ee:ff"
    assert device.label == "laptop"


def test_device_defaults():
    device = Device(ip="192.168.1.20")
    assert device.mac is None
    assert device.hostname is None
    assert device.label is None
    assert device.known is False
    assert device.first_seen is None
    assert device.last_seen is None
