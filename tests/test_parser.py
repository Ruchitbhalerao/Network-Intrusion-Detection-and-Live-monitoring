from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from nids.models import PacketRecord
from nids.parser import parse_packet


def test_parse_tcp_packet_includes_ethernet_and_ports():
    packet = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=1234, dport=80)
    )
    packet.time = 1000.0

    record = parse_packet(packet)

    assert isinstance(record, PacketRecord)
    assert record.timestamp == 1000.0
    assert record.src_ip == "10.0.0.1"
    assert record.dst_ip == "10.0.0.2"
    assert record.src_port == 1234
    assert record.dst_port == 80
    assert record.protocol == "TCP"
    assert record.src_mac == "aa:bb:cc:dd:ee:ff"
    assert record.dst_mac == "11:22:33:44:55:66"


def test_parse_udp_packet():
    packet = Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=5353, dport=53)
    packet.time = 500.0

    record = parse_packet(packet)

    assert record.protocol == "UDP"
    assert record.src_port == 5353
    assert record.dst_port == 53


def test_parse_icmp_packet_has_no_ports():
    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
    packet.time = 42.0

    record = parse_packet(packet)

    assert record.protocol == "ICMP"
    assert record.src_ip == "10.0.0.1"
    assert record.dst_ip == "10.0.0.2"
    assert record.src_port is None
    assert record.dst_port is None


def test_parse_arp_packet():
    packet = (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=1,
            psrc="10.0.0.1",
            hwsrc="aa:aa:aa:aa:aa:aa",
            pdst="10.0.0.2",
            hwdst="00:00:00:00:00:00",
        )
    )
    packet.time = 7.0

    record = parse_packet(packet)

    assert record.protocol == "ARP"
    assert record.arp_operation == 1
    assert record.arp_sender_ip == "10.0.0.1"
    assert record.arp_sender_mac == "aa:aa:aa:aa:aa:aa"
    assert record.arp_target_ip == "10.0.0.2"
    assert record.arp_target_mac == "00:00:00:00:00:00"
    assert record.src_ip == "10.0.0.1"
    assert record.dst_ip == "10.0.0.2"
    assert record.src_mac == "aa:aa:aa:aa:aa:aa"


def test_parse_arp_without_ethernet():
    packet = ARP(op=2, psrc="10.0.0.9", hwsrc="aa:bb:cc:dd:ee:ff", pdst="10.0.0.1")

    record = parse_packet(packet)

    assert record.protocol == "ARP"
    assert record.arp_sender_mac == "aa:bb:cc:dd:ee:ff"
    assert record.src_mac is None
    assert record.dst_mac is None


def test_parse_ip_without_ethernet():
    packet = IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=2222, dport=443)

    record = parse_packet(packet)

    assert record.src_ip == "10.0.0.3"
    assert record.dst_port == 443
    assert record.src_mac is None
    assert record.dst_mac is None


def test_parse_unsupported_ip_protocol_uses_number():
    packet = IP(src="10.0.0.1", dst="10.0.0.2", proto=99) / Raw(load=b"x")

    record = parse_packet(packet)

    assert record.src_ip == "10.0.0.1"
    assert record.protocol == "99"
    assert record.src_port is None


def test_ethernet_frame_without_ip_or_arp_returns_none():
    packet = Ether() / Raw(load=b"hello")

    assert parse_packet(packet) is None


def test_transport_without_ip_returns_none():
    assert parse_packet(TCP()) is None


def test_none_input_returns_none():
    assert parse_packet(None) is None


def test_non_packet_object_returns_none():
    assert parse_packet(object()) is None


def test_missing_timestamp_returns_none():
    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2)
    packet.time = None

    assert parse_packet(packet) is None
