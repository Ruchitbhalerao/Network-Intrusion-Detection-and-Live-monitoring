from nids.models import PacketRecord
from nids.synthetic import (
    arp_mapping_change,
    packet_burst,
    port_scan_packets,
    repeated_connections,
    tcp_packets,
    udp_packets,
    unknown_device_traffic,
)


def test_tcp_packets_count_types_and_values():
    records = tcp_packets(
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        src_port=1111,
        dst_port=2222,
        count=3,
        start_time=10.0,
        interval=0.5,
    )

    assert len(records) == 3
    assert all(isinstance(record, PacketRecord) for record in records)
    assert [record.protocol for record in records] == ["TCP", "TCP", "TCP"]
    assert records[0].src_ip == "1.1.1.1"
    assert records[0].dst_ip == "2.2.2.2"
    assert records[1].src_port == 1111
    assert records[2].dst_port == 2222
    assert [record.timestamp for record in records] == [10.0, 10.5, 11.0]


def test_udp_packets_count_types_and_values():
    records = udp_packets(dst_port=53, count=2, start_time=0.0, interval=1.0)

    assert len(records) == 2
    assert all(record.protocol == "UDP" for record in records)
    assert all(record.dst_port == 53 for record in records)
    assert [record.timestamp for record in records] == [0.0, 1.0]


def test_port_scan_packets_use_many_destination_ports():
    records = port_scan_packets(port_count=5, start_port=20, start_time=0.0, interval=0.01)

    assert len(records) == 5
    assert [record.dst_port for record in records] == [20, 21, 22, 23, 24]
    assert len({record.dst_port for record in records}) == 5
    assert all(record.src_ip == records[0].src_ip for record in records)


def test_packet_burst_count_and_spacing():
    records = packet_burst(count=20, start_time=0.0, interval=0.01)

    assert len(records) == 20
    assert all(isinstance(record, PacketRecord) for record in records)
    assert records[0].timestamp == 0.0
    assert records[-1].timestamp == 0.19
    assert records[0].src_ip == records[-1].src_ip


def test_arp_mapping_change_produces_conflicting_mappings():
    records = arp_mapping_change(
        sender_ip="10.0.0.5",
        macs=("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"),
    )

    assert len(records) == 2
    assert all(record.protocol == "ARP" for record in records)
    assert {record.arp_sender_ip for record in records} == {"10.0.0.5"}
    assert [record.arp_sender_mac for record in records] == [
        "aa:aa:aa:aa:aa:aa",
        "bb:bb:bb:bb:bb:bb",
    ]
    assert records[0].arp_operation == 2


def test_unknown_device_traffic():
    records = unknown_device_traffic(src_ip="192.168.9.9", dst_port=23, count=4)

    assert len(records) == 4
    assert all(record.src_ip == "192.168.9.9" for record in records)
    assert all(record.dst_port == 23 for record in records)
    assert all(record.protocol == "TCP" for record in records)


def test_repeated_connections_reuse_destination_and_vary_source():
    records = repeated_connections(dst_port=443, count=6, start_port=50000)

    assert len(records) == 6
    assert {record.dst_port for record in records} == {443}
    assert [record.src_port for record in records] == [50000, 50001, 50002, 50003, 50004, 50005]
