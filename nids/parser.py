"""Convert Scapy packets into normalized :class:`PacketRecord` objects.

This module only reads a packet and copies the interesting fields into a plain
dataclass. It performs no detection and touches no database. Packets that do
not contain anything we can use (no IPv4 and no ARP layer) return ``None``
instead of raising.
"""

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from .models import PacketRecord

_IP_PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def parse_packet(packet):
    """Return a :class:`PacketRecord` for ``packet``, or ``None``.

    ``None`` is returned for empty input, objects that are not Scapy packets,
    packets without a usable timestamp, and Ethernet frames that carry neither
    IPv4 nor ARP.
    """
    if packet is None or not hasattr(packet, "haslayer"):
        return None

    timestamp = _packet_timestamp(packet)
    if timestamp is None:
        return None

    record = PacketRecord(timestamp=timestamp)
    record.length = _packet_length(packet)
    _copy_ethernet(packet, record)

    if packet.haslayer(ARP):
        _copy_arp(packet.getlayer(ARP), record)
        return record

    if packet.haslayer(IP):
        _copy_ip(packet, record)
        return record

    return None


def _packet_length(packet):
    try:
        return int(len(packet))
    except (TypeError, ValueError):
        return None


def _packet_timestamp(packet):
    value = getattr(packet, "time", None)
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _copy_ethernet(packet, record):
    ether = packet.getlayer(Ether)
    if ether is not None:
        record.src_mac = ether.src
        record.dst_mac = ether.dst


def _copy_arp(arp, record):
    record.protocol = "ARP"
    record.arp_operation = int(arp.op)
    record.arp_sender_ip = arp.psrc
    record.arp_sender_mac = arp.hwsrc
    record.arp_target_ip = arp.pdst
    record.arp_target_mac = arp.hwdst
    record.src_ip = arp.psrc
    record.dst_ip = arp.pdst


def _copy_ip(packet, record):
    ip = packet.getlayer(IP)
    record.src_ip = ip.src
    record.dst_ip = ip.dst
    record.protocol = _IP_PROTOCOLS.get(ip.proto, str(ip.proto))

    tcp = packet.getlayer(TCP)
    if tcp is not None:
        record.src_port = int(tcp.sport)
        record.dst_port = int(tcp.dport)
        return

    udp = packet.getlayer(UDP)
    if udp is not None:
        record.src_port = int(udp.sport)
        record.dst_port = int(udp.dport)
