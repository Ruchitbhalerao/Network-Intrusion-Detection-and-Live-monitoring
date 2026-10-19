"""Plain data models shared across the application.

These dataclasses are intentionally independent of Scapy, Flask, and SQLite so
they can be created and tested anywhere in the project. Fields that are not
always available (ports, MAC addresses, ARP details) default to ``None``.
"""

from dataclasses import dataclass, field
from time import time
from typing import Optional


@dataclass
class PacketRecord:
    """A single normalized network packet."""

    timestamp: float = field(default_factory=time)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    length: Optional[int] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    arp_operation: Optional[int] = None
    arp_sender_ip: Optional[str] = None
    arp_sender_mac: Optional[str] = None
    arp_target_ip: Optional[str] = None
    arp_target_mac: Optional[str] = None


@dataclass
class Alert:
    """A possible suspicious event produced by a detector."""

    alert_type: str
    severity: str = "medium"
    message: str = ""
    timestamp: float = field(default_factory=time)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None


@dataclass
class Device:
    """A device observed on the monitored network."""

    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    label: Optional[str] = None
    known: bool = False
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
