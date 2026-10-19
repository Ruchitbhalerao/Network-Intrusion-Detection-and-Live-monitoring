"""ARP anomaly: an IP address suddenly claiming a different MAC address.

We remember the first MAC seen for each sender IP and compare later ARP
records against it. A different MAC raises a single alert for that IP. If the
IP goes back to its original MAC the alert state is cleared, so a *new*
conflict can be reported later. Incomplete ARP records are ignored.
"""

from .base import Detector


class ArpAnomalyDetector(Detector):
    section = "arp_anomaly"
    alert_type = "arp_anomaly"
    severity = "high"

    def __init__(self, config):
        super().__init__(config)
        self._mappings = {}
        self._alerted = set()

    def inspect(self, record):
        ip = record.arp_sender_ip
        mac = record.arp_sender_mac
        if ip is None or mac is None:
            return None

        known_mac = self._mappings.get(ip)
        if known_mac is None:
            self._mappings[ip] = mac
            return None

        if mac == known_mac:
            self._alerted.discard(ip)
            return None

        if ip in self._alerted:
            return None

        self._alerted.add(ip)
        message = f"ARP anomaly: {ip} was seen with MAC {known_mac} but now claims {mac}"
        return self.build_alert(record, message, src_ip=ip, protocol="ARP")
