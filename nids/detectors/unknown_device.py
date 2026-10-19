"""Unknown device: traffic from a source that is not in the inventory.

Matching rules (also covered by the tests):

* A record must have a source IP; records without one are ignored so missing
  information is never treated as an unknown device.
* A source IP is known when it appears in ``config["known_devices"]``.
* If the inventory entry lists a MAC *and* the record carries a source MAC,
  the two MACs must match. A mismatch is treated as an unknown/spoofed device.
* If either MAC is unavailable, the IP match alone is enough.
* Only the first sighting of an unknown IP raises an alert; later packets from
  the same IP stay quiet until it becomes known.
"""

from .base import Detector


class UnknownDeviceDetector(Detector):
    section = "unknown_device"
    alert_type = "unknown_device"
    severity = "medium"

    def __init__(self, config):
        super().__init__(config)
        self._inventory = {}
        for entry in config.get("known_devices", []):
            if entry.get("ip"):
                self._inventory[entry["ip"]] = entry.get("mac")
        self._alerted = set()

    def inspect(self, record):
        ip = record.src_ip
        if ip is None:
            return None

        if self._is_known(ip, record.src_mac):
            self._alerted.discard(ip)
            return None

        if ip in self._alerted:
            return None

        self._alerted.add(ip)
        if record.src_mac:
            message = (
                f"Unknown device: {ip} ({record.src_mac}) is not in the "
                f"known-device inventory"
            )
        else:
            message = f"Unknown device: {ip} is not in the known-device inventory"
        return self.build_alert(record, message, src_ip=ip)

    def _is_known(self, ip, mac):
        if ip not in self._inventory:
            return False
        known_mac = self._inventory[ip]
        if known_mac is None or mac is None:
            return True
        return known_mac.lower() == mac.lower()
