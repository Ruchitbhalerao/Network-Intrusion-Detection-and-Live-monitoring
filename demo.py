"""Command-line demonstration of the five detection rules.

Run from the project root:

    .venv/bin/python demo.py

Every record comes from ``nids.synthetic``; no live capture is started and no
administrator privileges are needed. Alerts and tracked devices are stored in
``demo.db`` so the normal ``nids.db`` is left untouched. To show the results on
the dashboard, start the app pointed at ``demo.db`` (printed at the end of the
run).
"""

from pathlib import Path
from time import time

from nids import db
from nids.config import load_config
from nids.engine import DetectionEngine
from nids.models import Device
from nids.synthetic import (
    arp_mapping_change,
    packet_burst,
    port_scan_packets,
    repeated_connections,
    unknown_device_traffic,
)

DEMO_DB_PATH = "demo.db"

SCENARIOS = (
    ("Port scanning", lambda start: port_scan_packets(start_time=start)),
    (
        "Packet burst / traffic anomaly",
        lambda start: packet_burst(count=200, start_time=start),
    ),
    ("ARP mapping change", lambda start: arp_mapping_change(start_time=start)),
    ("Unknown device", lambda start: unknown_device_traffic(start_time=start)),
    ("Repeated connections", lambda start: repeated_connections(start_time=start)),
)


def known_inventory(config):
    return {
        entry["ip"]: entry
        for entry in config.get("known_devices", [])
        if entry.get("ip")
    }


def observed_device(record, inventory):
    ip = record.arp_sender_ip or record.src_ip
    if ip is None:
        return None
    entry = inventory.get(ip)
    mac = record.arp_sender_mac or record.src_mac
    return Device(
        ip=ip,
        mac=mac,
        label=entry.get("label") if entry else None,
        known=entry is not None,
        first_seen=record.timestamp,
        last_seen=record.timestamp,
    )


def run_scenario(name, records, config, db_path):
    engine = DetectionEngine(config, db_path=db_path)
    inventory = known_inventory(config)
    emitted = []

    print(f"\n{name}")
    for record in records:
        device = observed_device(record, inventory)
        if device is not None:
            db.insert_device(device, db_path)
        emitted.extend(engine.process_record(record))

    if not emitted:
        print("  no alerts")
        return
    for alert in emitted:
        print(
            f"  {alert.alert_type:<20} {alert.severity:<8} "
            f"src={alert.src_ip} dst_port={alert.dst_port}"
        )


def main(db_path=DEMO_DB_PATH):
    Path(db_path).unlink(missing_ok=True)
    config = load_config()

    print(f"Running the detection demo (writing to {db_path})...")
    start_time = time()
    for name, make_records in SCENARIOS:
        run_scenario(name, make_records(start_time), config, db_path)

    stored = db.get_alerts(db_path=db_path)
    devices = db.get_devices(db_path=db_path)
    print(f"\nTotal alerts stored in {db_path}: {len(stored)}")
    print(f"Tracked devices in {db_path}: {len(devices)}")
    for device in devices:
        print(f"  {device.ip:<15} mac={device.mac} known={device.known}")

    print("\nTo view them on the dashboard, run:")
    print(
        "  .venv/bin/python -c \"from run import build_app; "
        f"build_app(db_path='{db_path}').run(host='127.0.0.1', port=5000)\""
    )
    print("Then open http://127.0.0.1:5000/ in your browser.")
    print(f"\nTo remove the demo database afterwards: rm -f {db_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
