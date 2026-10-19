"""Entry point for the Network Intrusion Detection and Threat Monitoring System.

Starts the read-only dashboard and JSON API on localhost.

By default live packet capture is intentionally not started: the dashboard only
displays data already in the SQLite database. Run from the project root:

    .venv/bin/python run.py

Two optional live sources can feed the dashboard in real time:

    .venv/bin/python run.py --live-demo        # synthetic traffic, no sudo
    sudo .venv/bin/python run.py --capture      # real packets off an interface

``--live-demo`` drives the real detection engine with synthetic records so the
dashboard fills with alerts without privileges or real traffic. ``--capture``
sniffs real packets and usually requires root access to ``/dev/bpf*`` on macOS;
on a normal setup you will mostly see traffic to and from your own machine.
"""

import argparse

from nids import db
from nids.api import create_app
from nids.config import ConfigError, load_config

HOST = "127.0.0.1"
PORT = 5001


def build_app(db_path=None, config=None):
    """Load configuration and build the Flask application."""
    return create_app(config=config or load_config(), db_path=db_path)


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Network Intrusion Detection dashboard and JSON API."
    )
    parser.add_argument(
        "--live-demo",
        action="store_true",
        help="Feed synthetic traffic through the engine for a live demo (no sudo).",
    )
    parser.add_argument(
        "--capture",
        action="store_true",
        help="Start live packet capture (needs root on macOS). Use with care.",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface for --capture (defaults to config / Scapy default).",
    )
    parser.add_argument(
        "--db",
        default=None,
        help="SQLite database path (defaults to the project nids.db).",
    )
    parser.add_argument(
        "--host",
        default=HOST,
        help=f"Host/IP to bind the web server to (default {HOST}, localhost only).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=PORT,
        help=f"Port for the web server (default {PORT}; avoids macOS AirPlay on 5000).",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List the network interfaces Scapy can see, then exit.",
    )
    return parser.parse_args(argv)


def _default_iface():
    try:
        from scapy.all import conf
        return str(conf.iface)
    except Exception:
        return "default"


def _list_interfaces():
    """Print the interfaces Scapy can see and the default one."""
    try:
        from scapy.all import conf, get_if_list
    except Exception as error:
        print(f"Could not load Scapy to list interfaces: {error}")
        return 1
    print("Available network interfaces:")
    for name in get_if_list():
        print(f"  - {name}")
    print(f"Default (used when --interface is omitted): {conf.iface}")
    return 0


def main(argv=None):
    args = _parse_args(argv)

    if args.list_interfaces:
        return _list_interfaces()

    try:
        config = load_config()
    except ConfigError as error:
        print(f"Configuration error: {error}")
        return 1

    db_path = args.db if args.db is not None else db.DEFAULT_DB_PATH
    app = build_app(db_path=db_path, config=config)

    feed = None
    capture = None

    if args.live_demo:
        from nids.livefeed import LiveFeed

        feed = LiveFeed(config, db_path=db_path)
        feed.start()
        print("Live demo feed started: synthetic traffic is driving the engine.")

    if args.capture:
        from nids.capture import CaptureError, PacketCapture

        config["capture"]["enabled"] = True
        capture = PacketCapture(config, db_path=db_path)
        try:
            capture.start(interface=args.interface)
        except CaptureError as error:
            print(f"Could not start packet capture: {error}")
            print("Live capture usually needs root (e.g. sudo) to read /dev/bpf*.")
            print("Tip: run 'python run.py --list-interfaces' to see interfaces.")
            return 1
        iface = args.interface or config["capture"].get("interface") or _default_iface()
        print(f"Live packet capture started on interface: {iface}")
        print("Showing real traffic to/from this machine (e.g. Google Meet appears as UDP).")

    print(f"Network Intrusion Detection dashboard: http://{args.host}:{args.port}/")
    print(f"Live traffic portal:                   http://{args.host}:{args.port}/live")
    if feed is None and capture is None:
        print("Press Ctrl+C to stop. Live packet capture is not started.")
    else:
        print("Press Ctrl+C to stop.")

    try:
        app.run(host=args.host, port=args.port, debug=False)
    finally:
        if feed is not None:
            feed.stop()
        if capture is not None:
            capture.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
