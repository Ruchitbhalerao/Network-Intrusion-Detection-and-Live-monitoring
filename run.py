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
PORT = 5000


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
    return parser.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)
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
            return 1
        print("Live packet capture started.")

    print(f"Network Intrusion Detection dashboard: http://{HOST}:{PORT}/")
    if feed is None and capture is None:
        print("Press Ctrl+C to stop. Live packet capture is not started.")
    else:
        print("Press Ctrl+C to stop.")

    try:
        app.run(host=HOST, port=PORT, debug=False)
    finally:
        if feed is not None:
            feed.stop()
        if capture is not None:
            capture.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
