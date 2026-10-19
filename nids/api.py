"""Read-only JSON API for the NIDS dashboard.

This module exposes the data already stored by the detection pipeline. It
never starts packet capture and never starts a web server on import; callers
build an application with :func:`create_app` and run it explicitly. The
factory accepts a ``db_path`` so tests can point at a temporary database
instead of the real ``nids.db``.

All endpoints return JSON. Errors use a small ``{"error": "..."}`` shape and a
sensible HTTP status code; internal failures are reported generically so no
stack traces or local paths leak to clients.
"""

from dataclasses import asdict
from time import time

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from . import db
from .web import register_web

DEFAULT_ALERT_LIMIT = 50
MAX_ALERT_LIMIT = 500

DEFAULT_TRAFFIC_WINDOW = 60
MAX_TRAFFIC_WINDOW = 900
DEFAULT_TOP_TALKERS = 5


def create_app(config=None, db_path=None):
    """Build a Flask application.

    ``db_path`` selects the SQLite file (defaults to the project database) and
    ``config`` is the loaded NIDS configuration, kept for later stages.
    """
    app = Flask(__name__, static_folder=None)
    app.config["DB_PATH"] = db_path if db_path is not None else db.DEFAULT_DB_PATH
    app.config["NIDS_CONFIG"] = config

    db.init_db(app.config["DB_PATH"])
    _register_routes(app)
    _register_error_handlers(app)
    register_web(app)
    return app


def _register_routes(app):
    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/api/alerts")
    def alerts():
        limit, error = _parse_limit(request.args.get("limit"))
        if error is not None:
            return _error(error, 400)
        stored = db.get_alerts(limit=limit, db_path=app.config["DB_PATH"])
        return jsonify({"count": len(stored), "alerts": [asdict(a) for a in stored]})

    @app.get("/api/devices")
    def devices():
        stored = db.get_devices(db_path=app.config["DB_PATH"])
        return jsonify({"count": len(stored), "devices": [asdict(d) for d in stored]})

    @app.get("/api/stats")
    def stats():
        return jsonify(db.get_stats(db_path=app.config["DB_PATH"]))

    @app.get("/api/traffic")
    def traffic():
        monitor = _traffic_settings(app.config.get("NIDS_CONFIG"))
        window, error = _parse_window(request.args.get("window"), monitor)
        if error is not None:
            return _error(error, 400)
        db_path = app.config["DB_PATH"]
        now = time()
        return jsonify(
            {
                "window_seconds": window,
                "generated_at": now,
                "summary": db.get_traffic_summary(window, now=now, db_path=db_path),
                "series": db.get_traffic_series(window, now=now, db_path=db_path),
                "protocols": db.get_protocol_breakdown(window, now=now, db_path=db_path),
                "top_talkers": db.get_top_talkers(
                    window, limit=monitor["top_talkers"], now=now, db_path=db_path
                ),
            }
        )


def _register_error_handlers(app):
    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        return _error(error.description, error.code)

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        return _error("internal server error", 500)


def _parse_limit(raw):
    if raw is None:
        return DEFAULT_ALERT_LIMIT, None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None, "'limit' must be a whole number"
    if value < 1:
        return None, "'limit' must be greater than 0"
    if value > MAX_ALERT_LIMIT:
        return None, f"'limit' must not exceed {MAX_ALERT_LIMIT}"
    return value, None


def _traffic_settings(config):
    monitor = (config or {}).get("traffic_monitor", {}) if config else {}
    return {
        "default_window": monitor.get("default_window_seconds", DEFAULT_TRAFFIC_WINDOW),
        "max_window": monitor.get("max_window_seconds", MAX_TRAFFIC_WINDOW),
        "top_talkers": monitor.get("top_talkers", DEFAULT_TOP_TALKERS),
    }


def _parse_window(raw, monitor):
    if raw is None:
        return monitor["default_window"], None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None, "'window' must be a whole number of seconds"
    if value < 1:
        return None, "'window' must be greater than 0"
    if value > monitor["max_window"]:
        return None, f"'window' must not exceed {monitor['max_window']}"
    return value, None


def _error(message, status):
    return jsonify({"error": message}), status
