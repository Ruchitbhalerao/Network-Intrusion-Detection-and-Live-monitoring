"""Load the JSON configuration, fill in defaults, and validate it.

Every configurable threshold used by the detectors lives here (as a default)
and in ``config.json`` (as the user-editable file). Detectors should read
values from the dict returned by :func:`load_config` instead of hardcoding
their own numbers.
"""

import copy
import json
from pathlib import Path

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"

DEFAULTS = {
    "capture": {
        "enabled": False,
        "interface": None,
        "packet_limit": 0,
        "timeout_seconds": 0,
    },
    "port_scan": {
        "enabled": True,
        "window_seconds": 10,
        "unique_ports_threshold": 20,
    },
    "traffic_anomaly": {
        "enabled": True,
        "window_seconds": 5,
        "packet_rate_threshold": 200,
    },
    "arp_anomaly": {
        "enabled": True,
    },
    "unknown_device": {
        "enabled": True,
    },
    "repeated_connections": {
        "enabled": True,
        "window_seconds": 30,
        "attempts_threshold": 10,
    },
    "dedup": {
        "window_seconds": 60,
    },
    "traffic_monitor": {
        "enabled": True,
        "retention_seconds": 900,
        "default_window_seconds": 60,
        "max_window_seconds": 900,
        "top_talkers": 5,
    },
    "known_devices": [],
}


class ConfigError(ValueError):
    """Raised when the configuration file is missing or invalid."""


def load_config(path=None):
    """Return a validated configuration dict.

    Missing sections or keys fall back to :data:`DEFAULTS`. The ``path``
    argument is mainly useful in tests; when omitted the ``config.json`` next
    to the project root is used.
    """
    config_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    raw = _read_json(config_path)
    merged = _merge(DEFAULTS, raw)
    return _validate(merged)


def _read_json(path):
    if not path.is_file():
        raise ConfigError(f"Configuration file not found: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ConfigError(f"Could not read configuration file {path}: {error}") from error
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise ConfigError(f"Configuration file {path} is not valid JSON: {error}") from error
    if not isinstance(data, dict):
        raise ConfigError(f"Configuration file {path} must contain a JSON object at the top level")
    return data


def _merge(defaults, user, prefix=""):
    if not isinstance(user, dict):
        location = prefix or "configuration"
        raise ConfigError(f"'{location}' must be a JSON object")
    result = {}
    for key, default_value in defaults.items():
        location = f"{prefix}.{key}" if prefix else key
        if key not in user:
            result[key] = copy.deepcopy(default_value)
            continue
        user_value = user[key]
        if isinstance(default_value, dict):
            result[key] = _merge(default_value, user_value, location)
        else:
            result[key] = user_value
    for key in user:
        if key not in defaults:
            location = f"{prefix}.{key}" if prefix else key
            raise ConfigError(f"Unknown configuration option: '{location}'")
    return result


def _validate(config):
    for section in ("port_scan", "traffic_anomaly", "arp_anomaly", "unknown_device", "repeated_connections"):
        _validate_enabled(config[section], section)

    _validate_capture(config["capture"])

    _positive_int(config["port_scan"]["window_seconds"], "port_scan.window_seconds")
    _positive_int(config["port_scan"]["unique_ports_threshold"], "port_scan.unique_ports_threshold")
    _positive_int(config["traffic_anomaly"]["window_seconds"], "traffic_anomaly.window_seconds")
    _positive_int(config["traffic_anomaly"]["packet_rate_threshold"], "traffic_anomaly.packet_rate_threshold")
    _positive_int(config["repeated_connections"]["window_seconds"], "repeated_connections.window_seconds")
    _positive_int(config["repeated_connections"]["attempts_threshold"], "repeated_connections.attempts_threshold")
    _positive_int(config["dedup"]["window_seconds"], "dedup.window_seconds")

    _validate_traffic_monitor(config["traffic_monitor"])

    _validate_known_devices(config["known_devices"])
    return config


def _validate_enabled(section, name):
    if not isinstance(section["enabled"], bool):
        raise ConfigError(f"'{name}.enabled' must be true or false")


def _positive_int(value, name):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"'{name}' must be a whole number")
    if value <= 0:
        raise ConfigError(f"'{name}' must be greater than 0, got {value}")


def _non_negative_int(value, name):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"'{name}' must be a whole number")
    if value < 0:
        raise ConfigError(f"'{name}' must be 0 or greater, got {value}")


def _non_negative_number(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"'{name}' must be a number")
    if value < 0:
        raise ConfigError(f"'{name}' must be 0 or greater, got {value}")


def _validate_capture(capture):
    if not isinstance(capture["enabled"], bool):
        raise ConfigError("'capture.enabled' must be true or false")
    interface = capture["interface"]
    if interface is not None and (not isinstance(interface, str) or not interface):
        raise ConfigError("'capture.interface' must be null or a non-empty string")
    _non_negative_int(capture["packet_limit"], "capture.packet_limit")
    _non_negative_number(capture["timeout_seconds"], "capture.timeout_seconds")


def _validate_traffic_monitor(monitor):
    if not isinstance(monitor["enabled"], bool):
        raise ConfigError("'traffic_monitor.enabled' must be true or false")
    _positive_int(monitor["retention_seconds"], "traffic_monitor.retention_seconds")
    _positive_int(monitor["default_window_seconds"], "traffic_monitor.default_window_seconds")
    _positive_int(monitor["max_window_seconds"], "traffic_monitor.max_window_seconds")
    _positive_int(monitor["top_talkers"], "traffic_monitor.top_talkers")
    if monitor["default_window_seconds"] > monitor["max_window_seconds"]:
        raise ConfigError(
            "'traffic_monitor.default_window_seconds' must not exceed "
            "'traffic_monitor.max_window_seconds'"
        )


def _validate_known_devices(devices):
    if not isinstance(devices, list):
        raise ConfigError("'known_devices' must be a JSON list")
    for index, device in enumerate(devices):
        location = f"known_devices[{index}]"
        if not isinstance(device, dict):
            raise ConfigError(f"'{location}' must be a JSON object")
        ip = device.get("ip")
        if not isinstance(ip, str) or not ip:
            raise ConfigError(f"'{location}.ip' must be a non-empty string")
        for key in ("mac", "label"):
            if key in device and not isinstance(device[key], str):
                raise ConfigError(f"'{location}.{key}' must be a string")
