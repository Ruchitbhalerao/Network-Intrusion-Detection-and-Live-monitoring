from pathlib import Path

import pytest

from nids.config import DEFAULTS, ConfigError, load_config

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_loads_valid_configuration(write_config):
    config = load_config(
        write_config(
            {
                "port_scan": {"window_seconds": 5, "unique_ports_threshold": 3},
                "known_devices": [
                    {"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:ff", "label": "laptop"}
                ],
            }
        )
    )
    assert config["port_scan"]["window_seconds"] == 5
    assert config["port_scan"]["unique_ports_threshold"] == 3
    assert config["known_devices"][0]["ip"] == "192.168.1.10"
    assert config["known_devices"][0]["label"] == "laptop"


def test_empty_config_uses_all_defaults(write_config):
    assert load_config(write_config({})) == DEFAULTS


def test_default_threshold_values(write_config):
    config = load_config(write_config({}))
    assert config["port_scan"]["unique_ports_threshold"] == 20
    assert config["traffic_anomaly"]["packet_rate_threshold"] == 200
    assert config["repeated_connections"]["attempts_threshold"] == 10
    assert config["arp_anomaly"]["enabled"] is True
    assert config["unknown_device"]["enabled"] is True
    assert config["known_devices"] == []


def test_missing_configuration_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "does_not_exist.json")


def test_invalid_json(write_config):
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_config(write_config("{ this is not json "))


def test_top_level_must_be_object(write_config):
    with pytest.raises(ConfigError, match="JSON object"):
        load_config(write_config([1, 2, 3]))


def test_section_must_be_object(write_config):
    with pytest.raises(ConfigError, match="port_scan"):
        load_config(write_config({"port_scan": "not an object"}))


@pytest.mark.parametrize("value", [0, -1, 1.5, "10", None, True])
def test_invalid_threshold_values(write_config, value):
    with pytest.raises(ConfigError):
        load_config(write_config({"port_scan": {"unique_ports_threshold": value}}))


@pytest.mark.parametrize("value", [1, "yes", None])
def test_invalid_enabled_flag(write_config, value):
    with pytest.raises(ConfigError, match="true or false"):
        load_config(write_config({"arp_anomaly": {"enabled": value}}))


def test_unknown_option_is_rejected(write_config):
    with pytest.raises(ConfigError, match="Unknown configuration option"):
        load_config(write_config({"port_scann": {"window_seconds": 5}}))


def test_invalid_known_device_missing_ip(write_config):
    with pytest.raises(ConfigError, match="ip"):
        load_config(write_config({"known_devices": [{"mac": "aa:bb:cc:dd:ee:ff"}]}))


def test_invalid_known_devices_type(write_config):
    with pytest.raises(ConfigError, match="known_devices"):
        load_config(write_config({"known_devices": "nope"}))


def test_defaults_are_not_mutated(write_config):
    load_config(write_config({"port_scan": {"window_seconds": 1}}))
    assert DEFAULTS["port_scan"]["window_seconds"] == 10


def test_repository_config_file_loads():
    config = load_config(REPO_ROOT / "config.json")
    assert config["known_devices"] == []
    assert config["port_scan"]["enabled"] is True
