import json

import pytest

from nids.config import load_config


@pytest.fixture
def write_config(tmp_path):
    def _write(data):
        path = tmp_path / "config.json"
        text = data if isinstance(data, str) else json.dumps(data)
        path.write_text(text, encoding="utf-8")
        return path

    return _write


@pytest.fixture
def config():
    return load_config()
