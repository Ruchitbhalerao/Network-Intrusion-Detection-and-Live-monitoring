import pytest

from nids.api import create_app


@pytest.fixture
def client(tmp_path):
    return create_app(db_path=tmp_path / "web.db").test_client()


def test_dashboard_page_is_served(client):
    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.content_type
    body = response.get_data(as_text=True)
    assert "Network Intrusion Detection and Threat Monitoring System" in body
    assert 'id="alerts-body"' in body
    assert 'id="devices-body"' in body
    assert 'id="severity-counts"' in body
    assert 'id="refresh"' in body


def test_static_assets_are_served(client):
    css = client.get("/static/style.css")
    js = client.get("/static/app.js")

    assert css.status_code == 200
    assert "text/css" in css.content_type
    assert js.status_code == 200
    assert "javascript" in js.content_type


def test_frontend_calls_existing_api_endpoints(client):
    js = client.get("/static/app.js").get_data(as_text=True)

    for path in ("/api/health", "/api/alerts", "/api/devices", "/api/stats"):
        assert path in js


def test_dashboard_has_no_hardcoded_sample_data(client):
    body = client.get("/").get_data(as_text=True)

    for marker in ("10.0.0", "192.168", "aa:bb:cc", "example.com"):
        assert marker not in body


def test_dashboard_ships_with_loading_and_empty_states(client):
    body = client.get("/").get_data(as_text=True)

    assert "Loading" in body

    js = client.get("/static/app.js").get_data(as_text=True)
    assert "No alerts recorded yet" in js
    assert "No devices tracked yet" in js
    assert "Could not load data" in js


def test_live_portal_page_is_served(client):
    response = client.get("/live")

    assert response.status_code == 200
    assert "text/html" in response.content_type
    body = response.get_data(as_text=True)
    assert "Live Traffic Portal" in body
    assert 'id="bandwidth-chart"' in body
    assert 'id="protocol-bars"' in body
    assert 'id="talkers-body"' in body


def test_live_portal_script_is_served_and_calls_traffic_api(client):
    js = client.get("/static/live.js")

    assert js.status_code == 200
    assert "javascript" in js.content_type
    body = js.get_data(as_text=True)
    assert "/api/traffic" in body
    assert "/api/health" in body


def test_dashboard_links_to_live_portal(client):
    body = client.get("/").get_data(as_text=True)
    assert 'href="/live"' in body


def test_live_portal_has_no_hardcoded_sample_data(client):
    body = client.get("/live").get_data(as_text=True)

    for marker in ("10.0.0", "192.168", "aa:bb:cc", "example.com"):
        assert marker not in body
