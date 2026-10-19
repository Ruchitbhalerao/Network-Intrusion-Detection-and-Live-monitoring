from nids.dedup import Deduplicator
from nids.models import Alert


def make_alert(
    alert_type="port_scan",
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    src_port=40000,
    dst_port=80,
    timestamp=0.0,
    message="possible event",
):
    return Alert(
        alert_type=alert_type,
        severity="high",
        message=message,
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
    )


def test_identical_ongoing_alert_is_suppressed(config):
    dedup = Deduplicator(config)

    assert dedup.should_emit(make_alert(timestamp=0.0)) is True
    assert dedup.should_emit(make_alert(timestamp=1.0)) is False
    assert dedup.should_emit(make_alert(timestamp=2.0)) is False


def test_different_alert_types_are_independent(config):
    dedup = Deduplicator(config)

    assert dedup.should_emit(make_alert(alert_type="port_scan", timestamp=0.0)) is True
    assert dedup.should_emit(make_alert(alert_type="traffic_anomaly", timestamp=1.0)) is True


def test_different_endpoints_are_independent(config):
    dedup = Deduplicator(config)

    assert dedup.should_emit(make_alert(src_ip="10.0.0.1", timestamp=0.0)) is True
    assert dedup.should_emit(make_alert(src_ip="10.0.0.9", timestamp=1.0)) is True
    assert dedup.should_emit(make_alert(dst_ip="10.0.0.8", timestamp=2.0)) is True
    assert dedup.should_emit(make_alert(dst_port=443, timestamp=3.0)) is True
    assert dedup.should_emit(make_alert(src_port=1234, timestamp=4.0)) is True


def test_same_source_different_destination_is_independent(config):
    dedup = Deduplicator(config)

    assert dedup.should_emit(make_alert(dst_ip="10.0.0.2", timestamp=0.0)) is True
    assert dedup.should_emit(make_alert(dst_ip="10.0.0.3", timestamp=1.0)) is True


def test_alert_accepted_again_after_window(config):
    config["dedup"]["window_seconds"] = 10
    dedup = Deduplicator(config)

    assert dedup.should_emit(make_alert(timestamp=0.0)) is True
    assert dedup.should_emit(make_alert(timestamp=5.0)) is False
    assert dedup.should_emit(make_alert(timestamp=10.0)) is True
    assert dedup.should_emit(make_alert(timestamp=15.0)) is False


def test_identity_ignores_message_and_timestamp_alone(config):
    dedup = Deduplicator(config)

    assert dedup.should_emit(make_alert(timestamp=0.0, message="first")) is True
    assert dedup.should_emit(make_alert(timestamp=1.0, message="different text")) is False
