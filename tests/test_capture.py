from types import SimpleNamespace

import pytest

from nids.capture import CaptureError, PacketCapture, start_capture
from nids.config import load_config
from nids.models import PacketRecord


class DummyEngine:
    def __init__(self):
        self.records = []

    def process_record(self, record):
        self.records.append(record)
        return []


@pytest.fixture
def base_config(write_config):
    cfg = load_config(write_config({}))
    cfg["capture"]["enabled"] = True
    cfg["capture"]["interface"] = "lo0"
    cfg["capture"]["packet_limit"] = 0
    return cfg


def test_start_capture_returns_instance_and_stores_engine(base_config, tmp_path):
    engine = DummyEngine()

    class FakeSniff:
        def __call__(self, prn=None, store=False, **kwargs):
            return []

    capture = start_capture(
        base_config,
        db_path=tmp_path / "nids.db",
        engine=engine,
        sniff_func=FakeSniff(),
    )
    assert isinstance(capture, PacketCapture)
    assert capture.engine is engine
    capture.stop()


def test_parsed_packets_forwarded_to_engine(base_config, tmp_path):
    engine = DummyEngine()
    capture = PacketCapture(base_config, db_path=tmp_path / "nids.db", engine=engine)

    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    packet = Ether(src="aa:bb:cc:dd:ee:ff") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)
    packet.time = 100.0

    class FakeSniff:
        def __call__(self, prn=None, store=False, stop_filter=None, **kwargs):
            assert kwargs["iface"] == "lo0"
            assert store is False
            prn(packet)
            return [packet]

    capture.start(sniff_func=FakeSniff())
    capture.stop(timeout=0.5)

    assert len(engine.records) == 1
    assert isinstance(engine.records[0], PacketRecord)
    assert engine.records[0].src_ip == "10.0.0.1"


def test_unparseable_packets_are_ignored(base_config, tmp_path):
    engine = DummyEngine()
    capture = PacketCapture(base_config, db_path=tmp_path / "nids.db", engine=engine)

    class Junk:
        haslayer = False

    class FakeSniff:
        def __call__(self, prn=None, store=False, **kwargs):
            prn(Junk())
            return [Junk()]

    capture.start(sniff_func=FakeSniff())
    capture.stop()

    assert engine.records == []


def test_capture_disabled_does_not_start_sniff(base_config, tmp_path):
    base_config["capture"]["enabled"] = False
    engine = DummyEngine()

    class FakeSniff:
        def __init__(self):
            self.called = False

        def __call__(self, *args, **kwargs):
            self.called = True
            return []

    fake = FakeSniff()
    capture = PacketCapture(base_config, db_path=tmp_path / "nids.db", engine=engine)
    capture.start(sniff_func=fake)

    assert fake.called is False
    assert capture.is_running() is False


def test_interface_and_limits_passed_to_sniff(base_config, tmp_path):
    base_config["capture"]["interface"] = "en0"
    base_config["capture"]["packet_limit"] = 5
    base_config["capture"]["timeout_seconds"] = 2
    engine = DummyEngine()
    capture = PacketCapture(base_config, db_path=tmp_path / "nids.db", engine=engine)

    class FakeSniff:
        def __call__(self, prn=None, store=False, stop_filter=None, **kwargs):
            assert kwargs["iface"] == "en0"
            assert kwargs["count"] == 5
            assert kwargs["timeout"] == 2
            assert store is False
            return []

    capture.start(sniff_func=FakeSniff())
    capture.stop()


def test_override_arguments_take_precedence(base_config, tmp_path):
    engine = DummyEngine()
    capture = PacketCapture(base_config, db_path=tmp_path / "nids.db", engine=engine)

    class FakeSniff:
        def __call__(self, prn=None, store=False, **kwargs):
            assert kwargs["iface"] == "utun0"
            assert kwargs["count"] == 3
            assert kwargs["timeout"] == 1.5
            return []

    capture.start(interface="utun0", packet_limit=3, timeout=1.5, sniff_func=FakeSniff())
    capture.stop()


def test_invalid_interface_exception_raised(base_config, tmp_path):
    engine = DummyEngine()
    capture = PacketCapture(base_config, db_path=tmp_path / "nids.db", engine=engine)

    class FakeSniff:
        def __call__(self, **kwargs):
            raise RuntimeError("no such interface")

    with pytest.raises(CaptureError, match="Packet capture failed"):
        capture.start(sniff_func=FakeSniff())
    capture.stop()


def test_permission_denied_is_reported_as_capture_error(base_config, tmp_path):
    engine = DummyEngine()
    capture = PacketCapture(base_config, db_path=tmp_path / "nids.db", engine=engine)

    class PermissionSniff:
        def __call__(self, **kwargs):
            raise PermissionError("Permission denied: could not open /dev/bpf0")

    with pytest.raises(CaptureError, match="Packet capture failed"):
        capture.start(sniff_func=PermissionSniff())

    assert capture.is_running() is False
    with pytest.raises(CaptureError, match="Permission denied"):
        raise capture._exception


def test_scapy_unavailable_raises(base_config, tmp_path):
    engine = DummyEngine()
    capture = PacketCapture(base_config, db_path=tmp_path / "nids.db", engine=engine)
    capture._sniff_func = None

    with pytest.raises(CaptureError, match="Scapy is not available"):
        capture.start()


def test_stop_clears_stop_event(base_config, tmp_path):
    engine = DummyEngine()
    capture = PacketCapture(base_config, db_path=tmp_path / "nids.db", engine=engine)
    assert not capture.is_running()

    class SlowSniff:
        def __call__(self, prn=None, store=False, stop_filter=None, **kwargs):
            while stop_filter() is False:
                pass
            return []

    capture.start(sniff_func=SlowSniff())
    assert capture.is_running()
    capture.stop(timeout=0.5)
    assert not capture.is_running()
