"""Live packet capture wrapper using Scapy.

Capturing packets directly integrates the existing parser, engine, dedup and
database. To keep this stage testable and safe, all live sniffing is optional
and can be stopped cleanly. Callers must explicitly invoke :func:`start_capture`
and stop it later.

Notes (macOS):
- Live capture usually requires access to `/dev/bpf*` (often run as root or
  with network capture permissions). Never run with sudo automatically.
- Monitor mode is not available in normal macOS setups, so you'll typically
  only see traffic to/from your own machine. For development and testing, the
  synthetic workflow is strongly preferred.

The wrapper never auto-starts when imported or during tests.
"""

from threading import Event, Thread

try:
    from scapy.all import sniff
except Exception:  # pragma: no cover - optional dependency at runtime
    sniff = None

from .engine import DetectionEngine
from .parser import parse_packet


class CaptureError(Exception):
    """Raised when packet capture cannot be started or fails."""


class CaptureStopped(Exception):
    """Raised when capture is stopped cleanly."""


class PacketCapture:
    def __init__(self, config, db_path=None, engine=None):
        self.config = config
        self.db_path = db_path
        self.engine = engine or DetectionEngine(config, db_path=db_path)
        self._stop_event = Event()
        self._thread = None
        self._settings = config["capture"]
        self._sniff_func = sniff
        self._exception = None

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self, interface=None, packet_limit=None, timeout=None, sniff_func=None):
        """Start capturing packets."""
        if not self._settings.get("enabled", False):
            return

        if sniff_func is not None:
            self._sniff_func = sniff_func

        if self._sniff_func is None:
            raise CaptureError("Scapy is not available. Install scapy to enable live capture.")

        iface = interface if interface is not None else self._settings.get("interface")
        limit = packet_limit if packet_limit is not None else self._settings.get("packet_limit") or 0
        timeout_s = timeout if timeout is not None else self._settings.get("timeout_seconds") or 0

        self._stop_event.clear()
        self._exception = None
        self._thread = Thread(target=self._run, args=(iface, limit, timeout_s), daemon=True)
        try:
            self._thread.start()
        except Exception as error:
            self._thread = None
            raise CaptureError(f"Packet capture failed: {error}") from error
        import time as _time
        for _ in range(50):
            if not self._thread.is_alive():
                if self._exception is not None:
                    raise self._exception
                break
            _time.sleep(0.001)

    def stop(self, timeout=1.0):
        if not self.is_running():
            return
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            return  # left running intentionally

    def _run(self, interface, packet_limit, timeout_s):
        kwargs = {"stop_filter": lambda pkt=None: self._stop_event.is_set()}
        if interface is not None:
            kwargs["iface"] = interface
        if packet_limit and packet_limit > 0:
            kwargs["count"] = packet_limit
        if timeout_s and timeout_s > 0:
            kwargs["timeout"] = timeout_s

        try:
            def process(pkt):
                if self._stop_event.is_set():
                    raise CaptureStopped()
                record = parse_packet(pkt)
                if record is not None:
                    self.engine.process_record(record)

            self._sniff_func(prn=process, store=False, **kwargs)
        except CaptureStopped:
            pass
        except Exception as error:
            self._exception = CaptureError(f"Packet capture failed: {error}")


def start_capture(config, db_path=None, engine=None, **kwargs):
    capture = PacketCapture(config, db_path=db_path, engine=engine)
    capture.start(**kwargs)
    return capture
