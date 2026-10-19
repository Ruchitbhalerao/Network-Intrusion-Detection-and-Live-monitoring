"""In-memory deduplication so one ongoing event is not reported repeatedly.

An event is identified by stable fields -- alert type, source and destination
IP, and the source/destination ports -- never by the message or timestamp
alone. The first alert for a key is emitted; further alerts with the same key
are suppressed until the configured ``dedup`` window has passed. State lives
only in memory and never touches the database.
"""


class Deduplicator:
    def __init__(self, config):
        self.window_seconds = config["dedup"]["window_seconds"]
        self._last_seen = {}

    def should_emit(self, alert):
        """Return ``True`` if this alert is new enough to be emitted.

        Also records the alert's timestamp so the next matching alert inside
        the window is suppressed.
        """
        key = self._event_key(alert)
        previous = self._last_seen.get(key)
        if previous is not None and alert.timestamp - previous < self.window_seconds:
            return False
        self._last_seen[key] = alert.timestamp
        return True

    @staticmethod
    def _event_key(alert):
        return (
            alert.alert_type,
            alert.src_ip,
            alert.dst_ip,
            alert.src_port,
            alert.dst_port,
        )
