from __future__ import annotations

from ..models import Alert, Event


class Detector:
    """Streaming detector: feed() every event in time order, then collect alerts."""

    name = "base"

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.alerts: dict[str, Alert] = {}

    def feed(self, ev: Event) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def finalize(self) -> list[Alert]:
        return list(self.alerts.values())

    def _upsert(self, key: str, make_alert, ts: float, count: int | None = None) -> Alert:
        """Create the alert on first hit; afterwards just extend it (keeps output deduplicated)."""
        a = self.alerts.get(key)
        if a is None:
            a = make_alert()
            self.alerts[key] = a
        else:
            a.last_seen = ts
            a.count = count if count is not None else a.count + 1
        return a
