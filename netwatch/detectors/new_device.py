from __future__ import annotations

from ..mitre import technique
from ..models import Alert, Event
from ..utils import is_unicast_mac
from .base import Detector


class NewDeviceDetector(Detector):
    """Any unicast source MAC that is not in the known-device inventory."""

    name = "new_device"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.known = {m.lower() for m in cfg["known_macs"]}
        self.seen: set[str] = set()

    def feed(self, ev: Event) -> None:
        if not self.known or not is_unicast_mac(ev.src_mac) or ev.src_mac in self.known:
            return
        if ev.src_mac in self.seen:
            self.alerts[f"{self.name}:{ev.src_mac}"].last_seen = ev.ts
            self.alerts[f"{self.name}:{ev.src_mac}"].count += 1
            return
        self.seen.add(ev.src_mac)
        self.alerts[f"{self.name}:{ev.src_mac}"] = Alert(
            rule=self.name,
            severity="low",
            src=ev.src_mac,
            first_seen=ev.ts,
            last_seen=ev.ts,
            title=f"Unknown device {ev.src_mac}",
            description=f"MAC not in inventory (IP seen: {ev.src_ip or 'n/a'}).",
            mitre=[technique("T1200")],
            evidence=[f"ip={ev.src_ip}"],
            recommendation="Identify the owner; add to inventory or disconnect (802.1X / port security).",
        )
