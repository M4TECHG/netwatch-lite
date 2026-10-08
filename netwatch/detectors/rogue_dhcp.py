from __future__ import annotations

from collections import Counter

from ..mitre import technique
from ..models import Alert, Event
from .base import Detector


class RogueDhcpDetector(Detector):
    """DHCP offers/acks from servers that are not on the allow-list (or >1 server if no list)."""

    name = "rogue_dhcp"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.allowed = set(cfg["allowed_servers"])
        self.servers: dict[str, dict] = {}
        self.counts = Counter()

    def feed(self, ev: Event) -> None:
        if ev.kind != "dhcp" or ev.extra.get("msg") not in ("offer", "ack", "nak"):
            return
        srv = ev.extra["server_ip"]
        self.counts[srv] += 1
        info = self.servers.setdefault(srv, {"mac": ev.src_mac, "first": ev.ts})

        if self.allowed:
            if srv in self.allowed:
                return
            self._upsert(
                f"{self.name}:{srv}",
                lambda: Alert(
                    rule=self.name,
                    severity="high",
                    src=srv,
                    first_seen=ev.ts,
                    last_seen=ev.ts,
                    title=f"Rogue DHCP server {srv}",
                    description=(
                        f"DHCP {ev.extra['msg']} from {srv} (MAC {info['mac']}) "
                        "which is not in allowed_servers."
                    ),
                    mitre=[technique("T1557.003")],
                    evidence=[f"mac={info['mac']}"],
                    recommendation="Enable DHCP snooping on access switches and remove the device.",
                ),
                ev.ts,
                count=self.counts[srv],
            )
        elif len(self.servers) >= 2:
            names = sorted(self.servers)
            self._upsert(
                f"{self.name}:multi",
                lambda: Alert(
                    rule=self.name,
                    severity="medium",
                    src=",".join(names),
                    first_seen=ev.ts,
                    last_seen=ev.ts,
                    title="Multiple DHCP servers answering on the same network",
                    description=(
                        f"Servers seen: {', '.join(names)}. Set allowed_servers to pinpoint the rogue one."
                    ),
                    mitre=[technique("T1557.003")],
                    evidence=[f"{s} mac={v['mac']}" for s, v in sorted(self.servers.items())],
                    recommendation="Identify the unauthorised server and enable DHCP snooping.",
                ),
                ev.ts,
                count=sum(self.counts.values()),
            )
