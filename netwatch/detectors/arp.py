from __future__ import annotations

from collections import defaultdict

from ..mitre import technique
from ..models import Alert, Event
from .base import Detector


class ArpSpoofDetector(Detector):
    """IP->MAC binding changes and one MAC claiming many IPs."""

    name = "arp"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.gateways = set(cfg["gateways"])
        self.ignore = {m.lower() for m in cfg["ignore_macs"]}
        self.bind: dict[str, str] = {}
        self.first_ts: dict[str, float] = {}
        self.mac_ips = defaultdict(set)
        self.changes = defaultdict(int)

    def feed(self, ev: Event) -> None:
        if ev.kind != "arp" or not ev.src_ip or ev.src_ip == "0.0.0.0" or not ev.src_mac:  # noqa: S104
            return
        if ev.src_mac in self.ignore:
            return
        ip, mac = ev.src_ip, ev.src_mac
        if ev.extra.get("op") == "reply":
            self.mac_ips[mac].add(ip)

        known = self.bind.get(ip)
        if known is None:
            self.bind[ip], self.first_ts[ip] = mac, ev.ts
        elif known != mac:
            self.changes[ip] += 1
            crit = ip in self.gateways
            self._upsert(
                f"{self.name}:bind:{ip}",
                lambda: Alert(
                    rule=self.name,
                    severity="critical" if crit else "high",
                    src=mac,
                    first_seen=ev.ts,
                    last_seen=ev.ts,
                    title=f"ARP spoofing: {ip} changed MAC {known} -> {mac}",
                    description=f"{ip} was first bound to {known} but {mac} now claims it"
                    + (" (configured gateway: likely man-in-the-middle)." if crit else "."),
                    mitre=[technique("T1557.002")],
                    evidence=[f"original={known}", f"new={mac}"],
                    recommendation="Enable Dynamic ARP Inspection / port security on the switch and verify "
                    "which port the new MAC is on.",
                ),
                ev.ts,
                count=self.changes[ip] + 1,
            )

        if len(self.mac_ips[mac]) >= self.cfg["ips_per_mac"]:
            n = len(self.mac_ips[mac])
            self._upsert(
                f"{self.name}:many:{mac}",
                lambda: Alert(
                    rule=self.name,
                    severity="medium",
                    src=mac,
                    first_seen=ev.ts,
                    last_seen=ev.ts,
                    title=f"MAC {mac} answers ARP for {n} different IPs",
                    description="Possible ARP poisoning sweep (or legitimate proxy ARP / router).",
                    mitre=[technique("T1557.002")],
                    evidence=sorted(self.mac_ips[mac])[:8],
                    recommendation="Confirm the device is a router/firewall; otherwise isolate it.",
                ),
                ev.ts,
                count=n,
            )
