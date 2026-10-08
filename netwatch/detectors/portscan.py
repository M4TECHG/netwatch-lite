from __future__ import annotations

from collections import Counter, defaultdict, deque

from ..mitre import technique
from ..models import Alert, Event
from .base import Detector


class PortScanDetector(Detector):
    """SYN-only probes to many distinct (host, port) targets inside a short window."""

    name = "portscan"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.win = cfg["window_seconds"]
        self.thr = cfg["distinct_targets"]
        self.q = defaultdict(deque)
        self.cnt = defaultdict(Counter)
        self.total = Counter()

    def feed(self, ev: Event) -> None:
        if ev.kind != "tcp" or not ev.src_ip or ev.extra.get("flags") != "S":
            return
        dq, cnt = self.q[ev.src_ip], self.cnt[ev.src_ip]
        tgt = (ev.dst_ip, ev.dport)
        dq.append((ev.ts, tgt))
        cnt[tgt] += 1
        self.total[ev.src_ip] += 1
        while dq and ev.ts - dq[0][0] > self.win:
            _, old = dq.popleft()
            cnt[old] -= 1
            if cnt[old] <= 0:
                del cnt[old]
        if len(cnt) < self.thr:
            return

        hosts = {h for h, _ in cnt}
        ports = {p for _, p in cnt}
        if len(hosts) == 1:
            kind = "vertical scan (many ports on one host)"
        elif len(ports) <= 3:
            kind = "horizontal sweep (few ports across many hosts)"
        else:
            kind = "block scan (many hosts and ports)"
        sev = "high" if len(cnt) >= self.thr * 3 else "medium"
        sample = sorted(ports)[:12]

        def make():
            return Alert(
                rule=self.name,
                severity=sev,
                src=ev.src_ip,
                first_seen=dq[0][0],
                last_seen=ev.ts,
                title=f"Port scan from {ev.src_ip}",
                description=f"{ev.src_ip} sent SYN-only probes to {len(cnt)} distinct targets within "
                f"{self.win}s: {kind}.",
                mitre=[technique("T1046")],
                evidence=[f"hosts={len(hosts)} ports={len(ports)} sample_ports={sample}"],
                recommendation="Verify whether the source is an authorised scanner; otherwise isolate "
                "the host and review firewall logs for follow-up connections.",
            )

        a = self._upsert(self.name + ":" + ev.src_ip, make, ev.ts, count=self.total[ev.src_ip])
        if sev == "high":
            a.severity = "high"
