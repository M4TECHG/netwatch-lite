from __future__ import annotations

from collections import defaultdict, deque

from ..mitre import technique
from ..models import Alert, Event
from .base import Detector


class BruteForceDetector(Detector):
    """Failed-login bursts (auth logs), password spraying, success-after-failures,
    and a connection-rate heuristic for auth ports seen in PCAPs."""

    name = "bruteforce"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.win = cfg["window_seconds"]
        self.fail_thr = cfg["failed_logins"]
        self.spray_thr = cfg["spray_users"]
        self.ports = set(cfg["auth_ports"])
        self.conn_thr = cfg["connection_attempts"]
        self.fails = defaultdict(deque)  # (src, service) -> deque[(ts, user)]
        self.conns = defaultdict(deque)  # (src, dst, port) -> deque[ts]
        self.total_fail = defaultdict(int)

    def feed(self, ev: Event) -> None:
        if ev.kind == "auth":
            self._auth(ev)
        elif ev.kind == "tcp" and ev.extra.get("flags") == "S" and ev.dport in self.ports:
            self._conn(ev)

    def _auth(self, ev: Event) -> None:
        key = (ev.src_ip, ev.extra["service"])
        dq = self.fails[key]
        while dq and ev.ts - dq[0][0] > self.win:
            dq.popleft()

        if not ev.extra["success"]:
            dq.append((ev.ts, ev.extra["user"]))
            self.total_fail[key] += 1
            if len(dq) < self.fail_thr:
                return
            users = {u for _, u in dq}
            spray = len(users) >= self.spray_thr
            tid = "T1110.003" if spray else "T1110"
            label = "Password spraying" if spray else "Brute-force"

            def make():
                return Alert(
                    rule=self.name,
                    severity="high",
                    src=ev.src_ip,
                    first_seen=dq[0][0],
                    last_seen=ev.ts,
                    title=f"{label} against {ev.extra['service'].upper()} from {ev.src_ip}",
                    description=f"{len(dq)} failed logins in {self.win}s targeting {len(users)} account(s).",
                    mitre=[technique(tid)],
                    evidence=[f"users={sorted(users)[:8]}"],
                    recommendation="Block the source, enforce lockout / MFA, and review accounts that "
                    "were targeted.",
                )

            self._upsert(f"{self.name}:auth:{key}", make, ev.ts, count=self.total_fail[key])
        else:
            prior = self.alerts.get(f"{self.name}:auth:{key}")
            if prior is not None:
                self._upsert(
                    f"{self.name}:success:{key}",
                    lambda: Alert(
                        rule=self.name,
                        severity="critical",
                        src=ev.src_ip,
                        first_seen=ev.ts,
                        last_seen=ev.ts,
                        title=(
                            f"Successful {ev.extra['service'].upper()} login after brute "
                            f"force from {ev.src_ip}"
                        ),
                        description=f"Account '{ev.extra['user']}' authenticated successfully after "
                        f"{self.total_fail[key]} failures from the same source.",
                        mitre=[technique("T1110"), technique("T1078")],
                        evidence=[f"user={ev.extra['user']}"],
                        recommendation="Treat the account as compromised: reset credentials, kill active "
                        "sessions and audit activity after this timestamp.",
                    ),
                    ev.ts,
                )

    def _conn(self, ev: Event) -> None:
        key = (ev.src_ip, ev.dst_ip, ev.dport)
        dq = self.conns[key]
        dq.append(ev.ts)
        while dq and ev.ts - dq[0] > self.win:
            dq.popleft()
        if len(dq) < self.conn_thr:
            return
        self._upsert(
            f"{self.name}:conn:{key}",
            lambda: Alert(
                rule=self.name,
                severity="medium",
                src=ev.src_ip,
                first_seen=dq[0],
                last_seen=ev.ts,
                title=f"Possible brute force on {ev.dst_ip}:{ev.dport} from {ev.src_ip}",
                description=f"{len(dq)} new TCP connections to an authentication port within {self.win}s "
                "(connection-rate heuristic, no auth log available).",
                mitre=[technique("T1110")],
                evidence=[f"dst={ev.dst_ip}:{ev.dport}"],
                recommendation="Correlate with the target host's authentication logs.",
            ),
            ev.ts,
            count=len(dq),
        )
