from __future__ import annotations

from collections import Counter, defaultdict, deque

from ..mitre import technique
from ..models import Alert, Event
from ..utils import shannon_entropy, split_domain
from .base import Detector

VOWELS = set("aeiou")


class DnsDetector(Detector):
    """DGA-like high-entropy names and DNS tunnelling (many unique subdomains, long names, TXT/NULL abuse)."""

    name = "dns"

    def __init__(self, cfg):
        super().__init__(cfg)
        self.c = cfg
        self.allow = tuple(cfg["allowlist"])
        self.win = cfg["window_seconds"]
        self.subs = defaultdict(deque)  # (src, reg_domain) -> deque[(ts, fqdn, qtype)]
        self.dga_hits = defaultdict(dict)
        self.reg_hits = Counter()
        self.dga_first = {}

    def _looks_random(self, label: str) -> bool:
        # hyphenated names (e.g. "sobhgheshlagh-products") are judged part by part
        if "-" in label:
            return any(self._looks_random(part) for part in label.split("-"))
        if len(label) < self.c["min_label_length"]:
            return False
        if shannon_entropy(label) < self.c["entropy_threshold"]:
            return False
        digits = sum(ch.isdigit() for ch in label) / len(label)
        letters = [ch for ch in label if ch.isalpha()]
        vowel_ratio = (sum(ch in VOWELS for ch in letters) / len(letters)) if letters else 0
        return digits >= 0.15 or vowel_ratio < 0.28

    def feed(self, ev: Event) -> None:
        if ev.kind != "dns":
            return
        fqdn = ev.extra["qname"]
        if fqdn.endswith((".arpa", ".local")) or fqdn.endswith(self.allow):
            return
        reg, _sub = split_domain(fqdn)
        if not reg:
            return
        suffix_len = len(reg.split(".")) - 1  # TLD labels contained in `reg`
        candidates = fqdn.split(".")[:-suffix_len] if suffix_len else fqdn.split(".")
        longest = max(candidates, key=len, default="")

        # 1) DGA-like names: many *distinct* registered domains, each queried only a few times
        if self._looks_random(longest):
            self.reg_hits[(ev.src_ip, reg)] += 1
            self.dga_first.setdefault(ev.src_ip, ev.ts)
            self.dga_hits[ev.src_ip].setdefault(reg, fqdn)
            doms = [d for d, f in self.dga_hits[ev.src_ip].items() if self.reg_hits[(ev.src_ip, d)] <= 5]
            if len(doms) >= 3:
                self._upsert(
                    f"{self.name}:dga:{ev.src_ip}",
                    lambda: Alert(
                        rule=self.name,
                        severity="medium",
                        src=ev.src_ip,
                        first_seen=self.dga_first[ev.src_ip],
                        last_seen=ev.ts,
                        count=len(doms),
                        title=f"DGA-like domain lookups from {ev.src_ip}",
                        description=f"{len(doms)} distinct domains with random-looking names were queried "
                        "(high Shannon entropy).",
                        mitre=[technique("T1568.002")],
                        evidence=[self.dga_hits[ev.src_ip][d] for d in doms[:5]],
                        recommendation="Check the host for malware; sinkhole the domains at the resolver.",
                    ),
                    ev.ts,
                    count=len(doms),
                )

        # 2) Tunnelling: window of queries per (src, registered domain)
        key = (ev.src_ip, reg)
        dq = self.subs[key]
        dq.append((ev.ts, fqdn, ev.extra["qtype"]))
        while dq and ev.ts - dq[0][0] > self.win:
            dq.popleft()
        uniq = len({q for _, q, _ in dq})
        avg_len = sum(len(q) for _, q, _ in dq) / len(dq)
        txt = sum(1 for _, _, t in dq if t in ("TXT", "NULL"))
        reasons = []
        if uniq >= self.c["unique_subdomains"]:
            reasons.append(f"{uniq} unique names in {self.win}s")
        if len(dq) >= 20 and avg_len >= self.c["avg_query_length"]:
            reasons.append(f"avg query length {avg_len:.0f}")
        if txt >= self.c["txt_null_queries"]:
            reasons.append(f"{txt} TXT/NULL queries")
        if reasons:
            self._upsert(
                f"{self.name}:tunnel:{key}",
                lambda: Alert(
                    rule=self.name,
                    severity="high",
                    src=ev.src_ip,
                    first_seen=dq[0][0],
                    last_seen=ev.ts,
                    title=f"Possible DNS tunnelling to {reg} from {ev.src_ip}",
                    description="; ".join(reasons) + ".",
                    mitre=[technique("T1071.004"), technique("T1048")],
                    evidence=[q for _, q, _ in list(dq)[:4]],
                    recommendation="Block or sinkhole the domain and inspect the host for tunnelling tools "
                    "(iodine, dnscat2).",
                ),
                ev.ts,
                count=len(dq),
            )
