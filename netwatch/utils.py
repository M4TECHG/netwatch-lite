from __future__ import annotations

import logging
import math
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone

MULTI_LABEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "com.tr",
    "co.ir",
    "ac.ir",
    "gov.ir",
    "org.ir",
    "net.ir",
    "co.jp",
    "com.br",
    "co.in",
}


@contextmanager
def scapy_quiet():
    """Import scapy without its optional-libpcap banner.

    Offline PCAP reading does not need libpcap, so the warning is noise for our users.
    Only silences records emitted while the block runs (scapy prints it at import time).
    """
    logging.disable(logging.WARNING)
    try:
        yield
    finally:
        logging.disable(logging.NOTSET)


def silence_scapy() -> None:
    """Keep scapy quiet for the rest of the process (called once after the import)."""
    try:
        import scapy.error as scapy_error

        scapy_error.log_runtime.setLevel(logging.ERROR)
    except Exception:  # noqa: S110 - scapy is always present when this is called
        pass
    for name in ("scapy", "scapy.runtime"):
        logging.getLogger(name).setLevel(logging.ERROR)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def split_domain(fqdn: str) -> tuple[str, str]:
    """Return (registered_domain, subdomain_part) using a simple suffix heuristic."""
    labels = [lb for lb in fqdn.lower().strip(".").split(".") if lb]
    if len(labels) <= 2:
        return ".".join(labels), ""
    take = 3 if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES else 2
    return ".".join(labels[-take:]), ".".join(labels[:-take])


def fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def is_unicast_mac(mac: str | None) -> bool:
    if not mac:
        return False
    mac = mac.lower()
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return False
    try:
        return not (int(mac.split(":")[0], 16) & 1)
    except ValueError:
        return False
