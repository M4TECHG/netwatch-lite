from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from ..models import Event

SYSLOG_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})")
SSH_FAIL = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[\d.]+)"
)
SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")
SSH_OK = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.]+)")


def _syslog_ts(line: str, year: int) -> float | None:
    m = SYSLOG_TS.match(line)
    if not m:
        return None
    dt = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc).timestamp()  # syslog has no TZ: treated as UTC


def _parse_ts(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _auth_event(ts: float, service: str, user: str, ip: str, success: bool) -> Event:
    return Event(ts, "auth", src_ip=ip, extra={"service": service, "user": user, "success": success})


def parse_auth_file(path, year: int | None = None) -> Iterator[Event]:
    """Supports: OpenSSH syslog (auth.log/secure), CSV (ts,service,user,src_ip,result), JSON lines."""
    p = Path(path)
    year = year or datetime.now().year
    suffix = p.suffix.lower()

    if suffix == ".csv":
        with open(p, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                ok = row["result"].strip().lower() in ("success", "ok", "accepted", "4624")
                yield _auth_event(
                    _parse_ts(row["ts"]),
                    row.get("service", "unknown"),
                    row.get("user", ""),
                    row["src_ip"],
                    ok,
                )
        return

    if suffix in (".jsonl", ".json"):
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    r = json.loads(line)
                    ok = str(r.get("result", "")).lower() in ("success", "ok", "accepted", "4624")
                    yield _auth_event(
                        _parse_ts(str(r["ts"])),
                        r.get("service", "unknown"),
                        r.get("user", ""),
                        r["src_ip"],
                        ok,
                    )
        return

    with open(p, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            ts = _syslog_ts(line, year)
            if ts is None or "sshd" not in line:
                continue
            for rx, ok in ((SSH_FAIL, False), (SSH_INVALID, False), (SSH_OK, True)):
                m = rx.search(line)
                if m:
                    yield _auth_event(ts, "ssh", m["user"], m["ip"], ok)
                    break
