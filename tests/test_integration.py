import json

import pytest

pytest.importorskip("scapy")

from netwatch.engine import run
from netwatch.parsers.authlog import parse_auth_file
from netwatch.report.exporters import to_html, to_json, to_splunk_hec
from netwatch.samples import generate


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    out = tmp_path_factory.mktemp("demo")
    pcap, auth, inv = generate(out)
    return run([str(pcap), str(auth)], inventory=str(inv), year=2026)


def test_all_attack_classes_detected(result):
    titles = " | ".join(a.title for a in result.alerts)
    for needle in (
        "Port scan",
        "ARP spoofing",
        "DNS tunnelling",
        "DGA-like",
        "DHCP",
        "Successful SSH login",
        "Unknown device",
    ):
        assert needle in titles, needle


def test_no_alert_for_baseline_host(result):
    assert not [a for a in result.alerts if a.src == "192.168.10.20"]


def test_reports(result):
    for lang in ("en", "fa"):
        html = to_html(result, lang)
        assert "T1046" in html and "NW-0001" in html
    assert 'dir="rtl"' in to_html(result, "fa")
    assert json.loads(to_json(result))["alerts"]
    lines = to_splunk_hec(result, "https://x", "t", dry_run=True).strip().splitlines()
    assert json.loads(lines[0])["sourcetype"] == "netwatch:alert"


def test_syslog_parser(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text(
        "Oct  5 10:00:01 h sshd[1]: Failed password for invalid user bob from 1.2.3.4 port 22 ssh2\n"
        "Oct  5 10:00:09 h sshd[1]: Accepted password for bob from 1.2.3.4 port 22 ssh2\n"
    )
    ev = list(parse_auth_file(f, year=2026))
    assert [e.extra["success"] for e in ev] == [False, True] and ev[0].src_ip == "1.2.3.4"
