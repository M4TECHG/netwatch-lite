from netwatch.config import DEFAULTS, deep_merge
from netwatch.engine import analyze_events
from netwatch.models import Event


def run(events, **over):
    cfg = deep_merge(DEFAULTS, over)
    alerts, _, _ = analyze_events(sorted(events, key=lambda e: e.ts), cfg)
    return alerts


def syn(t, src, dst, port):
    return Event(t, "tcp", src_ip=src, dst_ip=dst, dport=port, extra={"flags": "S"})


def test_portscan_detected_and_deduplicated():
    ev = [syn(i * 0.1, "10.0.0.9", "10.0.0.5", p) for p in range(1, 101) for i in [p]]
    alerts = [a for a in run(ev) if a.rule == "portscan"]
    assert len(alerts) == 1 and alerts[0].mitre[0]["id"] == "T1046" and alerts[0].count == 100


def test_normal_web_traffic_is_quiet():
    ev = [syn(i, "10.0.0.9", "10.0.0.5", 443) for i in range(200)]
    assert not [a for a in run(ev) if a.rule == "portscan"]


def auth(t, ip, user, ok):
    return Event(t, "auth", src_ip=ip, extra={"service": "ssh", "user": user, "success": ok})


def test_bruteforce_then_success_is_critical():
    ev = [auth(i, "1.2.3.4", "root", False) for i in range(10)] + [auth(11, "1.2.3.4", "root", True)]
    sev = {a.severity for a in run(ev) if a.rule == "bruteforce"}
    assert "critical" in sev and "high" in sev


def test_few_failures_do_not_alert():
    assert not run([auth(i, "1.2.3.4", "alice", False) for i in range(3)])


def test_spraying_label():
    users = ["a", "b", "c", "d", "e", "f", "g", "h"]
    alerts = run([auth(i, "9.9.9.9", u, False) for i, u in enumerate(users)])
    assert alerts[0].mitre[0]["id"] == "T1110.003"


def dns(t, name, qtype="A", src="10.0.0.7"):
    return Event(t, "dns", src_ip=src, extra={"qname": name, "qtype": qtype})


def test_dns_tunnel():
    ev = [dns(i * 0.2, f"{'x' * 3}{i:04d}abcdefghijklmnop.t.bad.example", "TXT") for i in range(60)]
    assert any("tunnelling" in a.title for a in run(ev))


def test_dns_legit_names_quiet():
    names = ["www.google.com", "github.com", "mail.example.ir", "pypi.org"] * 20
    assert not run([dns(i, n) for i, n in enumerate(names)])


def test_dga_needs_multiple_domains():
    import random

    r = random.Random(1)

    def gen() -> str:
        return "".join(r.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(18)) + ".com"

    assert not [a for a in run([dns(0, gen())]) if a.rule == "dns"]
    assert [a for a in run([dns(i, gen()) for i in range(5)]) if a.rule == "dns"]


def arp(t, ip, mac, op="reply"):
    return Event(t, "arp", src_ip=ip, src_mac=mac, extra={"op": op})


def test_arp_gateway_spoof_is_critical():
    alerts = run(
        [arp(0, "10.0.0.1", "aa:aa:aa:aa:aa:01"), arp(5, "10.0.0.1", "de:ad:be:ef:00:66")],
        arp={"gateways": ["10.0.0.1"]},
    )
    assert alerts[0].severity == "critical"


def test_arp_stable_binding_quiet():
    assert not run([arp(i, "10.0.0.1", "aa:aa:aa:aa:aa:01") for i in range(10)])


def dhcp(t, srv):
    return Event(t, "dhcp", src_ip=srv, src_mac="aa:00:00:00:00:01", extra={"msg": "offer", "server_ip": srv})


def test_rogue_dhcp_with_allowlist():
    alerts = run([dhcp(0, "10.0.0.2"), dhcp(1, "10.0.0.66")], rogue_dhcp={"allowed_servers": ["10.0.0.2"]})
    assert len(alerts) == 1 and alerts[0].src == "10.0.0.66" and alerts[0].severity == "high"


def test_new_device():
    ev = [
        Event(0, "ip", src_ip="10.0.0.3", src_mac="02:11:22:33:44:55"),
        Event(1, "ip", src_ip="10.0.0.4", src_mac="aa:aa:aa:aa:aa:01"),
    ]
    alerts = run(ev, new_device={"known_macs": ["aa:aa:aa:aa:aa:01"]})
    assert [a.src for a in alerts] == ["02:11:22:33:44:55"]
