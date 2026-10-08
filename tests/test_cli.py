import json

import pytest

pytest.importorskip("scapy")

from netwatch.cli import EXIT_ALERT, EXIT_ERROR, EXIT_INTERRUPTED, EXIT_OK, UI, main
from netwatch.report.exporters import to_csv, to_webhook


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    out = tmp_path_factory.mktemp("demo")
    from netwatch.samples import generate

    pcap, auth, inv = generate(out)
    return out, [str(pcap), str(auth)], str(inv)


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "netwatch-lite" in capsys.readouterr().out


def test_version_flag_after_subcommand(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["demo", "--version"])
    assert exc.value.code == 0
    assert "netwatch-lite" in capsys.readouterr().out


def test_usage_error_exits_one_not_two(capsys):
    """argparse defaults to 2, which would collide with the --fail-on contract."""
    with pytest.raises(SystemExit) as exc:
        main(["analyze"])
    assert exc.value.code == EXIT_ERROR


def test_missing_file_is_friendly(capsys):
    assert main(["analyze", "does-not-exist.pcap"]) == EXIT_ERROR
    assert "file not found" in capsys.readouterr().err


def test_demo_quiet_is_machine_readable(demo, tmp_path, capsys):
    code = main(["demo", "--out", str(tmp_path / "d"), "--lang", "fa", "--quiet"])
    assert code == EXIT_OK
    assert capsys.readouterr().out.split() == ["317", "9"]  # events + alerts, nothing else
    assert (tmp_path / "d" / "report.html").exists()


def test_demo_writes_both_reports(demo, tmp_path, capsys):
    assert main(["demo", "--out", str(tmp_path / "d"), "--lang", "fa"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "report.html" in out and "317" in out
    assert (tmp_path / "d" / "report.json").exists()


def test_analyze_exit_codes_and_outputs(demo, tmp_path, capsys):
    _, files, inv = demo
    j = tmp_path / "report.json"
    c = tmp_path / "alerts.csv"
    code = main(
        [
            "analyze",
            *files,
            "--inventory",
            inv,
            "--year",
            "2026",
            "--fail-on",
            "high",
            "--json",
            str(j),
            "--csv",
            str(c),
            "--quiet",
        ]
    )
    assert code == EXIT_ALERT
    payload = json.loads(j.read_text(encoding="utf-8"))
    assert payload["tool"] == "netwatch-lite" and payload["alerts"]
    rows = c.read_text(encoding="utf-8").splitlines()
    assert rows[0].startswith("id,severity,rule") and len(rows) > 1


def test_fail_on_critical_passes_on_clean_input(tmp_path):
    """A benign log stays at exit 0 even with the strictest threshold."""
    log = tmp_path / "clean.log"
    log.write_text(
        "Oct  5 10:00:01 h sshd[1]: Accepted password for bob from 1.2.3.4 port 22 ssh2\n", encoding="utf-8"
    )
    assert main(["analyze", str(log), "--year", "2026", "--fail-on", "critical", "-q"]) == EXIT_OK


def test_min_severity_filters_console(demo, capsys):
    _, files, inv = demo
    main(["analyze", *files, "--inventory", inv, "--year", "2026", "--min-severity", "critical"])
    out = capsys.readouterr().out
    assert "CRITICAL" in out and "NW-0009" not in out


def test_verbose_prints_progress(demo, capsys):
    _, files, inv = demo
    main(["analyze", *files, "--inventory", inv, "--year", "2026", "--verbose", "-q"])
    assert "parsing" not in capsys.readouterr().out  # quiet wins over verbose output


def test_no_output_flags_still_succeeds(demo):
    _, files, inv = demo
    assert main(["analyze", *files, "--inventory", inv, "--year", "2026", "-q"]) == EXIT_OK


def test_splunk_requires_token(demo, capsys):
    _, files, inv = demo
    assert (
        main(
            [
                "analyze",
                *files,
                "--inventory",
                inv,
                "--year",
                "2026",
                "--splunk-url",
                "https://x:8088/services/collector/event",
            ]
        )
        == EXIT_ERROR
    )
    assert "--splunk-token" in capsys.readouterr().err


def test_webhook_dry_run(demo, capsys):
    from netwatch.engine import run

    _, files, inv = demo
    result = run(files, inventory=inv, year=2026)
    body = to_webhook(result, "https://example.invalid/hook", dry_run=True)
    assert json.loads(body)["alerts"]


def test_to_csv_quotes_commas(demo):
    from netwatch.engine import run

    _, files, inv = demo
    result = run(files, inventory=inv, year=2026)
    assert to_csv(result).splitlines()[0].startswith("id,severity")


def test_keyboard_interrupt_maps_to_130(monkeypatch):
    monkeypatch.setattr("netwatch.cli.run", lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert main(["analyze", __file__]) == EXIT_INTERRUPTED


def test_ui_respects_no_color(monkeypatch, capsys):
    monkeypatch.setenv("NO_COLOR", "1")
    ui = UI()
    ui.out(ui.sev("critical"))
    assert "\033[" not in capsys.readouterr().out


def test_force_color_zero_disables_colour(monkeypatch, capsys):
    """FORCE_COLOR=0 means off; a truthy-looking string must not force colours on."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "0")
    UI().out(UI().sev("critical"))
    assert "\033[" not in capsys.readouterr().out


def test_force_color_one_enables_colour(monkeypatch, capsys):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    UI().out(UI().sev("critical"))
    assert "\033[" in capsys.readouterr().out
