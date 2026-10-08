from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .engine import Result, run
from .models import SEVERITIES, sev_rank
from .report.exporters import to_csv, to_html, to_json, to_splunk_hec, to_webhook
from .utils import fmt_ts

# Exit codes are part of the contract (documented in --help and README).
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_ALERT = 2  # an alert reached --fail-on
EXIT_INTERRUPTED = 130

SEV_COLOR = {"info": "37", "low": "36", "medium": "33", "high": "31", "critical": "1;41"}

EPILOG = """\
examples:
  netwatch demo --out demo_output --lang fa
  netwatch analyze capture.pcap auth.log --inventory inventory.csv -c rules/default.yaml \\
      --html report.html --json report.json --lang fa --fail-on high
  netwatch analyze capture.pcap --csv alerts.csv --webhook-url https://hooks.example/abc

exit codes:
  0   finished, no alert reached the --fail-on threshold
  1   bad input / runtime error
  2   an alert reached the --fail-on threshold (use this in CI)
  130 interrupted by Ctrl+C

environment:
  NO_COLOR   disable ANSI colours (https://no-color.org)
  FORCE_COLOR  colour even when stdout is not a terminal
"""


def _want_color() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    force = os.environ.get("FORCE_COLOR")
    if force is not None:  # FORCE_COLOR=0 / "" / false means "off", anything else means on
        return force.strip().lower() not in {"", "0", "false", "no"}
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _enable_windows_ansi() -> None:
    """Turn on VT processing so colours work in cmd.exe / PowerShell on Windows 10+."""
    if os.name != "nt":
        return
    try:
        import ctypes

        k32 = ctypes.windll.kernel32
        for handle in (-11, -12):  # STDOUT, STDERR
            mode = ctypes.c_uint32()
            if k32.GetConsoleMode(handle, ctypes.byref(mode)):
                k32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:  # noqa: S110 - best effort, plain text still works  # pragma: no cover
        pass


class UI:
    """Small console helper: colour, verbosity and consistent prefixes."""

    def __init__(self, quiet: bool = False, verbose: bool = False, color: bool | None = None):
        self.quiet, self.verbose = quiet, verbose
        self.color = _want_color() if color is None else color
        if self.color:
            _enable_windows_ansi()

    def _c(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def out(self, msg: str = "") -> None:
        if not self.quiet:
            print(msg)

    def info(self, msg: str) -> None:
        """Only shown with --verbose. ASCII only: the console code page may not be UTF-8."""
        if self.verbose and not self.quiet:
            print(self._c("2", f"  - {msg}"))

    def error(self, msg: str) -> None:
        print(self._c("1;31", f"error: {msg}"), file=sys.stderr)

    def sev(self, severity: str) -> str:
        return self._c(SEV_COLOR.get(severity, "37"), f"{severity.upper():8}")


def _print_summary(result: Result, ui: UI, min_sev: str) -> None:
    shown = [a for a in result.alerts if sev_rank(a.severity) >= sev_rank(min_sev)]
    if ui.quiet:
        print(f"{result.total_events} {len(result.alerts)}")
        return

    head = f"NetWatch-Lite {__version__} - {result.total_events} events - {len(result.alerts)} alerts"
    if result.first_ts is not None:
        head += f" - {fmt_ts(result.first_ts)} -> {fmt_ts(result.last_ts)}"
    ui.out(ui._c("1", head))

    if not shown:
        ui.out(
            ui._c("32", "  no alerts above the requested severity")
            if result.alerts
            else ui._c("32", "  clean - no rule matched")
        )
        return

    ui.out()
    id_w = max(len(a.id) for a in shown)
    rule_w = max(len(a.rule) for a in shown)
    src_w = max(len(str(a.src)) for a in shown)
    mitre_w = max((sum(len(m["id"]) + 1 for m in a.mitre) for a in shown), default=0)

    for a in shown:
        tag = ",".join(m["id"] for m in a.mitre)
        print(
            f"  {ui.sev(a.severity)} {a.id:<{id_w}}  {a.rule:<{rule_w}}  "
            f"{a.src!s:<{src_w}}  {tag:<{mitre_w}}  x{a.count:<5} {a.title}"
        )
    ui.out()


def _check_inputs(paths: list[str], ui: UI) -> int | None:
    if not paths:
        ui.error("no input files given")
        return EXIT_ERROR
    for p in paths:
        path = Path(p)
        if not path.exists():
            ui.error(f"file not found: {p}")
            return EXIT_ERROR
        if path.is_dir():
            ui.error(f"not a file: {p}")
            return EXIT_ERROR
    return None


def _write(path: str, content: str, ui: UI) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content, encoding="utf-8")
    ui.info(f"wrote {path}")


class _Parser(argparse.ArgumentParser):
    """argparse exits with 2 on usage errors, which collides with our --fail-on contract (2)."""

    def error(self, message: str):
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_ERROR)


def _flags(parser: argparse.ArgumentParser, suppress: bool) -> None:
    """Add -q/-v so they work before *and* after the sub-command.

    `default=argparse.SUPPRESS` on the sub-parser stops it from overwriting a value the
    user already set on the top-level parser.
    """
    d = argparse.SUPPRESS if suppress else False
    parser.add_argument("-q", "--quiet", action="store_true", default=d, help="only machine-friendly output")
    parser.add_argument("-v", "--verbose", action="store_true", default=d, help="extra progress detail")


def _build_parser() -> argparse.ArgumentParser:
    ap = _Parser(
        prog="netwatch",
        description="NetWatch-Lite - network threat detection for PCAP and authentication logs.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--version", action="version", version=f"netwatch-lite {__version__}")
    _flags(ap, suppress=False)

    sub = ap.add_subparsers(dest="cmd", required=True)

    an = sub.add_parser(
        "analyze",
        help="analyse PCAP / auth log files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    _flags(an, suppress=True)
    an.add_argument("--version", action="version", version=f"netwatch-lite {__version__}")
    an.add_argument(
        "files", nargs="+", metavar="FILE", help=".pcap/.pcapng, syslog auth.log, CSV or JSON Lines"
    )
    an.add_argument("-c", "--config", help="YAML rules file (see rules/default.yaml)")
    an.add_argument("--inventory", help="CSV/TXT of known device MACs (enables new_device rule)")
    an.add_argument("--year", type=int, help="year for syslog timestamps (default: current)")
    an.add_argument("--html", metavar="FILE", help="write the interactive HTML report")
    an.add_argument("--json", metavar="FILE", help="write the JSON report")
    an.add_argument("--csv", metavar="FILE", help="write the alert queue as CSV")
    an.add_argument("--lang", choices=["en", "fa"], default="en", help="HTML report language")
    an.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="low",
        help="lowest severity printed to the console (default: low)",
    )
    an.add_argument(
        "--fail-on", choices=SEVERITIES, help="exit code 2 if an alert >= this severity exists (for CI)"
    )
    an.add_argument("--splunk-url", help="e.g. https://splunk:8088/services/collector/event")
    an.add_argument("--splunk-token")
    an.add_argument("--splunk-index")
    an.add_argument("--splunk-insecure", action="store_true", help="skip TLS verification (lab only)")
    an.add_argument("--splunk-dry-run", action="store_true", help="print HEC payload instead of sending")
    an.add_argument("--webhook-url", metavar="URL", help="POST the JSON report to a generic webhook")
    an.add_argument("--webhook-dry-run", action="store_true", help="print the webhook payload instead")

    demo = sub.add_parser("demo", help="generate synthetic attack traffic and analyse it")
    _flags(demo, suppress=True)
    demo.add_argument("--version", action="version", version=f"netwatch-lite {__version__}")
    demo.add_argument("--out", default="demo_output", help="output directory (default: demo_output)")
    demo.add_argument("--lang", choices=["en", "fa"], default="en", help="HTML report language")

    return ap


def _outputs(result: Result, args, ui: UI) -> int | None:
    if args.html:
        _write(args.html, to_html(result, args.lang), ui)
    if args.json:
        _write(args.json, to_json(result), ui)
    if getattr(args, "csv", None):
        _write(args.csv, to_csv(result), ui)

    if getattr(args, "splunk_url", None):
        if not args.splunk_token:
            ui.error("--splunk-token is required with --splunk-url")
            return EXIT_ERROR
        try:
            resp = to_splunk_hec(
                result,
                args.splunk_url,
                args.splunk_token,
                args.splunk_index,
                verify_tls=not args.splunk_insecure,
                dry_run=args.splunk_dry_run,
            )
        except Exception as exc:  # network / auth problems must not crash with a traceback
            ui.error(f"Splunk HEC request failed: {exc}")
            return EXIT_ERROR
        ui.out(resp if args.splunk_dry_run else ui._c("32", "delivered to Splunk HEC"))

    if getattr(args, "webhook_url", None):
        try:
            resp = to_webhook(result, args.webhook_url, dry_run=args.webhook_dry_run)
        except Exception as exc:
            ui.error(f"webhook request failed: {exc}")
            return EXIT_ERROR
        ui.out(resp if args.webhook_dry_run else ui._c("32", "delivered to webhook"))
    return None


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    ui = UI(quiet=args.quiet, verbose=args.verbose)

    try:
        if args.cmd == "demo":
            from .samples import generate

            out = Path(args.out)
            ui.info(f"generating synthetic traffic in {out}")
            pcap, authlog, inv = generate(out)
            result = run([str(pcap), str(authlog)], inventory=str(inv), year=2026)
            _write(str(out / "report.html"), to_html(result, args.lang), ui)
            _write(str(out / "report.json"), to_json(result), ui)
            _print_summary(result, ui, "low")
            ui.out(f"  report: {out / 'report.html'}")
            return EXIT_OK

        bad = _check_inputs(args.files, ui)
        if bad is not None:
            return bad

        for p in args.files:
            ui.info(f"parsing {p}")
        result = run(args.files, args.config, args.inventory, args.year)
        ui.info(f"{result.total_events} events, {len(result.alerts)} alerts")

        _print_summary(result, ui, args.min_severity)
        code = _outputs(result, args, ui)
        if code is not None:
            return code
        for p in (args.html, args.json, getattr(args, "csv", None)):
            if p:
                ui.out(f"  wrote: {p}")

        if args.fail_on and any(sev_rank(a.severity) >= sev_rank(args.fail_on) for a in result.alerts):
            ui.out(ui._c("31", f"  fail-on {args.fail_on}: threshold reached"))
            return EXIT_ALERT
        return EXIT_OK

    except KeyboardInterrupt:
        ui.error("interrupted")
        return EXIT_INTERRUPTED
    except FileNotFoundError as exc:
        ui.error(f"file not found: {exc.filename}")
        return EXIT_ERROR
    except PermissionError as exc:
        ui.error(f"permission denied: {exc.filename}")
        return EXIT_ERROR
    except ValueError as exc:
        ui.error(str(exc))
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
