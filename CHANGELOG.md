# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `--csv FILE` export of the alert queue (spreadsheets, tickets, handover notes)
- `--webhook-url URL` posts the JSON report to a generic webhook (with `--webhook-dry-run`)
- `--version`, `--quiet` / `-q` and `--verbose` / `-v`, usable before *or* after the sub-command
- Documented exit codes (`0` ok · `1` error · `2` fail-on reached · `130` interrupted)
- Colour honours `NO_COLOR` / `FORCE_COLOR` and is enabled automatically on Windows 10+ VT
- Interactive HTML report: severity filters, live search, four sort orders, alert timeline,
  MITRE coverage chips, dark/light theme with persistence, keyboard shortcuts, CSV export,
  per-alert JSON copy, print stylesheet, RTL/Persian number localisation
- `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue and PR templates
- Ruff lint/format job and a PyPI publish workflow
- Tests for the CLI, the report structure, accessibility hooks and label coverage
- Report screenshots in `assets/` (desktop light/dark, alert detail, phone) plus the CI
  artifact that renders them on every run

### Changed
- Usage errors now exit with `1` instead of argparse's default `2`, so `--fail-on` keeps a
  distinct contract for CI
- Console summary rendered as an aligned table with severity colour coding
- `Ctrl+C` exits cleanly with `130` instead of printing a traceback
- README rewritten: report screenshots, full option reference, exit-code table and a real
  demo transcript
- Report toolbar groups the sort menu and action buttons so they never wrap onto a row of
  their own at narrow widths; topbar actions align to the left edge on phones

### Fixed
- scapy's "no libpcap provider" banner no longer pollutes stdout/stderr during offline parsing
- `FORCE_COLOR=0` now turns colour off instead of forcing it on
- The alert timeline always runs left to right, so dots and timestamps agree in the RTL layout
- The capture-window tile no longer breaks `UTC` onto its own line
- Persian headings are no longer letter-spaced or upper-cased (it loosened the script joins)
- The report UI job installed the Playwright browser but not Playwright itself

## [0.1.0] - 2026-10-05

### Added
- First release: streaming detectors for port scan, brute force / password spraying,
  DNS tunnelling & DGA, ARP spoofing, rogue DHCP and unknown devices
- PCAP, OpenSSH syslog, CSV and JSON Lines parsers
- MITRE ATT&CK mapping for every alert
- HTML (EN/FA) and JSON reports, Splunk HEC export
- YAML-tunable thresholds, inventory file, `--fail-on` for CI, test suite and CI workflow
