# Contributing to NetWatch-Lite

Thanks for helping. This is a small, focused project: a lightweight detection tool that
stays readable and dependency-light.

## Development setup

```bash
git clone https://github.com/M4TECHG/netwatch-lite.git
cd netwatch-lite
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q                                            # must be green before you push
netwatch demo --out demo_output --lang fa            # sanity check + a report to look at
```

## Before you open a pull request

```bash
ruff check .           # lint
ruff format .          # formatting
pytest -q              # tests
```

CI runs the same three steps on Python 3.10, 3.11 and 3.12, plus a demo run that must exit
with code `2` (i.e. the demo is expected to raise a High alert).

## What makes a good change here

1. **Streaming only.** Detectors consume an ordered event stream and keep bounded state.
   Nothing may load a whole PCAP into memory.
2. **Every threshold lives in YAML.** If you hardcode a number in a detector, it belongs in
   `config.DEFAULTS` *and* in `rules/default.yaml` instead.
3. **Every alert maps to MITRE.** Add the technique to `netwatch/mitre.py`, not a raw ID.
4. **Evidence, not vibes.** An alert must carry the numbers that justified it so a Tier-1
   analyst can triage without re-running anything.
5. **Tests for both directions.** One test that the detection fires, one that normal traffic
   stays quiet. See `tests/test_detectors.py`.
6. **Honest limitations.** Document what the rule *cannot* do in `docs/detections.md`.

## Adding a detector

1. Create `netwatch/detectors/my_rule.py` with a `Detector` subclass (`name`, `feed(event)`).
2. Register it in `netwatch/detectors/__init__.py`.
3. Add its default configuration to `DEFAULTS` in `netwatch/config.py` and to
   `rules/default.yaml`.
4. Add its display name to both language blocks in `netwatch/report/exporters.py`.
5. Write tests: fires on attack traffic, silent on baseline traffic.
6. Document it in `docs/detections.md`, including known false-positive sources.

## Changing the HTML report

`netwatch/templates/report.html.j2` is deliberately a single self-contained file — no CDN,
no build step, no framework. It must still open from a USB stick with no network.

Rules that the tests enforce:

- inline `<style>`/`<script>` only; no remote CSS/JS/font
- exactly one `<h1>` and no skipped heading levels
- decorative icons are inline SVG with `aria-hidden`, never emoji
- every icon-only button has an accessible name
- all text colour pairs keep ≥ 4.5:1 contrast in **both** light and dark themes
- keep it usable with JavaScript disabled (the alerts are server-rendered)
- the same string exists in `en` **and** `fa`

## Commit messages

Short imperative subject, then a body that says *why* when it is not obvious:

```
Add sliding window to the DNS tunnel detector

The previous logic counted unique subdomains for the whole capture, so a
long capture of a busy resolver crossed the threshold on normal traffic.
```

## Reporting bugs / requesting features

Use the issue templates. For anything security related, read [SECURITY.md](SECURITY.md)
first and keep it private.

## License

By contributing you agree that your contribution is released under the MIT License.
