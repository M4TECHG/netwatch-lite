## What changed and why

<!-- Link the issue with "Fixes #123" when there is one. -->

## Type of change

- [ ] New detection rule
- [ ] Bug fix
- [ ] Report / CLI UX
- [ ] Docs
- [ ] Refactor, no behaviour change

## Checklist

- [ ] `ruff check .` and `ruff format .` are clean
- [ ] `pytest -q` is green and I added/updated tests
- [ ] A detection has **both** a "fires on attack traffic" and a "quiet on normal traffic" test
- [ ] New thresholds live in `config.DEFAULTS` **and** `rules/default.yaml`
- [ ] MITRE technique IDs come from `netwatch/mitre.py`
- [ ] `docs/detections.md` documents the logic and its false-positive sources
- [ ] The HTML report still opens offline (no CDN) and passes the label/accessibility tests
- [ ] New user-facing strings exist in both `en` and `fa`
- [ ] `CHANGELOG.md` has an entry under **Unreleased**

## Screenshots (for UI changes)

<!-- Before / after of the HTML report, both light and dark theme if relevant. -->
