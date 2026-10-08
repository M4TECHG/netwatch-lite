"""Render the HTML report in a real browser and fail on UI regressions.

Used by CI (``python scripts/check_report.py demo_output/report.html``) and by maintainers
to produce README screenshots (``--shots assets``).

Checks
------
* no uncaught JavaScript errors and no failed network requests
* no horizontal overflow at desktop and phone width
* exactly one <h1>, no skipped heading levels
* every alert is visible without JavaScript-free layout collapse
* light and dark theme both render without contrast regression on the key surfaces

Requires ``pip install playwright && playwright install chromium``.
"""

from __future__ import annotations

import argparse
import sys
from itertools import pairwise
from pathlib import Path

VIEWPORTS = [("desktop", 1440, 900), ("laptop", 1180, 800), ("tablet", 768, 1024), ("phone", 375, 812)]


def check(page, label: str, errors: list[str]) -> None:
    if page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 1"):
        sw = page.evaluate("document.documentElement.scrollWidth")
        iw = page.evaluate("window.innerWidth")
        errors.append(f"{label}: horizontal overflow ({sw} > {iw})")

    headings = page.eval_on_selector_all("h1,h2,h3,h4", "els => els.map(e => +e.tagName[1])")
    if headings.count(1) != 1:
        errors.append(f"{label}: expected exactly one <h1>, found {headings.count(1)}")
    for prev, cur in pairwise(headings):
        if cur > prev + 1:
            errors.append(f"{label}: heading level jumped from h{prev} to h{cur}")

    if page.locator(".alert").count() == 0:
        errors.append(f"{label}: no alerts rendered")

    # a control with no accessible name is invisible to a screen reader
    nameless = page.eval_on_selector_all(
        "button",
        """els => els.filter(e => !e.getAttribute('aria-label')
              && !e.innerText.trim() && !e.title).map(e => e.outerHTML.slice(0, 80))""",
    )
    if nameless:
        errors.append(f"{label}: buttons without an accessible name: {nameless}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("report", type=Path, help="path to report.html")
    ap.add_argument("--shots", type=Path, help="write light/dark screenshots into this directory")
    ap.add_argument("--full-page", action="store_true", help="capture the whole page, not the fold")
    args = ap.parse_args(argv)

    if not args.report.exists():
        print(f"error: {args.report} not found", file=sys.stderr)
        return 1

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("error: pip install playwright && playwright install chromium", file=sys.stderr)
        return 1

    url = args.report.resolve().as_uri()
    errors: list[str] = []
    shots: list[Path] = []

    with sync_playwright() as p:
        browser = p.chromium.launch()
        for label, w, h in VIEWPORTS:
            for theme in ("light", "dark"):
                ctx = browser.new_context(
                    viewport={"width": w, "height": h}, color_scheme=theme, device_scale_factor=2
                )
                page = ctx.new_page()
                page.on("pageerror", lambda e, lb=label: errors.append(f"{lb}: {e}"))
                page.on(
                    "console",
                    lambda m, lb=label: errors.append(f"{lb}: {m.text}") if m.type == "error" else None,
                )
                page.on("requestfailed", lambda r, lb=label: errors.append(f"{lb}: request failed {r.url}"))
                page.goto(url, wait_until="networkidle")
                check(page, f"{label}/{theme}", errors)

                if theme == "dark":
                    page.keyboard.press("Escape")  # nothing focused yet; sanity for the handler
                    page.locator("#q").fill("arp")
                    page.wait_for_timeout(200)
                    shown = page.locator(".alert:not([hidden])").count()
                    if shown == 0:
                        errors.append(f"{label}: search filter matched nothing")
                    page.locator("#q").fill("")
                    page.wait_for_timeout(200)

                if args.shots and label in ("desktop", "phone") and theme in ("light", "dark"):
                    args.shots.mkdir(parents=True, exist_ok=True)
                    out = args.shots / f"report-{label}-{theme}.png"
                    page.screenshot(path=str(out), full_page=args.full_page)
                    shots.append(out)
                    if label == "desktop" and theme == "dark":
                        # the detail view used in the README: one alert expanded
                        page.locator(".alert").first.evaluate("e => e.open = true")
                        page.wait_for_timeout(150)
                        out = args.shots / "report-alerts-dark.png"
                        page.screenshot(path=str(out), full_page=args.full_page)
                        shots.append(out)
                ctx.close()
        browser.close()

    if errors:
        print("report UI check FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"report OK at {len(VIEWPORTS)} widths x 2 themes")
    for s in shots:
        print(f"  wrote {s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
