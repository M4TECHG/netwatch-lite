import json
import re
from itertools import pairwise

import pytest

pytest.importorskip("scapy")

from netwatch.engine import run
from netwatch.report.exporters import LABELS, to_html


@pytest.fixture(scope="module")
def html(tmp_path_factory):
    from netwatch.samples import generate

    out = tmp_path_factory.mktemp("rep")
    pcap, auth, inv = generate(out)
    result = run([str(pcap), str(auth)], inventory=str(inv), year=2026)
    return {"en": to_html(result, "en"), "fa": to_html(result, "fa"), "result": result}


# ---------------------------------------------------------------- document structure
def test_single_h1_and_no_heading_skips(html):
    for key in ("en", "fa"):
        levels = [int(m) for m in re.findall(r"<h([1-4])[\s>]", html[key])]
        assert levels.count(1) == 1, "the report must expose exactly one <h1>"
        for prev, cur in pairwise(levels):
            assert cur <= prev + 1, f"heading level jumped from h{prev} to h{cur}"


def test_lang_and_direction(html):
    assert 'lang="en" dir="ltr"' in html["en"]
    assert 'lang="fa" dir="rtl"' in html["fa"]


def test_alert_ids_are_anchor_targets(html):
    assert 'id="NW-0001"' in html["en"]
    assert 'href="#NW-0001"' in html["en"], "timeline dots must link to their alert"


# ---------------------------------------------------------------- self-contained + safe
def test_no_external_requests(html):
    """A report must open offline from a USB stick."""
    for page in (html["en"], html["fa"]):
        assert not re.search(r'(?:src|href)\s*=\s*["\']https?://', page.split("<body")[0]), (
            "stylesheets/scripts must be inline"
        )
        assert "<script src=" not in page and "<link rel=" not in page
        # outbound links are allowed, but only as user-clicked anchors with rel=noopener
        for url in re.findall(r'href="(https?://[^"]+)"', page):
            assert (
                "attack.mitre.org" in url or "github.com" in url or "opensource.org" in url or "hooks" in url
            ), url
    assert 'rel="noopener noreferrer"' in html["en"]


def test_embedded_json_cannot_break_out_of_script(html):
    """Alert titles come from network data - they are attacker controlled."""
    blob = re.search(r'<script type="application/json" id="nw-data">(.*?)</script>', html["en"], re.S).group(
        1
    )
    assert "</" not in blob and "<" not in blob
    assert json.loads(blob.replace("\\u003c", "<"))[0]["id"] == "NW-0001"


def test_ui_strings_are_injected_for_javascript(html):
    assert '"showing": "' in html["en"]
    assert '"showing": "نمایش' in html["fa"]


# ---------------------------------------------------------------- accessibility hooks
def test_filters_are_present_and_labelled(html):
    page = html["en"]
    assert 'id="q"' in page and "Search rule, title" in page
    assert page.count("data-sev-filter=") >= 6  # 5 severities in the toolbar + the overview bars
    assert 'role="status" aria-live="polite"' in page
    for key in ("sev", "time", "count", "rule"):
        assert f'value="{key}"' in page, f"missing sort option: {key}"
    assert "aria-label=" in re.search(r'<button class="ibtn" id="btn-theme"[^>]*>', page).group(0)


def test_every_button_is_identifiable_by_a_screen_reader(html):
    for page in (html["en"], html["fa"]):
        for btn in re.findall(r"<button\b.*?</button>", page, re.S | re.I):
            has_label = "aria-label=" in btn
            has_text = re.sub(r"<[^>]*>", "", btn).strip() != ""
            assert has_label or has_text, f"icon-only button without an accessible name: {btn[:90]}"


def test_mitre_links_open_safely(html):
    links = re.findall(r'<a class="chip" href="(https://attack\.mitre\.org[^"]+)"([^>]*)>', html["en"])
    assert links and all('rel="noopener noreferrer"' in attrs for _, attrs in links)


def test_skip_link_targets_the_alert_queue(html):
    assert 'class="skip" href="#alerts"' in html["en"]


def test_no_emoji_used_as_interface_icon(html):
    """Emoji render differently on every platform; icons must be vectors."""
    for page in (html["en"], html["fa"]):
        body = page.split("<body", 1)[1]
        assert not re.search(r"[\U0001F300-\U0001FAFF\u2600-\u27BF]", body), "emoji found in the report body"


# ---------------------------------------------------------------- i18n
def test_all_labels_exist_in_every_language():
    missing = set(LABELS["en"]) ^ set(LABELS["fa"])
    assert not missing, f"label keys differ between languages: {missing}"


def test_no_unused_or_missing_ui_strings():
    """Dead translations rot fast: every label must be referenced, and vice versa."""
    from pathlib import Path

    from netwatch.report.exporters import JS_KEYS, SEV_LABEL_KEYS

    tpl = (Path(__file__).parents[1] / "netwatch" / "templates" / "report.html.j2").read_text(
        encoding="utf-8"
    )
    used = {k for k in re.findall(r"\bL\.([a-z_]+)", tpl) if k != "get"}
    used |= set(JS_KEYS) | set(SEV_LABEL_KEYS.values())
    from netwatch.detectors import REGISTRY

    used |= set(REGISTRY)  # rule display names are looked up with L.get(a.rule, ...)
    for lang, labels in LABELS.items():
        assert not set(labels) - used, f"{lang}: unused labels {sorted(set(labels) - used)}"
        assert not used - set(labels), f"{lang}: missing labels {sorted(used - set(labels))}"


def test_persian_digits_are_used_for_numbers(html):
    assert "۳۱۷" in html["fa"]
    assert "317" in html["en"]
    # identifiers stay ASCII so they remain searchable / copy-pasteable
    assert "NW-0001" in html["fa"]


def test_fa_severity_names_are_translated(html):
    assert "بحرانی" in html["fa"] and "CRITICAL" in html["en"]


# ---------------------------------------------------------------- resilience
def test_report_with_no_alerts_renders_empty_state(tmp_path):

    out = tmp_path / "empty"
    out.mkdir()
    (out / "auth.log").write_text(
        "Oct  5 10:00:01 h sshd[1]: Accepted password for bob from 1.2.3.4 port 22 ssh2\n", encoding="utf-8"
    )
    result = run([str(out / "auth.log")], year=2026)
    page = to_html(result, "en")
    assert result.alerts == []
    assert 'id="empty"' in page and "hidden" not in re.search(r'<div class="empty"[^>]*>', page).group(0)
    assert "No alerts" in page


def test_html_is_valid_enough_to_parse(html):
    from html.parser import HTMLParser

    class P(HTMLParser):
        def error(self, message):  # pragma: no cover - py<3.10 API
            raise AssertionError(message)

    P().feed(html["en"])
    P().feed(html["fa"])
