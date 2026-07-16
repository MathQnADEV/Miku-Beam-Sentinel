"""Behavioural tests for the XSS scanner (issue #2).

Covers context-aware detection: a finding requires the (canary-tagged) payload to
have parsed into a genuinely executable construct (a real <script> element, an
event-handler attribute, or a javascript: URI) — not a bare substring match. HTML-
encoded reflections and reflections inside inert containers (comments, <textarea>)
must not be flagged; raw reflection into an executable position must still be.
"""
import html
import json
from urllib.parse import urlparse, parse_qs

from engine.scanners.xss import XSSScanner
from engine.core.target import Target


def _reflecting_session(make_session, render):
    """Build a FakeSession whose handler decodes the single query param sent and
    renders it through `render(value) -> html_body`."""
    def handler(method, url, **kw):
        qs = parse_qs(urlparse(url).query)
        value = next(iter(qs.values()), [""])[0]
        return {"text": render(value), "status_code": 200}
    return make_session(handler=handler)


# ---- Acceptance criteria from issue #2 --------------------------------------

def test_html_encoded_reflection_yields_no_finding(make_session):
    # The correct, safe behaviour: output is HTML-entity-encoded before rendering.
    session = _reflecting_session(make_session, lambda v: f"<div>You searched for: {html.escape(v)}</div>")
    result = XSSScanner(session).scan(Target(url="http://x.local/search"))
    assert result == []


def test_raw_reflection_into_executable_context_is_flagged(make_session):
    # The vulnerable behaviour: output is echoed back completely unescaped.
    session = _reflecting_session(make_session, lambda v: f"<div>You searched for: {v}</div>")
    result = XSSScanner(session).scan(Target(url="http://x.local/search"))
    assert any("Cross-Site Scripting" in v.name for v in result)
    assert all(v.severity == "HIGH" for v in result)


# ---- Context awareness -------------------------------------------------------

def test_reflection_inside_html_comment_is_not_flagged(make_session, monkeypatch):
    # Raw markup, but inert: a real browser (and BeautifulSoup) never turns
    # comment content into a live <script> tag or attribute.
    #
    # Scoped to simple, non-breakout payloads: some payloads in the full list are
    # deliberate multi-context polyglots that contain a literal "-->" and are
    # SUPPOSED to escape a comment (a real browser parses it exactly that way too)
    # -- that's the scanner correctly catching a genuine escape, not a false
    # positive, so it's covered separately rather than asserted "not flagged" here.
    monkeypatch.setattr(XSSScanner, "PAYLOADS", ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"])
    session = _reflecting_session(make_session, lambda v: f"<!-- debug: you searched for {v} -->")
    result = XSSScanner(session).scan(Target(url="http://x.local/search"))
    assert result == []


def test_reflection_inside_textarea_is_not_flagged(make_session, monkeypatch):
    # <textarea> content is always inert text in a real browser, even unescaped —
    # for a payload that doesn't itself contain a "</textarea>" breakout sequence
    # (see the comment above; the polyglot payload is intentionally excluded here
    # for the same reason, and covered by test_polyglot_payload_escaping_a_textarea_is_flagged).
    monkeypatch.setattr(XSSScanner, "PAYLOADS", ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"])
    session = _reflecting_session(make_session, lambda v: f"<textarea>{v}</textarea>")
    result = XSSScanner(session).scan(Target(url="http://x.local/search"))
    assert result == []


def test_polyglot_payload_escaping_a_textarea_is_flagged(make_session, monkeypatch):
    # The multi-context polyglot payload contains its own "</textarea>" and "-->"
    # sequences and is specifically designed to break out of containers like this
    # one. A real browser parses it exactly the same way (no "nested" textareas),
    # so once it escapes, the trailing <svg onload=...> is genuinely live — the
    # scanner is correct to flag this, not a false positive.
    polyglot = next(p for p in XSSScanner.PAYLOADS if "</textarea>" in p)
    monkeypatch.setattr(XSSScanner, "PAYLOADS", [polyglot])
    session = _reflecting_session(make_session, lambda v: f"<textarea>{v}</textarea>")
    result = XSSScanner(session).scan(Target(url="http://x.local/search"))
    assert any("Cross-Site Scripting" in v.name for v in result)


def test_reflection_into_event_handler_attribute_is_flagged(make_session):
    # The app interpolates the value directly into an existing element's markup
    # rather than a plain text position; still must be caught.
    def handler(method, url, **kw):
        qs = parse_qs(urlparse(url).query)
        value = next(iter(qs.values()), [""])[0]
        return {"text": f"<div data-x=1>{value}</div>", "status_code": 200}

    session = make_session(handler=handler)
    result = XSSScanner(session).scan(Target(url="http://x.local/search"))
    assert any("Cross-Site Scripting" in v.name for v in result)


# ---- Canary uniqueness (false-positive prevention) --------------------------

def test_not_flagged_by_coincidental_static_example_on_the_page(make_session):
    # The page has a static, unrelated documentation example using the literal
    # argument "1" (e.g. "<script>alert(1)</script>"), on EVERY response,
    # regardless of what we send. Because our canary is a random 6-digit number,
    # it can never equal the single-digit "1" already on the page, so this must
    # not be mistaken for our own injection landing.
    session = make_session(
        text="<html><body><p>Example: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></p></body></html>",
        status_code=200,
    )
    result = XSSScanner(session).scan(Target(url="http://x.local/docs"))
    assert result == []


# ---- False positives from non-HTML-document responses (correctness/FP review) ---

def test_json_api_response_is_never_flagged(make_session):
    # A pure JSON API response is never rendered as an HTML document by a browser.
    # JSON encoding does not require escaping angle brackets, so a benign endpoint
    # that echoes the query faithfully as a properly JSON-serialized string value
    # would otherwise produce a coincidental <script> tag once html.parser
    # tokenizes the raw text -- that must not count as XSS. json.dumps is used
    # (not manual quote-replacement) so the body is valid JSON for every payload,
    # including ones containing tabs/newlines/backslashes.
    def handler(method, url, **kw):
        qs = parse_qs(urlparse(url).query)
        value = next(iter(qs.values()), [""])[0]
        body = json.dumps({"query": value})
        return {"text": body, "status_code": 200, "headers": {"Content-Type": "application/json"}}

    session = make_session(handler=handler)
    result = XSSScanner(session).scan(Target(url="http://x.local/api/search"))
    assert result == []


def test_json_response_detected_by_body_even_without_content_type_header(make_session):
    # Same as above but relying on sniffing the body (starts with '{' and parses
    # as JSON) when no Content-Type header is present.
    def handler(method, url, **kw):
        qs = parse_qs(urlparse(url).query)
        value = next(iter(qs.values()), [""])[0]
        body = json.dumps({"query": value})
        return {"text": body, "status_code": 200}

    session = make_session(handler=handler)
    result = XSSScanner(session).scan(Target(url="http://x.local/api/search"))
    assert result == []


def test_script_data_island_is_not_flagged(make_session, monkeypatch):
    # <script type="application/json"> (and application/ld+json, used for SEO
    # structured data / SPA hydration payloads on most modern sites) is never
    # executed by a browser -- it's inert data, even though BeautifulSoup parses
    # it as a <script> element with fully readable text.
    #
    # Scoped to a payload with no "</script>" of its own: that sequence ends ANY
    # script tag lexically (a browser's tokenizer doesn't consult the `type`
    # attribute before matching it), so a payload designed to escape a script tag
    # would do so regardless of its data-island type -- a genuine escape, not a
    # false positive, and not what this test is about.
    monkeypatch.setattr(XSSScanner, "PAYLOADS", ["<img src=x onerror=alert(1)>"])
    session = _reflecting_session(
        make_session,
        lambda v: f'<script type="application/ld+json">{{"sku": "{v}"}}</script>',
    )
    result = XSSScanner(session).scan(Target(url="http://x.local/product"))
    assert result == []


def test_amp_style_bare_on_attribute_is_not_flagged(make_session, monkeypatch):
    # AMP HTML's literal `on="tap:..."` attribute drives a constrained declarative
    # action DSL, not raw JS execution -- it must not be treated the same as a
    # real event handler (onclick, onerror, ...) just because it starts with "on".
    #
    # Scoped to a payload with no quote character of its own: a quote-breaking
    # payload would close the surrounding on="..." attribute early and create a
    # genuinely new, live element after it -- a real escape the scanner should
    # (and does) still catch, which is a different thing from this test's point.
    monkeypatch.setattr(XSSScanner, "PAYLOADS", ["<img src=x onerror=alert(1)>"])
    session = _reflecting_session(
        make_session,
        lambda v: f'<button on="tap:AMP.setState({{count: {v}}})">count</button>',
    )
    result = XSSScanner(session).scan(Target(url="http://x.local/amp-page"))
    assert result == []


# ---- Previously-undetectable payloads (false-negative regression fix) -------

def test_document_domain_payload_now_detected_when_landing_raw_in_script(make_session, monkeypatch):
    # Regression test: alert(document.domain)-style payloads (no numeral argument
    # to substitute) used to fall back to matching the WHOLE tag-wrapped payload
    # text against script.get_text() (which never contains the tag delimiters),
    # so they could never be detected regardless of how vulnerable the target was.
    monkeypatch.setattr(XSSScanner, "PAYLOADS", ["<script>alert(document.domain)</script>"])
    session = _reflecting_session(make_session, lambda v: f"<div>You searched for: {v}</div>")
    result = XSSScanner(session).scan(Target(url="http://x.local/search"))
    assert any("Cross-Site Scripting" in v.name for v in result)


def test_char_code_onerror_payload_now_detected_when_landing_raw_in_attribute(make_session, monkeypatch):
    # Same regression, for the base64/char-code-obfuscated onerror family -- these
    # exist specifically to catch targets that filter literal "alert(1)"-style
    # text, so they must still be detectable once they land unescaped.
    monkeypatch.setattr(XSSScanner, "PAYLOADS", ["<img src=1 onerror=eval(atob('YWxlcnQoMSk='))>"])
    session = _reflecting_session(make_session, lambda v: f"<div>You searched for: {v}</div>")
    result = XSSScanner(session).scan(Target(url="http://x.local/search"))
    assert any("Cross-Site Scripting" in v.name for v in result)


def test_external_src_only_script_payload_now_detected(make_session, monkeypatch):
    # Regression test: this payload has no inline body and no numeral to
    # substitute, so it used to have no viable detection path at all.
    monkeypatch.setattr(XSSScanner, "PAYLOADS", ["<script src=//xss.rocks/xss.js></script>"])
    session = _reflecting_session(make_session, lambda v: f"<div>You searched for: {v}</div>")
    result = XSSScanner(session).scan(Target(url="http://x.local/search"))
    assert any("Cross-Site Scripting" in v.name for v in result)


def test_data_uri_payload_now_detected(make_session, monkeypatch):
    # Regression test: only "javascript:" was recognized as an executable URI
    # scheme, so data:text/html and data:text/javascript payloads (a real
    # execution vector) landing raw in a URI-bearing attribute were never flagged.
    monkeypatch.setattr(
        XSSScanner, "PAYLOADS",
        ["<a href=\"data:text/html,<script>alert(1)</script>\">click</a>"],
    )
    session = _reflecting_session(make_session, lambda v: f"<div>You searched for: {v}</div>")
    result = XSSScanner(session).scan(Target(url="http://x.local/search"))
    assert any("Cross-Site Scripting" in v.name for v in result)


# ---- Unit tests for the canary-substitution helper --------------------------

def test_build_test_payload_substitutes_numeral_argument():
    payload, marker = XSSScanner._build_test_payload("<script>alert(1)</script>", "958234")
    assert payload == "<script>alert(958234)</script>"
    assert marker == "958234"


def test_build_test_payload_substitutes_backtick_argument():
    payload, marker = XSSScanner._build_test_payload("<img src=x onerror=alert`1`>", "958234")
    assert payload == "<img src=x onerror=alert`958234`>"
    assert marker == "958234"


def test_build_test_payload_injects_canary_as_extra_sink_argument():
    # No numeral to substitute, but a recognizable alert/confirm/prompt/eval call
    # -- JS evaluates every call argument eagerly, so adding a leading canary
    # argument still runs the original expression exactly as before.
    payload, marker = XSSScanner._build_test_payload("<script>alert(document.domain)</script>", "958234")
    assert payload == "<script>alert(958234,document.domain)</script>"
    assert marker == "958234"


def test_build_test_payload_appends_canary_inside_event_handler_attribute():
    # No numeral and no alert/confirm/prompt/eval call to inject an argument
    # into -- falls to the on*= attribute rule, appending the canary as a
    # trailing JS comment inside the existing (quoted) attribute value.
    payload, marker = XSSScanner._build_test_payload(
        "<img src=\"x\" onerror=\"doSomething()\">", "958234"
    )
    assert payload == "<img src=\"x\" onerror=\"doSomething()/*958234*/\">"
    assert marker == "958234"


def test_build_test_payload_appends_canary_inside_unquoted_event_handler_attribute():
    payload, marker = XSSScanner._build_test_payload("<img src=x onerror=doSomething()>", "958234")
    assert payload == "<img src=x onerror=doSomething()/*958234*/>"
    assert marker == "958234"


def test_build_test_payload_appends_canary_before_closing_script_tag():
    payload, marker = XSSScanner._build_test_payload("<script src=//xss.rocks/xss.js></script>", "958234")
    assert payload == "<script src=//xss.rocks/xss.js>/*958234*/</script>"
    assert marker == "958234"


def test_build_test_payload_falls_back_when_nothing_is_substitutable():
    # A payload with no numeral, no recognizable JS sink call, no on*= attribute,
    # and no </script> tag has no safe place to embed a canary at all.
    original = "javascript:void(0)"
    payload, marker = XSSScanner._build_test_payload(original, "958234")
    assert payload == original
    assert marker == original
