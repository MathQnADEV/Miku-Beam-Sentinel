"""Behavioural tests for the SQL injection scanner.

Covers issue #1: error-based and time-based detection must be evidence-based against
a payload-free baseline, not judged in isolation — so an endpoint that is merely slow,
or a page that always contains an "SQL"-flavoured phrase, does not false-positive.
"""
import time

from engine.scanners.injection import SQLInjectionScanner
from engine.core.target import Target


# ---- Error-based ------------------------------------------------------------

def test_error_based_not_flagged_when_signature_present_in_baseline(make_session):
    # The exact same text appears on every request (baseline included) — e.g. a
    # docs/blog page that happens to discuss SQL errors. The payload introduced
    # nothing, so this must NOT be reported.
    session = make_session(text="Read our guide: You have an error in your SQL syntax explained")
    result = SQLInjectionScanner(session).scan(Target(url="http://x.local/blog"))
    assert result == []


def test_error_based_flagged_when_signature_only_appears_after_payload(make_session):
    def handler(method, url, **kw):
        if url.endswith("=1"):  # the payload-free baseline request
            return {"text": "normal page, nothing unusual", "status_code": 200}
        return {"text": "You have an error in your SQL syntax; check the manual", "status_code": 200}

    session = make_session(handler=handler)
    result = SQLInjectionScanner(session).scan(Target(url="http://x.local/item"))
    assert any("Error-Based" in v.name for v in result)
    assert all(v.severity == "CRITICAL" for v in result)


def test_clean_response_produces_no_finding(make_session):
    session = make_session(text="Hello world, nothing to see here", status_code=200)
    assert SQLInjectionScanner(session).scan(Target(url="http://x.local/item")) == []


def test_findings_carry_recommendation_and_poc(make_session):
    def handler(method, url, **kw):
        if url.endswith("=1"):
            return {"text": "normal page", "status_code": 200}
        return {"text": "You have an error in your SQL syntax", "status_code": 200}

    session = make_session(handler=handler)
    result = SQLInjectionScanner(session).scan(Target(url="http://x.local/item"))
    assert result, "expected at least one finding"
    v = result[0]
    assert v.recommendation and v.proof_of_concept and v.url


# ---- Time-based (baseline + fast-control confirmation) ----------------------

def test_time_based_confirmed_with_fast_control(make_session, monkeypatch):
    monkeypatch.setattr(SQLInjectionScanner, "PAYLOADS", ["' AND SLEEP(5)--"])
    monkeypatch.setattr(SQLInjectionScanner, "PARAMS", ["id"])
    monkeypatch.setattr(SQLInjectionScanner, "DELAY_THRESHOLD", 0.05)

    def handler(method, url, **kw):
        if "SLEEP(5)" in url:
            time.sleep(0.08)
        return {"text": "normal page", "status_code": 200}

    session = make_session(handler=handler)
    result = SQLInjectionScanner(session).scan(Target(url="http://x.local/api"))
    assert any("Time-Based" in v.name for v in result)


def test_time_based_not_flagged_on_uniformly_slow_endpoint(make_session, monkeypatch):
    # If EVERY request (baseline included) is equally slow, there is no delta above
    # baseline -> not a SQL injection signal, just a slow endpoint. This is exactly
    # the false positive the old `elapsed >= 5` (no baseline) check produced.
    monkeypatch.setattr(SQLInjectionScanner, "PAYLOADS", ["' AND SLEEP(5)--"])
    monkeypatch.setattr(SQLInjectionScanner, "PARAMS", ["id"])
    monkeypatch.setattr(SQLInjectionScanner, "DELAY_THRESHOLD", 0.05)

    def handler(method, url, **kw):
        time.sleep(0.06)  # uniformly slow, including the baseline request
        return {"text": "normal page", "status_code": 200}

    session = make_session(handler=handler)
    result = SQLInjectionScanner(session).scan(Target(url="http://x.local/api"))
    assert result == []


def test_time_based_confirmed_for_non_five_second_delay(make_session, monkeypatch):
    # The fast-control substitution generalizes to ANY numeric delay, not just "5" —
    # this is what lets the SLEEP(1) polyglot payload (PAYLOADS, WAF-bypass section)
    # get the same strong zero-delay confirmation as the SLEEP(5) payloads, instead
    # of silently falling back to the weaker same-payload reproducibility check
    # (which can't tell a real DB sleep apart from a keyword-triggered WAF delay).
    monkeypatch.setattr(SQLInjectionScanner, "PAYLOADS", ["' AND SLEEP(10)--"])
    monkeypatch.setattr(SQLInjectionScanner, "PARAMS", ["id"])
    monkeypatch.setattr(SQLInjectionScanner, "DELAY_THRESHOLD", 0.05)

    def handler(method, url, **kw):
        if "SLEEP(10)" in url:
            time.sleep(0.08)
        return {"text": "normal page", "status_code": 200}

    session = make_session(handler=handler)
    result = SQLInjectionScanner(session).scan(Target(url="http://x.local/api"))
    assert any("Time-Based" in v.name for v in result)


def test_time_based_falls_back_to_reproducibility_without_a_fast_variant(make_session, monkeypatch):
    # A payload whose delay isn't a plain numeric literal (an obfuscated expression)
    # has no zero-delay control -> the scanner must fall back to confirming the SAME
    # payload reproduces the delay on a second request.
    monkeypatch.setattr(SQLInjectionScanner, "PAYLOADS", ["' AND SLEEP(RAND()*9)--"])
    monkeypatch.setattr(SQLInjectionScanner, "PARAMS", ["id"])
    monkeypatch.setattr(SQLInjectionScanner, "DELAY_THRESHOLD", 0.05)

    def handler(method, url, **kw):
        if "SLEEP(RAND" in url:
            time.sleep(0.08)
        return {"text": "normal page", "status_code": 200}

    session = make_session(handler=handler)
    result = SQLInjectionScanner(session).scan(Target(url="http://x.local/api"))
    assert any("Time-Based" in v.name for v in result)


def test_time_based_not_flagged_when_delay_is_keyword_triggered_not_real(make_session, monkeypatch):
    # A defensive WAF/tarpit that delays any request whose query merely CONTAINS the
    # keyword "SLEEP(" (regardless of the argument) would, under the old fast-control
    # logic, still delay the SLEEP(1) polyglot's "reproducibility" fallback check
    # identically both times -> falsely "confirmed". With the generalized fast-control,
    # the zero-delay variant (still containing "SLEEP(", just with "0" instead of "1")
    # is delayed by the WAF too -> correctly NOT confirmed as real SQL injection.
    monkeypatch.setattr(
        SQLInjectionScanner, "PAYLOADS",
        ["SLEEP(1)/*' or SLEEP(1) or '\" or SLEEP(1) or \"*/"],
    )
    monkeypatch.setattr(SQLInjectionScanner, "PARAMS", ["id"])
    monkeypatch.setattr(SQLInjectionScanner, "DELAY_THRESHOLD", 0.05)

    def handler(method, url, **kw):
        if "SLEEP(" in url:  # keyword-triggered tarpit: delays regardless of the digit
            time.sleep(0.08)
        return {"text": "normal page", "status_code": 200}

    session = make_session(handler=handler)
    result = SQLInjectionScanner(session).scan(Target(url="http://x.local/api"))
    assert result == []


def test_fast_control_payload_substitutes_known_delay_literals():
    assert SQLInjectionScanner._fast_control_payload("' AND SLEEP(5)--") == "' AND SLEEP(0)--"
    assert SQLInjectionScanner._fast_control_payload("'; WAITFOR DELAY '0:0:5'--") == "'; WAITFOR DELAY '0:0:0'--"
    # Generalized to any numeric delay, not just "5" — this is what fixes the
    # SLEEP(1) polyglot payload (previously had no fast-control variant at all).
    assert SQLInjectionScanner._fast_control_payload("' AND SLEEP(1)--") == "' AND SLEEP(0)--"
    assert SQLInjectionScanner._fast_control_payload("' AND SLEEP(10)--") == "' AND SLEEP(0)--"
    assert SQLInjectionScanner._fast_control_payload(
        "SLEEP(1)/*' or SLEEP(1) or '\" or SLEEP(1) or \"*/"
    ) == "SLEEP(0)/*' or SLEEP(0) or '\" or SLEEP(0) or \"*/"
    # No numeric delay literal at all (obfuscated expression) -> not constructible.
    assert SQLInjectionScanner._fast_control_payload("' AND SLEEP(RAND()*9)--") is None
