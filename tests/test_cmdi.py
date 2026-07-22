"""Behavioural tests for the OS command injection scanner.

Covers content-based and time-based detection, and (issue #5 adversarial-review
follow-up) that the scanner now fuzzes real query parameters found on the
target URL by REPLACING their value -- not just a single hardcoded "cmd" guess
appended via string concatenation, which could only ever append a parameter
and would produce a duplicate, inert query key when the real parameter already
existed in the URL.
"""
import time
from urllib.parse import parse_qsl, quote_plus, urlsplit

from engine.scanners.cmdi import CommandInjectionScanner
from engine.core.target import Target


# ---- Content-based -----------------------------------------------------------

def test_content_based_detected_when_command_output_present(make_session, monkeypatch):
    monkeypatch.setattr(CommandInjectionScanner, "PAYLOADS", ["; id"])
    monkeypatch.setattr(CommandInjectionScanner, "PARAMS", ["cmd"])

    def handler(method, url, **kw):
        if "cmd=" in url:
            return {"text": "uid=0(root) gid=0(root) groups=0(root)", "status_code": 200}
        return {"text": "normal page", "status_code": 200}

    session = make_session(handler=handler)
    result = CommandInjectionScanner(session).scan(Target(url="http://x.local/api"))
    assert any(v.name == "Command Injection" for v in result)
    assert all(v.severity == "CRITICAL" for v in result)


def test_clean_response_produces_no_finding(make_session):
    session = make_session(text="Hello world, nothing to see here", status_code=200)
    assert CommandInjectionScanner(session).scan(Target(url="http://x.local/api")) == []


# ---- Time-based (baseline-gated, double-confirmed) ---------------------------

def test_time_based_confirmed_when_sleep_payload_reproducibly_delays(make_session, monkeypatch):
    monkeypatch.setattr(CommandInjectionScanner, "PAYLOADS", ["; sleep 5"])
    monkeypatch.setattr(CommandInjectionScanner, "PARAMS", ["cmd"])
    monkeypatch.setattr(CommandInjectionScanner, "DELAY_THRESHOLD", 0.05)

    def handler(method, url, **kw):
        if "cmd=" in url:
            time.sleep(0.08)
        return {"text": "normal page", "status_code": 200}

    session = make_session(handler=handler)
    result = CommandInjectionScanner(session).scan(Target(url="http://x.local/api"))
    assert any("Time-Based" in v.name for v in result)


def test_time_based_not_flagged_on_uniformly_slow_endpoint(make_session, monkeypatch):
    # If EVERY request (baseline included) is equally slow, there is no delta
    # above baseline -> not a command injection signal, just a slow endpoint.
    monkeypatch.setattr(CommandInjectionScanner, "PAYLOADS", ["; sleep 5"])
    monkeypatch.setattr(CommandInjectionScanner, "PARAMS", ["cmd"])
    monkeypatch.setattr(CommandInjectionScanner, "DELAY_THRESHOLD", 0.05)

    def handler(method, url, **kw):
        time.sleep(0.06)
        return {"text": "normal page", "status_code": 200}

    session = make_session(handler=handler)
    result = CommandInjectionScanner(session).scan(Target(url="http://x.local/api"))
    assert result == []


# ---- Real-parameter fuzzing (issue #5) ---------------------------------------

def test_real_discovered_parameter_is_fuzzed_by_value_replacement(make_session, monkeypatch):
    monkeypatch.setattr(CommandInjectionScanner, "PAYLOADS", ["; id"])
    monkeypatch.setattr(CommandInjectionScanner, "PARAMS", ["cmd"])

    encoded_payload = quote_plus("; id")

    def handler(method, url, **kw):
        # Only fires when the REAL "file" parameter's value was replaced with
        # the payload -- not merely present somewhere in the query string.
        if f"file={encoded_payload}" in url:
            return {"text": "uid=0(root) gid=0(root)", "status_code": 200}
        return {"text": "normal page", "status_code": 200}

    session = make_session(handler=handler)
    result = CommandInjectionScanner(session).scan(Target(url="http://x.local/api?file=report.txt"))
    assert any(v.name == "Command Injection" for v in result)


def test_existing_query_param_is_replaced_not_duplicated(make_session, monkeypatch):
    # The old code built test URLs via `f"{target.url}{sep}cmd={payload}"`, which
    # could only ever APPEND a parameter -- fuzzing a real discovered parameter
    # requires replacing its existing value instead, or every request carries a
    # duplicate, inconsistently-resolved query key.
    monkeypatch.setattr(CommandInjectionScanner, "PAYLOADS", ["; id"])
    monkeypatch.setattr(CommandInjectionScanner, "PARAMS", ["cmd"])

    captured_urls = []

    def handler(method, url, **kw):
        captured_urls.append(url)
        return {"text": "normal page", "status_code": 200}

    session = make_session(handler=handler)
    CommandInjectionScanner(session).scan(Target(url="http://x.local/api?file=report.txt"))

    assert captured_urls  # sanity: requests were actually made
    for url in captured_urls:
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        assert sum(1 for name, _ in pairs if name == "file") <= 1
