"""Behavioural tests for the NoSQL injection scanner (issue #1).

Covers the boolean-differential (real bracket-notation operator injection) and the
baseline-gated error-based check.
"""
from engine.scanners.nosql import NoSQLInjectionScanner
from engine.core.target import Target


def test_boolean_differential_detected_when_ne_returns_much_more_data(make_session):
    def handler(method, url, **kw):
        if "[$ne]=" in url:
            return {"text": "x" * 200, "status_code": 200}  # "matches everything"
        if "[$eq]=" in url:
            return {"text": "no results", "status_code": 200}  # matches nothing
        return {"text": "welcome page", "status_code": 200}

    session = make_session(handler=handler)
    result = NoSQLInjectionScanner(session).scan(Target(url="http://x.local/api"))
    assert any("Boolean-Based" in v.name for v in result)


def test_no_boolean_differential_when_responses_are_similar(make_session):
    # $ne and $eq return near-identical bodies -> no query-logic divergence -> no finding.
    session = make_session(text="same response every time", status_code=200)
    result = NoSQLInjectionScanner(session).scan(Target(url="http://x.local/api"))
    assert result == []


def test_error_based_flagged_when_signature_absent_from_baseline(make_session):
    def handler(method, url, **kw):
        if "[$where]=" in url:
            return {"text": "MongoError: unsupported operator", "status_code": 200}
        if "[$ne]=" in url or "[$eq]=" in url:
            return {"text": "not found", "status_code": 200}  # no boolean diff
        return {"text": "welcome page", "status_code": 200}  # baseline

    session = make_session(handler=handler)
    result = NoSQLInjectionScanner(session).scan(Target(url="http://x.local/api"))
    assert any("Error-Based" in v.name for v in result)


def test_error_based_not_flagged_when_signature_present_in_baseline(make_session):
    # The word "MongoError" appears identically on every request, including the
    # payload-free baseline -> the payload introduced nothing -> must not flag.
    session = make_session(text="Our docs describe common MongoError scenarios")
    result = NoSQLInjectionScanner(session).scan(Target(url="http://x.local/api"))
    assert result == []


def test_boolean_differential_not_flagged_when_ne_response_size_is_unstable(make_session):
    # $ne looks much bigger than $eq on the FIRST request, but that's from unrelated
    # randomized content (e.g. a "related items" carousel), not the operator actually
    # being parsed -- re-issuing the identical $ne URL gives a wildly different size,
    # so the divergence isn't reproducible and must not be trusted as evidence.
    calls = {"n": 0}

    def handler(method, url, **kw):
        if "[$ne]=" in url:
            calls["n"] += 1
            size = 200 if calls["n"] == 1 else 20  # unstable across repeated requests
            return {"text": "x" * size, "status_code": 200}
        if "[$eq]=" in url:
            return {"text": "no results", "status_code": 200}
        return {"text": "welcome page", "status_code": 200}

    session = make_session(handler=handler)
    result = NoSQLInjectionScanner(session).scan(Target(url="http://x.local/api"))
    assert result == []
