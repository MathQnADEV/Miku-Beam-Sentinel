"""Behavioural tests for the SQL injection scanner.

These document current, intended behaviour (error-signature detection; no finding on a
clean page). See issue #1 for the planned baseline/control-request hardening that will
make error-based detection sound.
"""
from engine.scanners.injection import SQLInjectionScanner
from engine.core.target import Target


def test_error_based_detection_fires_on_sql_error_signature(make_session):
    session = make_session(
        text="You have an error in your SQL syntax; check the manual", status_code=200
    )
    result = SQLInjectionScanner(session).scan(Target(url="http://x.local/item"))
    assert any("SQL Injection" in v.name for v in result)
    assert all(v.severity == "CRITICAL" for v in result)


def test_clean_response_produces_no_finding(make_session):
    session = make_session(text="Hello world, nothing to see here", status_code=200)
    assert SQLInjectionScanner(session).scan(Target(url="http://x.local/item")) == []


def test_findings_carry_recommendation_and_poc(make_session):
    session = make_session(text="SQL syntax error near 'x'", status_code=200)
    result = SQLInjectionScanner(session).scan(Target(url="http://x.local/item"))
    assert result, "expected at least one finding"
    v = result[0]
    assert v.recommendation and v.proof_of_concept and v.url
