"""Regression tests for BOLAScanner.

Guards the crash fix (previously referenced an undefined ``self.PAYLOADS``) and the
numeric-ID / IDOR logic.
"""
from engine.scanners.bola import BOLAScanner
from engine.core.target import Target


def test_no_numeric_id_returns_empty(fake_session):
    target = Target(url="http://x.local/api/users")  # no numeric id in path
    assert BOLAScanner(fake_session).scan(target) == []


def test_numeric_id_runs_without_crashing(fake_session):
    target = Target(url="http://x.local/api/users/5")
    result = BOLAScanner(fake_session).scan(target)
    assert isinstance(result, list)


def test_detects_idor_when_other_ids_return_similar_response(make_session):
    # Baseline and manipulated IDs all return HTTP 200 with a similar body size,
    # which is the heuristic the scanner uses to flag possible IDOR.
    session = make_session(text="user profile: name, email, phone", status_code=200)
    target = Target(url="http://x.local/api/users/5")
    result = BOLAScanner(session).scan(target)
    assert any("BOLA" in v.name or "IDOR" in v.name for v in result)


def test_no_finding_when_manipulated_ids_are_forbidden(make_session):
    # 403 on the manipulated ID means authorization works -> no finding.
    session = make_session(text="Forbidden", status_code=403)
    target = Target(url="http://x.local/api/users/5")
    assert BOLAScanner(session).scan(target) == []
