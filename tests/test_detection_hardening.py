"""Regression tests for issue #4 — remove / gate unreliable detections.

Each test pins a specific false positive that used to fire, and (where relevant) that
the genuine signal is still detected.
"""
import base64
import json

from engine.core.target import Target
from engine.scanners.base import BaseScanner
from engine.scanners.jwt import JWTScanner
from engine.scanners.misconfig import SecurityMisconfigurationScanner
from engine.scanners.auth import AuthScanner
from engine.scanners.access_control import BrokenAccessControlScanner
from engine.scanners.rate_limit import RateLimitScanner
from engine.scanners.mass_assignment import MassAssignmentScanner
from engine.scanners.data_exposure import SensitiveDataExposureScanner
from engine.scanners.logging import LoggingScanner


def _jwt(alg):
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b64({'alg': alg, 'typ': 'JWT'})}.{b64({'sub': '1'})}.sig"


# ---- JWT -------------------------------------------------------------------

def test_jwt_hs256_is_not_a_finding(make_session):
    session = make_session(text=f"token: {_jwt('HS256')}")
    result = JWTScanner(session).scan(Target(url="http://x.local/"))
    assert not any("Symmetric" in v.name for v in result)


def test_jwt_none_algorithm_still_flagged(make_session):
    session = make_session(text=f"token: {_jwt('none')}")
    result = JWTScanner(session).scan(Target(url="http://x.local/"))
    assert any("None Algorithm" in v.name for v in result)


# ---- Misconfiguration ------------------------------------------------------

def test_misconfig_does_not_flag_missing_x_xss_protection(make_session):
    session = make_session(text="ok", status_code=200, headers={})
    result = SecurityMisconfigurationScanner(session).scan(Target(url="http://x.local/"))
    assert not any("X-XSS-Protection" in v.description for v in result)


def test_misconfig_delete_put_not_dangerous_but_trace_is(make_session):
    def allow(methods):
        def handler(method, url, **kw):
            if method == "OPTIONS":
                return {"status_code": 200, "headers": {"Allow": methods}}
            return {"status_code": 200, "text": "ok"}
        return handler

    rest = SecurityMisconfigurationScanner(make_session(handler=allow("GET, POST, PUT, DELETE, PATCH")))
    assert not any("Dangerous HTTP Methods" in v.name for v in rest.scan(Target(url="http://x.local/")))

    xst = SecurityMisconfigurationScanner(make_session(handler=allow("GET, TRACE")))
    assert any("Dangerous HTTP Methods" in v.name for v in xst.scan(Target(url="http://x.local/")))


# ---- Access control (soft-404 gate) ---------------------------------------

def test_access_control_suppressed_when_server_soft_404s(make_session):
    # Everything returns 200 (SPA / catch-all) -> no path-based findings.
    session = make_session(text="<html>app with user admin token config</html>", status_code=200)
    result = BrokenAccessControlScanner(session).scan(Target(url="http://x.local/"))
    assert result == []


def test_access_control_flags_when_server_distinguishes(make_session):
    probe = BaseScanner.NONEXISTENT_PROBE

    def handler(method, url, **kw):
        if probe in url:
            return {"status_code": 404, "text": "not found"}
        if url.endswith("/admin"):
            return {"status_code": 200, "text": "admin panel: password token config"}
        return {"status_code": 404, "text": "nope"}

    session = make_session(handler=handler)
    result = BrokenAccessControlScanner(session).scan(Target(url="http://x.local"))
    assert any("Broken Access Control" in v.name for v in result)


# ---- Rate limiting ---------------------------------------------------------

def test_rate_limit_is_informational_not_medium(make_session):
    result = RateLimitScanner(make_session(status_code=200)).scan(Target(url="http://x.local/"))
    assert result and all(v.severity == "INFO" for v in result)


def test_rate_limit_silent_when_429_seen(make_session):
    result = RateLimitScanner(make_session(status_code=429)).scan(Target(url="http://x.local/"))
    assert result == []


# ---- Mass assignment -------------------------------------------------------

def test_mass_assignment_requires_json_key_reflection(make_session):
    # Bare word 'status'/'admin' in text must NOT trigger.
    noisy = make_session(text="current status: admin dashboard", status_code=200)
    assert MassAssignmentScanner(noisy).scan(Target(url="http://x.local/")) == []

    # Field echoed back as a JSON key -> candidate finding.
    reflected = make_session(text='{"is_admin": true, "id": 5}', status_code=200)
    result = MassAssignmentScanner(reflected).scan(Target(url="http://x.local/"))
    assert any("Mass Assignment" in v.name for v in result)


# ---- Sensitive data exposure ----------------------------------------------

def test_data_exposure_ignores_plain_email(make_session):
    session = make_session(text="Contact us at hello@example.com", status_code=200)
    result = SensitiveDataExposureScanner(session).scan(Target(url="http://x.local/"))
    assert not any("Email" in v.name for v in result)


def test_data_exposure_still_flags_aws_key(make_session):
    session = make_session(text="key = AKIAIOSFODNN7EXAMPLE", status_code=200)
    result = SensitiveDataExposureScanner(session).scan(Target(url="http://x.local/"))
    assert any("AWS Key" in v.name for v in result)


def test_data_exposure_no_unencrypted_finding_for_localhost(make_session):
    session = make_session(text="ok", status_code=200)
    result = SensitiveDataExposureScanner(session).scan(Target(url="http://localhost:8000/api"))
    assert not any("Unencrypted" in v.name for v in result)


# ---- Authentication --------------------------------------------------------

def test_auth_silent_without_credentials(make_session):
    # No credentials configured -> cannot judge -> must not flag every 200 page.
    result = AuthScanner(make_session(status_code=200)).scan(Target(url="http://x.local/"))
    assert not any("Authentication Not Enforced" in v.name for v in result)


def test_auth_flags_when_credentials_are_ignored(make_session):
    session = make_session(status_code=200)
    session.headers["Authorization"] = "Bearer testtoken"
    result = AuthScanner(session).scan(Target(url="http://x.local/"))
    assert any("Authentication Not Enforced" in v.name for v in result)


# ---- Logging ---------------------------------------------------------------

def test_logging_scanner_emits_no_findings(make_session):
    session = make_session(text="login failed: invalid credentials", status_code=401)
    assert LoggingScanner(session).scan(Target(url="http://x.local/")) == []
