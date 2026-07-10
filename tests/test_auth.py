"""Tests for the Authenticator, including the API_KEY path the CLI now wires up."""
from engine.core.auth import Authenticator, AuthType


class DummySession:
    def __init__(self):
        self.headers = {}
        self.auth = None


def test_bearer_sets_authorization_header():
    s = DummySession()
    Authenticator(AuthType.BEARER, {"token": "abc123"}).authenticate(s)
    assert s.headers["Authorization"] == "Bearer abc123"


def test_basic_sets_session_auth():
    s = DummySession()
    Authenticator(AuthType.BASIC, {"username": "u", "password": "p"}).authenticate(s)
    assert s.auth == ("u", "p")


def test_api_key_sets_default_header():
    s = DummySession()
    # Mirrors the CLI mapping: --auth-type api_key --auth-token XYZ
    Authenticator(AuthType.API_KEY, {"key_name": "X-API-Key", "key_value": "XYZ"}).authenticate(s)
    assert s.headers["X-API-Key"] == "XYZ"


def test_api_key_custom_header_name():
    s = DummySession()
    Authenticator(AuthType.API_KEY, {"key_name": "Api-Token", "key_value": "T"}).authenticate(s)
    assert s.headers["Api-Token"] == "T"


def test_none_applies_nothing():
    s = DummySession()
    Authenticator(AuthType.NONE, {}).authenticate(s)
    assert s.headers == {} and s.auth is None
