"""Shared test fixtures.

Every scanner talks to the network exclusively through ``self.session`` (verified:
no scanner imports ``requests``/``socket`` directly). So a fake session injected at
construction time makes the whole engine testable fully offline and deterministically.
"""
import os
import sys

import pytest

# Make the repository root importable (so `import engine...` works from anywhere).
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


class FakeResponse:
    """Minimal stand-in for ``requests.Response`` covering the attributes the
    scanners actually read: text, status_code, content, headers, cookies."""

    def __init__(self, text="", status_code=200, headers=None, content=None, cookies=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self.content = content if content is not None else text.encode("utf-8", "ignore")
        self.cookies = cookies or {}
        self.url = ""

    def json(self):
        import json
        try:
            return json.loads(self.text) if self.text else {}
        except Exception:
            return {}


class FakeSession:
    """Drop-in for ``requests.Session`` that never touches the network.

    Returns a canned response for every verb. Pass ``handler(method, url, **kwargs)``
    to return custom responses per request; return ``None`` from it to fall back to
    the default response.
    """

    def __init__(self, text="", status_code=200, headers=None, cookies=None, handler=None):
        self.headers = {}
        self._text = text
        self._status = status_code
        self._headers = headers or {}
        self._cookies = cookies or {}
        self._handler = handler
        self.calls = []  # list of (method, url, kwargs) for assertions

    def _respond(self, method, url, **kwargs):
        # Mirror requests.Session's behaviour of merging `params=` into the URL's
        # query string, so a handler matching on `url` sees the real final URL
        # regardless of whether the scanner built the query string itself or passed
        # `params=`.
        params = kwargs.get("params")
        if params:
            from urllib.parse import urlencode
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{urlencode(params, doseq=True)}"

        self.calls.append((method, url, kwargs))
        if self._handler is not None:
            custom = self._handler(method, url, **kwargs)
            if custom is not None:
                # A handler may return a ready FakeResponse or a dict of kwargs.
                return FakeResponse(**custom) if isinstance(custom, dict) else custom
        return FakeResponse(self._text, self._status, dict(self._headers), cookies=dict(self._cookies))

    def get(self, url, **kw):
        return self._respond("GET", url, **kw)

    def post(self, url, **kw):
        return self._respond("POST", url, **kw)

    def put(self, url, **kw):
        return self._respond("PUT", url, **kw)

    def delete(self, url, **kw):
        return self._respond("DELETE", url, **kw)

    def head(self, url, **kw):
        return self._respond("HEAD", url, **kw)

    def patch(self, url, **kw):
        return self._respond("PATCH", url, **kw)

    def options(self, url, **kw):
        return self._respond("OPTIONS", url, **kw)

    def request(self, method, url, **kw):
        return self._respond(method, url, **kw)

    def mount(self, prefix, adapter):
        """No-op: real requests.Session.mount() installs a transport adapter
        (e.g. to resize the connection pool). FakeSession makes no real
        connections, so there is nothing to configure, but it must accept the
        call since production code (e.g. DirectoryDiscoverer.discover()) calls
        it unconditionally on whatever session it was given."""
        pass


@pytest.fixture
def fake_session():
    """A default fake session: HTTP 200, empty body."""
    return FakeSession()


@pytest.fixture
def make_session():
    """Factory to build a customised FakeSession, e.g. ``make_session(text='...')``."""
    def _factory(**kwargs):
        return FakeSession(**kwargs)
    return _factory
