"""Behavioural tests for the HTTP Parameter Pollution scanner (issue #1).

Covers the baseline-stability gate: a raw body diff is only trusted once we've
confirmed the page is stable across two identical requests.
"""
from engine.scanners.hpp import HTTPParameterPollutionScanner
from engine.core.target import Target


def test_flagged_when_stable_page_differs_on_duplicate_param(make_session):
    def handler(method, url, **kw):
        if url.endswith("id=1&id=2"):
            return {"text": "polluted result: id=2 used", "status_code": 200}
        return {"text": "stable baseline result: id=1 used", "status_code": 200}

    session = make_session(handler=handler)
    result = HTTPParameterPollutionScanner(session).scan(Target(url="http://x.local/api"))
    assert any("Parameter Pollution" in v.name for v in result)


def test_not_flagged_when_page_is_inherently_dynamic(make_session):
    # Baseline itself is unstable (two identical requests differ) -> the page is
    # dynamic and a later diff would be noise, not an HPP signal -> must skip.
    calls = {"n": 0}

    def handler(method, url, **kw):
        calls["n"] += 1
        return {"text": f"dynamic content instance #{calls['n']}", "status_code": 200}

    session = make_session(handler=handler)
    result = HTTPParameterPollutionScanner(session).scan(Target(url="http://x.local/api"))
    assert result == []


def test_not_flagged_when_duplicate_param_makes_no_difference(make_session):
    session = make_session(text="same response regardless of params", status_code=200)
    result = HTTPParameterPollutionScanner(session).scan(Target(url="http://x.local/api"))
    assert result == []


def test_polluted_url_correctly_built_when_target_already_has_a_query_string(make_session):
    # Regression test: the polluted-parameter URL used to be built with a hardcoded
    # '?' regardless of whether target.url already had a query string, producing a
    # malformed "...?existing=1?id=1&id=2" URL that didn't test what it claimed to.
    seen_urls = []

    def handler(method, url, **kw):
        seen_urls.append(url)
        return {"text": "stable response", "status_code": 200}

    session = make_session(handler=handler)
    HTTPParameterPollutionScanner(session).scan(Target(url="http://x.local/item?existing=1"))

    assert seen_urls, "expected at least one request"
    assert all(url.count("?") == 1 for url in seen_urls), seen_urls
