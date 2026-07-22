"""Tests for issue #5's query-string helpers (engine/core/url_utils.py).

Scanners historically built test URLs by string concatenation, which can only
ever APPEND a parameter -- fuzzing a parameter the crawler actually discovered
(e.g. "?id=42") requires REPLACING its existing value instead.
"""
from urllib.parse import parse_qsl, urlsplit

from engine.core.url_utils import get_query_params, merge_params, set_query_param


# ---- get_query_params --------------------------------------------------------

def test_get_query_params_returns_names_in_order_without_duplicates():
    assert get_query_params("http://x.local/search?q=foo&cat=bar") == ["q", "cat"]


def test_get_query_params_dedupes_repeated_names():
    assert get_query_params("http://x.local/search?id=1&id=2&tag=x") == ["id", "tag"]


def test_get_query_params_empty_for_url_with_no_query():
    assert get_query_params("http://x.local/search") == []


# ---- set_query_param ---------------------------------------------------------

def test_set_query_param_replaces_existing_value_in_place():
    result = set_query_param("http://x.local/search?q=foo&cat=bar", "q", "PAYLOAD")
    assert result == "http://x.local/search?q=PAYLOAD&cat=bar"


def test_set_query_param_appends_when_param_absent():
    result = set_query_param("http://x.local/search?cat=bar", "q", "PAYLOAD")
    parsed = dict(parse_qsl(urlsplit(result).query))
    assert parsed == {"cat": "bar", "q": "PAYLOAD"}


def test_set_query_param_appends_when_url_has_no_query_at_all():
    result = set_query_param("http://x.local/search", "q", "PAYLOAD")
    assert urlsplit(result).path == "/search"
    assert dict(parse_qsl(urlsplit(result).query)) == {"q": "PAYLOAD"}


def test_set_query_param_drops_further_duplicates_of_the_same_name():
    # id=1&id=2 -> only ONE id survives, holding the new value -- a duplicate
    # query key resolves inconsistently across frameworks (first-wins/last-
    # wins/array), so a genuine fuzz must leave exactly one.
    result = set_query_param("http://x.local/x?id=1&id=2&tag=z", "id", "PAYLOAD")
    pairs = parse_qsl(urlsplit(result).query)
    assert pairs.count(("id", "PAYLOAD")) == 1
    assert ("id", "1") not in pairs and ("id", "2") not in pairs
    assert ("tag", "z") in pairs


def test_set_query_param_percent_encodes_special_characters():
    result = set_query_param("http://x.local/x", "q", "' AND SLEEP(5)--")
    assert "SLEEP(5)" not in result  # raw parens must not survive unencoded
    assert dict(parse_qsl(urlsplit(result).query))["q"] == "' AND SLEEP(5)--"


def test_set_query_param_preserves_other_params_and_their_order():
    result = set_query_param("http://x.local/x?a=1&b=2&c=3", "b", "NEW")
    assert parse_qsl(urlsplit(result).query) == [("a", "1"), ("b", "NEW"), ("c", "3")]


# ---- merge_params -------------------------------------------------------------

def test_merge_params_discovered_first_then_guessed_deduped():
    assert merge_params(["q", "cat"], ["id", "q", "user"]) == ["q", "cat", "id", "user"]


def test_merge_params_with_no_discovered_params_is_just_the_guessed_list():
    assert merge_params([], ["id", "q"]) == ["id", "q"]
