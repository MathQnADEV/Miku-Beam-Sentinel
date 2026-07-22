"""
Query-string helpers for parameter fuzzing (issue #5).

Scanners historically built test URLs by string concatenation
(``f"{target.url}&{param}={payload}"``), which only ever APPENDS a parameter --
if that name already exists in the URL (e.g. a crawled URL like
``/search?id=42``), appending a second ``id=`` produces a duplicate query key
instead of replacing the real value with the payload, which most frameworks
resolve inconsistently (first-wins, last-wins, or an array). Fuzzing a
discovered parameter requires actually replacing its value.
"""
from typing import Iterable, List, Tuple
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


def get_query_params(url: str) -> List[str]:
    """Return the real parameter names present in url's query string, in
    order of first appearance, without duplicates."""
    query = urlsplit(url).query
    seen = []
    for name, _ in parse_qsl(query, keep_blank_values=True):
        if name not in seen:
            seen.append(name)
    return seen


def set_query_param(url: str, param: str, value: str) -> str:
    """Return url with `param` set to `value`, replacing it if already present
    (preserving the position and every other existing parameter) or appending
    it if absent -- the correct fuzzing operation, unlike blind string
    concatenation which can only ever append (and so can produce a duplicate,
    inert query key when the parameter already exists)."""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)

    replaced = False
    new_pairs: List[Tuple[str, str]] = []
    for name, existing_value in pairs:
        if name == param and not replaced:
            new_pairs.append((name, value))
            replaced = True
        elif name == param:
            continue  # drop any further duplicates of the same real param
        else:
            new_pairs.append((name, existing_value))
    if not replaced:
        new_pairs.append((param, value))

    new_query = urlencode(new_pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def merge_params(discovered: Iterable[str], guessed: Iterable[str]) -> List[str]:
    """Real, discovered parameter names first (they're evidence, not a guess),
    followed by the guessed default list, deduplicated while preserving order."""
    merged: List[str] = []
    for name in list(discovered) + list(guessed):
        if name not in merged:
            merged.append(name)
    return merged
