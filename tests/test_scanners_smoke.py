"""Smoke tests: every scanner must instantiate and run offline without raising.

This is the regression guard for the class of bug where a scanner references an
undefined attribute (e.g. the old ``BOLAScanner`` `self.PAYLOADS` crash that aborted
``--scan-all``). A CI run of this file would have caught it.
"""
import inspect

import pytest

from engine import scanners as S
from engine.scanners.base import BaseScanner, Vulnerability
from engine.core.target import Target

ALL_SCANNERS = [
    getattr(S, name)
    for name in dir(S)
    if inspect.isclass(getattr(S, name))
    and issubclass(getattr(S, name), BaseScanner)
    and getattr(S, name) is not BaseScanner
]


def test_all_23_scanner_modules_exported():
    assert len(ALL_SCANNERS) == 23


@pytest.mark.parametrize("scanner_cls", ALL_SCANNERS, ids=[c.__name__ for c in ALL_SCANNERS])
def test_scanner_runs_offline_without_crashing(scanner_cls, fake_session):
    target = Target(url="http://testserver.local/api/items/5?id=1")
    result = scanner_cls(fake_session).scan(target)
    assert isinstance(result, list)
    assert all(isinstance(v, Vulnerability) for v in result)


@pytest.mark.parametrize("scanner_cls", ALL_SCANNERS, ids=[c.__name__ for c in ALL_SCANNERS])
def test_scanner_accepts_callback(scanner_cls, fake_session):
    """scan() must accept the optional progress callback used by the web executor."""
    seen = []
    target = Target(url="http://testserver.local/api/items/5")
    scanner_cls(fake_session).scan(target, callback=seen.append)
    # We don't require callbacks to fire, only that passing one doesn't break.
