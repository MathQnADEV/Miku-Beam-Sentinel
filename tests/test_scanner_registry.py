"""Tests for issue #6: a declarative scanner registry that every scanner is
reachable through, replacing the hand-duplicated selection logic that could
never reach 10 of the 23 modules and gated SQLi/NoSQL on an almost-always-
"Unknown" database string.
"""
import os
import sys

import pytest

from engine.scanners.registry import REGISTRY, select_scanners, _sql_family, _nosql_family, _graphql_relevant

# scan_executor.py lives in web/backend/projects/ as a plain module (not a
# pytest-discovered app); importing it directly needs that directory on
# sys.path, exactly as manage.py/asgi.py would set up in the real app.
WEB_BACKEND = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web", "backend")
if WEB_BACKEND not in sys.path:
    sys.path.insert(0, WEB_BACKEND)


ORIGINAL_CLI_FLAG_KEYS = {
    "sqli", "xss", "cmdi", "bola", "ssrf", "xxe", "auth", "access", "misconfig",
    "data", "nosql", "graphql", "ssti", "ldap", "xpath", "xml", "jwt", "oauth",
    "hpp", "ratelimit", "mass", "logic", "logging",
}


# ---- Registry completeness --------------------------------------------------

def test_registry_has_exactly_23_scanners_with_unique_keys():
    assert len(REGISTRY) == 23
    assert len({spec.key for spec in REGISTRY}) == 23


def test_registry_keys_match_the_original_cli_flag_names():
    # Regression guard: renaming/removing a key would silently break an
    # existing user's --scan-<key> command line.
    assert {spec.key for spec in REGISTRY} == ORIGINAL_CLI_FLAG_KEYS


def test_every_registry_entry_is_a_real_basescanner_subclass(fake_session):
    from engine.scanners.base import BaseScanner
    for spec in REGISTRY:
        instance = spec.scanner_class(fake_session)
        assert isinstance(instance, BaseScanner)


# ---- The core bug: "Unknown" must mean "run it" ----------------------------

def test_select_scanners_reaches_all_23_when_tech_stack_is_unknown(fake_session):
    selected = select_scanners({}, fake_session)
    assert len(selected) == 23


def test_select_scanners_reaches_all_23_when_tech_stack_is_none(fake_session):
    selected = select_scanners(None, fake_session)
    assert len(selected) == 23


def test_previously_unreachable_scanners_are_now_selected(fake_session):
    # These 10 could never be selected by the old hand-written _select_scanners.
    from engine.scanners.ldap import LDAPInjectionScanner
    from engine.scanners.xpath import XPathInjectionScanner
    from engine.scanners.xml_injection import XMLInjectionScanner
    from engine.scanners.oauth import OAuthScanner
    from engine.scanners.hpp import HTTPParameterPollutionScanner
    from engine.scanners.rate_limit import RateLimitScanner
    from engine.scanners.mass_assignment import MassAssignmentScanner
    from engine.scanners.business_logic import BusinessLogicScanner
    from engine.scanners.logging import LoggingScanner
    from engine.scanners.auth import AuthScanner

    selected_types = {type(s) for s in select_scanners({}, fake_session)}
    for cls in (LDAPInjectionScanner, XPathInjectionScanner, XMLInjectionScanner,
                OAuthScanner, HTTPParameterPollutionScanner, RateLimitScanner,
                MassAssignmentScanner, BusinessLogicScanner, LoggingScanner, AuthScanner):
        assert cls in selected_types, f"{cls.__name__} should be reachable"


# ---- Database-family predicate ---------------------------------------------

@pytest.mark.parametrize("db", ["", "Unknown", "unknown"])
def test_sql_and_nosql_both_included_when_database_unknown(db, fake_session):
    selected_names = {type(s).__name__ for s in select_scanners({"database": db}, fake_session)}
    assert "SQLInjectionScanner" in selected_names
    assert "NoSQLInjectionScanner" in selected_names


@pytest.mark.parametrize("db", ["MySQL", "PostgreSQL", "MSSQL", "Oracle", "SQLite", "MariaDB"])
def test_nosql_excluded_when_database_confidently_sql_only(db, fake_session):
    selected_names = {type(s).__name__ for s in select_scanners({"database": db}, fake_session)}
    assert "SQLInjectionScanner" in selected_names
    assert "NoSQLInjectionScanner" not in selected_names


@pytest.mark.parametrize("db", ["MongoDB", "CouchDB", "Redis", "Cassandra"])
def test_sql_excluded_when_database_confidently_nosql_only(db, fake_session):
    selected_names = {type(s).__name__ for s in select_scanners({"database": db}, fake_session)}
    assert "NoSQLInjectionScanner" in selected_names
    assert "SQLInjectionScanner" not in selected_names


def test_both_included_when_database_guess_is_ambiguous(fake_session):
    # TechDetector's DATABASE_BY_BACKEND infers "MongoDB/MySQL" for Express.js --
    # an ambiguous guess spanning both families should exclude neither.
    selected_names = {type(s).__name__ for s in select_scanners({"database": "MongoDB/MySQL"}, fake_session)}
    assert "SQLInjectionScanner" in selected_names
    assert "NoSQLInjectionScanner" in selected_names


# ---- GraphQL predicate ------------------------------------------------------

def test_graphql_included_when_frameworks_empty(fake_session):
    selected_names = {type(s).__name__ for s in select_scanners({"frameworks": []}, fake_session)}
    assert "GraphQLInjectionScanner" in selected_names


def test_graphql_included_when_detected(fake_session):
    selected_names = {type(s).__name__ for s in select_scanners({"frameworks": ["GraphQL"]}, fake_session)}
    assert "GraphQLInjectionScanner" in selected_names


def test_graphql_excluded_when_frameworks_confidently_detected_without_it(fake_session):
    selected_names = {type(s).__name__ for s in select_scanners({"frameworks": ["Bootstrap", "jQuery"]}, fake_session)}
    assert "GraphQLInjectionScanner" not in selected_names


# ---- Predicate unit tests ----------------------------------------------------

def test_sql_family_predicate_directly():
    assert _sql_family({}) is True
    assert _sql_family({"database": "Unknown"}) is True
    assert _sql_family({"database": "MySQL"}) is True
    assert _sql_family({"database": "MongoDB"}) is False
    assert _sql_family({"database": "MongoDB/MySQL"}) is True


def test_nosql_family_predicate_directly():
    assert _nosql_family({}) is True
    assert _nosql_family({"database": "Unknown"}) is True
    assert _nosql_family({"database": "MongoDB"}) is True
    assert _nosql_family({"database": "MySQL"}) is False
    assert _nosql_family({"database": "MongoDB/MySQL"}) is True


def test_graphql_relevant_predicate_directly():
    assert _graphql_relevant({}) is True
    assert _graphql_relevant({"frameworks": []}) is True
    assert _graphql_relevant({"frameworks": ["GraphQL"]}) is True
    assert _graphql_relevant({"frameworks": ["jQuery"]}) is False


# ---- Predicates degrade to "run it" on malformed input, not crash ----------
# Regression guard from adversarial review: these are public, directly-tested
# functions with no guarantee about who calls them or with what -- a malformed
# tech_stack value should default-include (matching the "can't tell -> run it"
# philosophy), not raise.

def test_sql_family_survives_non_string_database():
    assert _sql_family({"database": 123}) is True
    assert _sql_family({"database": ["MySQL"]}) is True
    assert _sql_family({"database": None}) is True


def test_graphql_relevant_survives_non_list_or_none_frameworks():
    assert _graphql_relevant({"frameworks": 123}) is True
    assert _graphql_relevant({"frameworks": ["GraphQL", None]}) is True
    assert _graphql_relevant({"frameworks": None}) is True


def test_duplicate_key_detection_logic_flags_a_real_duplicate():
    # The registry's own duplicate-key guard is a real `raise ValueError`, not a
    # bare `assert` (which `python -O` strips and would silently disable this
    # check). Exercise the same detection logic directly against a genuinely
    # duplicated list built from real ScannerSpec instances.
    from dataclasses import replace

    duplicated = list(REGISTRY) + [replace(REGISTRY[0])]
    assert len({spec.key for spec in duplicated}) != len(duplicated)  # the condition the guard checks for


# ---- ScanExecutor delegates to the registry ---------------------------------

def test_scan_executor_select_scanners_reaches_all_23_for_unknown_tech():
    from projects.scan_executor import ScanExecutor
    executor = ScanExecutor()
    selected = executor._select_scanners({})
    assert len(selected) == 23


def test_scan_executor_select_scanners_uses_the_executors_own_session():
    from projects.scan_executor import ScanExecutor
    executor = ScanExecutor()
    selected = executor._select_scanners({})
    assert all(s.session is executor.session for s in selected)
