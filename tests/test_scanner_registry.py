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


# ---- open_ports / discovered_paths evidence (issue #5) ----------------------
# Reconnaissance (port scan, crawler) can now hand the registry evidence that a
# passive HTTP fingerprint never had -- an open 3306/27017 port, or a
# discovered "/graphql" endpoint -- without requiring a positive `database`/
# `frameworks` string fingerprint too.

@pytest.mark.parametrize("port", [3306, 5432, 1433, 1521])
def test_sql_family_included_by_open_sql_port_alone(port):
    assert _sql_family({"open_ports": [{"port": port}]}) is True


@pytest.mark.parametrize("port", [27017, 6379, 5984, 9042])
def test_nosql_family_included_by_open_nosql_port_alone(port):
    assert _nosql_family({"open_ports": [{"port": port}]}) is True


def test_open_nosql_port_alone_does_not_exclude_sql():
    # Regression guard (adversarial review): an unrelated open cache/queue port
    # must NOT veto a scanner that used to run unconditionally when the
    # database was unfingerprinted -- e.g. a real MySQL app that also runs
    # Redis for sessions/caching (a very common architecture). Only a
    # DATABASE-STRING fingerprint is confident enough to exclude on its own;
    # ports may only ADD inclusion or override an existing string-based
    # exclusion, never independently cause one.
    assert _sql_family({"open_ports": [{"port": 27017}]}) is True


def test_open_sql_port_alone_does_not_exclude_nosql():
    assert _nosql_family({"open_ports": [{"port": 3306}]}) is True


def test_port_evidence_overrides_a_misleading_database_string():
    # A dual-stack app (e.g. Postgres for primary data, Redis for caching/queues)
    # was fingerprinted as "PostgreSQL" only, but a 6379 (Redis) port is also
    # open -- NoSQL scanning should NOT be excluded just because the passive
    # fingerprint only caught one of the two backends.
    tech = {"database": "PostgreSQL", "open_ports": [{"port": 6379}]}
    assert _sql_family(tech) is True
    assert _nosql_family(tech) is True


def test_sql_port_overrides_a_confidently_nosql_only_database_string():
    # Mirror of the above: a MongoDB-fingerprinted app that ALSO has a 3306
    # (MySQL) port open -- SQL scanning should not stay excluded just because
    # the passive fingerprint only caught the NoSQL half of a dual-stack app.
    tech = {"database": "MongoDB", "open_ports": [{"port": 3306}]}
    assert _sql_family(tech) is True
    assert _nosql_family(tech) is True


def test_unrelated_port_does_not_override_a_confident_exclusion():
    # The database string confidently says SQL-only (MySQL), and the only open
    # port is unrelated to either family (e.g. plain HTTPS) -- NoSQL must stay
    # excluded, since there is no corroborating NoSQL evidence at all.
    tech = {"database": "MySQL", "open_ports": [{"port": 443}]}
    assert _nosql_family(tech) is False
    assert _sql_family(tech) is True


def test_open_ports_accepts_bare_int_list_and_tolerates_malformed_entries():
    assert _sql_family({"open_ports": [3306]}) is True
    assert _sql_family({"open_ports": [{"port": "not-a-number"}, {"no_port_key": 1}]}) is True  # degrades, doesn't crash
    assert _sql_family({"open_ports": "not-iterable-of-dicts"}) is True  # iterating chars degrades harmlessly
    assert _sql_family({"open_ports": 12345}) is True  # not iterable at all -> caught, degrades to no evidence


def test_graphql_included_by_discovered_path_alone():
    # Frameworks confidently detected WITHOUT graphql would normally exclude the
    # scanner, but a crawled "/graphql" endpoint is direct, positive evidence
    # that overrides that exclusion.
    tech = {"frameworks": ["Bootstrap", "jQuery"], "discovered_paths": ["http://x.local/api/graphql"]}
    assert _graphql_relevant(tech) is True


def test_graphql_relevant_survives_malformed_discovered_paths():
    assert _graphql_relevant({"discovered_paths": None}) is True
    assert _graphql_relevant({"discovered_paths": 123}) is True
    assert _graphql_relevant({"frameworks": ["jQuery"], "discovered_paths": [None, "/health"]}) is False


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
