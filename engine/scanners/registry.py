"""
Declarative scanner registry (issue #6).

Scanner selection used to be hand-duplicated in two places -- a
tech-stack-driven `_select_scanners` in `web/backend/projects/scan_executor.py`
and a 23-branch `if args.scan_all or args.scan_xxx:` copy-paste in
`cli/main.py` -- and the web path could never reach 10 of the 23 modules
(LDAP, XPath, XML, OAuth, HPP, RateLimit, MassAssignment, BusinessLogic,
Logging, Auth) while SQLi/NoSQL were gated on a `database` string that is
almost always "Unknown", silently skipping the flagship SQL scanner.

This module is the single source of truth both consumers now use. Each entry
declares an `applies_to` predicate over the detected tech stack; a scanner is
included BY DEFAULT unless there is confident, positive evidence it doesn't
apply -- "Unknown" tech means "run it", not "skip it". Only the
database-flavoured injection scanners (SQL vs NoSQL) and the GraphQL scanner
have a real, differentiating predicate: passive HTTP fingerprinting can't
reliably rule out most other vulnerability classes (XXE/SSTI/LDAP/XPath/OAuth
apply to far more stacks than their "traditional" association suggests), so
attempting to gate them on detected tech would mean guessing, not evidence.
"""
from dataclasses import dataclass
from typing import Callable, Dict, List, Type

from .base import BaseScanner
from .injection import SQLInjectionScanner
from .xss import XSSScanner
from .cmdi import CommandInjectionScanner
from .bola import BOLAScanner
from .ssrf import SSRFScanner
from .xxe import XXEScanner
from .auth import AuthScanner
from .access_control import BrokenAccessControlScanner
from .misconfig import SecurityMisconfigurationScanner
from .data_exposure import SensitiveDataExposureScanner
from .nosql import NoSQLInjectionScanner
from .graphql import GraphQLInjectionScanner
from .ssti import SSTIScanner
from .ldap import LDAPInjectionScanner
from .xpath import XPathInjectionScanner
from .xml_injection import XMLInjectionScanner
from .jwt import JWTScanner
from .oauth import OAuthScanner
from .hpp import HTTPParameterPollutionScanner
from .rate_limit import RateLimitScanner
from .mass_assignment import MassAssignmentScanner
from .business_logic import BusinessLogicScanner
from .logging import LoggingScanner

TechStack = Dict


def _always(tech: TechStack) -> bool:
    return True


_SQL_MARKERS = ('mysql', 'mariadb', 'postgres', 'mssql', 'oracle', 'sqlite')
_NOSQL_MARKERS = ('mongo', 'couchdb', 'redis', 'cassandra')


def _as_lower_str(value) -> str:
    """Best-effort, crash-proof lowercased string. A malformed tech_stack value
    (wrong type, None) degrades to an empty string — treated the same as
    "Unknown" by the predicates below — rather than raising, matching this
    registry's "can't tell -> run it" philosophy for the data itself too."""
    if not value:
        return ''
    try:
        return str(value).lower()
    except Exception:
        return ''


def _as_lower_str_list(value) -> List[str]:
    """Best-effort, crash-proof list of lowercased strings, tolerating a non-
    list value or None/non-string elements."""
    if not value:
        return []
    try:
        return [_as_lower_str(item) for item in value if item]
    except TypeError:
        return []  # value wasn't iterable at all (e.g. an int)


def _sql_family(tech: TechStack) -> bool:
    """Exclude only when the (inferred) database is confidently NoSQL-only —
    e.g. a Django/Laravel/ASP.NET backend was detected with no NoSQL hint at
    all. An "Unknown"/empty database (the common case) can't rule SQL out."""
    db = _as_lower_str(tech.get('database'))
    if not db or db == 'unknown':
        return True
    is_sql = any(marker in db for marker in _SQL_MARKERS)
    is_nosql = any(marker in db for marker in _NOSQL_MARKERS)
    return is_sql or not is_nosql


def _nosql_family(tech: TechStack) -> bool:
    """Exclude only when the (inferred) database is confidently SQL-only."""
    db = _as_lower_str(tech.get('database'))
    if not db or db == 'unknown':
        return True
    is_sql = any(marker in db for marker in _SQL_MARKERS)
    is_nosql = any(marker in db for marker in _NOSQL_MARKERS)
    return is_nosql or not is_sql


def _graphql_relevant(tech: TechStack) -> bool:
    """Exclude only when frameworks WERE confidently detected and GraphQL
    isn't among them; an empty/unknown frameworks list can't rule it out."""
    frameworks = _as_lower_str_list(tech.get('frameworks'))
    return not frameworks or 'graphql' in frameworks


@dataclass(frozen=True)
class ScannerSpec:
    key: str                                    # CLI flag suffix: --scan-<key>
    label: str                                   # human-readable name (CLI help / logs)
    scanner_class: Type[BaseScanner]
    applies_to: Callable[[TechStack], bool] = _always


# Order is preserved by every consumer (CLI flag/help order, web scan order).
REGISTRY: List[ScannerSpec] = [
    ScannerSpec('sqli', 'SQL Injection', SQLInjectionScanner, _sql_family),
    ScannerSpec('xss', 'Cross-Site Scripting', XSSScanner),
    ScannerSpec('cmdi', 'Command Injection', CommandInjectionScanner),
    ScannerSpec('bola', 'BOLA/IDOR', BOLAScanner),
    ScannerSpec('ssrf', 'SSRF', SSRFScanner),
    ScannerSpec('xxe', 'XXE', XXEScanner),
    ScannerSpec('auth', 'Broken Authentication', AuthScanner),
    ScannerSpec('access', 'Broken Access Control', BrokenAccessControlScanner),
    ScannerSpec('misconfig', 'Security Misconfiguration', SecurityMisconfigurationScanner),
    ScannerSpec('data', 'Sensitive Data Exposure', SensitiveDataExposureScanner),
    ScannerSpec('nosql', 'NoSQL Injection', NoSQLInjectionScanner, _nosql_family),
    ScannerSpec('graphql', 'GraphQL Injection', GraphQLInjectionScanner, _graphql_relevant),
    ScannerSpec('ssti', 'SSTI', SSTIScanner),
    ScannerSpec('ldap', 'LDAP Injection', LDAPInjectionScanner),
    ScannerSpec('xpath', 'XPath Injection', XPathInjectionScanner),
    ScannerSpec('xml', 'XML Injection', XMLInjectionScanner),
    ScannerSpec('jwt', 'JWT Vulnerabilities', JWTScanner),
    ScannerSpec('oauth', 'OAuth Misconfigurations', OAuthScanner),
    ScannerSpec('hpp', 'HTTP Parameter Pollution', HTTPParameterPollutionScanner),
    ScannerSpec('ratelimit', 'Rate Limiting Issues', RateLimitScanner),
    ScannerSpec('mass', 'Mass Assignment', MassAssignmentScanner),
    ScannerSpec('logic', 'Business Logic Flaws', BusinessLogicScanner),
    ScannerSpec('logging', 'Insufficient Logging', LoggingScanner),
]

if len({spec.key for spec in REGISTRY}) != len(REGISTRY):
    # Not a bare assert: assertions are stripped under `python -O`, which would
    # silently drop this invariant check in an optimized run.
    raise ValueError("duplicate scanner key in REGISTRY")


def select_scanners(tech_stack: TechStack, session) -> List[BaseScanner]:
    """Instantiate every scanner whose predicate matches the given tech stack.

    Used for automatic ("smart") selection, e.g. the web scan flow. The CLI's
    explicit --scan-<key> flags intentionally bypass this (a user who asks for
    a specific scanner gets it regardless of detected tech) and instead
    iterate REGISTRY directly.
    """
    tech_stack = tech_stack or {}
    return [spec.scanner_class(session) for spec in REGISTRY if spec.applies_to(tech_stack)]
