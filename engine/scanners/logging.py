"""
Insufficient Logging & Monitoring Scanner

Insufficient logging/monitoring is a server-side property that cannot be reliably
observed over HTTP from the outside, so this scanner intentionally emits no findings.
The previous heuristics were removed because they were unsound:
  - flagging "generic login error messages" as a vulnerability was backwards —
    generic errors are the recommended defence against username enumeration; and
  - probing /logs, /metrics, … and judging by response length produced false
    positives on SPAs and catch-all routers.

Kept as a no-op placeholder; real coverage belongs in a future authenticated /
behavioural check (see the roadmap).
"""
import logging
from typing import List
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)


class LoggingScanner(BaseScanner):
    """Placeholder: insufficient logging is not detectable over HTTP (no findings)."""

    def __init__(self, session):
        super().__init__(session)
        self.name = "Logging & Monitoring Scanner"

    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        logger.info(f"Logging scan on {target.url}: no HTTP-observable checks (skipped)")
        return []
