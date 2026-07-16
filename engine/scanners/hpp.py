"""
HTTP Parameter Pollution Scanner
Tests for HPP vulnerabilities
"""
from typing import List
import logging
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)

class HTTPParameterPollutionScanner(BaseScanner):
    """Scanner for detecting HTTP Parameter Pollution"""

    def __init__(self, session):
        super().__init__(session)
        self.name = "HTTP Parameter Pollution Scanner"

    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for HPP vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting HPP scan on {target.url}")

        try:
            # Baseline stability check: two IDENTICAL requests (same single param,
            # no duplication) must match before we trust any later diff. Many pages
            # embed timestamps, CSRF tokens, nonces, or randomized content, so a raw
            # body diff between requests is not by itself evidence of anything —
            # without this gate, the pollution check below would fire on any dynamic
            # page regardless of how it handles duplicate parameters.
            baseline_a = self.session.get(target.url, params={'id': '1'}, timeout=5)
            baseline_b = self.session.get(target.url, params={'id': '1'}, timeout=5)

            if baseline_a.text != baseline_b.text:
                logger.info(
                    "Page content is not stable across identical requests "
                    "(dynamic content); skipping HPP diff as the signal would be unreliable"
                )
                return vulnerabilities

            # Now that we know the page is stable, a real difference introduced by
            # duplicating the parameter is meaningful. Use the same separator logic
            # as the baseline calls (and every other scanner in this codebase) —
            # target.url may already carry its own query string.
            sep = '&' if '?' in target.url else '?'
            polluted_response = self.session.get(f"{target.url}{sep}id=1&id=2", timeout=5)

            if polluted_response.status_code == 200 and polluted_response.text != baseline_a.text:
                vulnerabilities.append(Vulnerability(
                    name="HTTP Parameter Pollution",
                    severity="MEDIUM",
                    description="Application handles duplicate parameters inconsistently: submitting the same parameter twice with different values changed the response, even though the page is otherwise stable across identical requests.",
                    evidence=(
                        f"Two identical requests with id=1 returned identical bodies (page is stable), "
                        f"but adding a duplicate id=2 changed the response."
                    ),
                    url=target.url,
                    recommendation="Explicitly define how duplicate parameters are handled (reject, or consistently use first/last) at the framework or application layer.",
                    proof_of_concept=f"curl '{target.url}?id=1&id=2'",
                ))
                logger.warning(f"HTTP Parameter Pollution detected at {target.url}")

        except Exception as e:
            logger.debug(f"Error testing HPP: {e}")

        return vulnerabilities
