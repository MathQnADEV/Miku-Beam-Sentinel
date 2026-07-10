"""
Business Logic Flaws Scanner

Business-logic flaws generally cannot be detected reliably without understanding
the application's workflow, so this scanner is deliberately conservative: it only
reports when there is concrete evidence that a manipulated value was accepted AND
reflected back by the endpoint. Otherwise it reports nothing (rather than crying
CRITICAL on every 200 response). Findings are flagged for manual verification.
"""
import logging
from typing import List
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)


class BusinessLogicScanner(BaseScanner):
    """Scanner for detecting *candidate* business logic flaws (needs manual review)."""

    def __init__(self, session):
        super().__init__(session)
        self.name = "Business Logic Scanner"

    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        vulnerabilities = []
        logger.info(f"Starting Business Logic scan on {target.url}")

        # Unusual sentinel values so a match is very unlikely to be coincidental.
        NEG_QTY = -13337
        NEG_AMT = -98765

        try:
            resp = self.session.post(
                target.url,
                json={"quantity": NEG_QTY, "amount": NEG_AMT},
                timeout=8,
            )

            body = resp.text or ""
            accepted = resp.status_code in (200, 201)
            reflected = str(NEG_QTY) in body or str(NEG_AMT) in body

            # Only flag when the endpoint both accepted the request AND echoed the
            # negative sentinel back (strong sign it was processed, not rejected).
            if accepted and reflected:
                vulnerabilities.append(Vulnerability(
                    name="Possible Negative-Value Business Logic Flaw",
                    severity="MEDIUM",
                    description=(
                        "The endpoint accepted a request with negative quantity/amount and reflected "
                        "the negative value in its response. This MAY indicate a business-logic flaw "
                        "(e.g. negative pricing). Manual verification required."
                    ),
                    evidence=f"POST negative sentinel values ({NEG_QTY}/{NEG_AMT}); reflected in response (HTTP {resp.status_code}).",
                    url=target.url,
                    recommendation="Validate value ranges server-side (reject non-positive quantities/amounts) and enforce business rules in the backend.",
                ))
                logger.warning(f"Candidate business logic flaw at {target.url} (manual review)")

        except Exception as e:
            logger.debug(f"Error testing business logic: {e}")

        return vulnerabilities
