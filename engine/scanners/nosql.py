"""
NoSQL Injection Scanner
Tests for NoSQL injection vulnerabilities (MongoDB, etc.)

Detection is evidence-based, mirroring CommandInjectionScanner's baseline+control
approach:
  * Boolean-differential: sends a real bracket-notation operator injection
    (e.g. ``id[$ne]=`` — the wire format Express/Mongoose etc. actually parse into
    ``{id: {$ne: ""}}``) that should always match, alongside a control value that
    should never match. Only a real query-logic difference between the two counts
    as evidence. The previous implementation sent ``str({'$ne': None})`` as a flat
    query value, which servers see as a literal string, not an operator — it could
    never trigger genuine NoSQL injection.
  * Error-based: only strong, MongoDB/CouchDB-specific error signatures, and only
    if the signature is absent from a payload-free baseline (not merely present
    somewhere on the page).
"""
from typing import List
import logging
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)


class NoSQLInjectionScanner(BaseScanner):
    """Scanner for detecting NoSQL injection vulnerabilities"""

    # Only strings that are strong, NoSQL-specific evidence of a broken query.
    # Generic words like 'mongo', 'NoSQL', 'invalid query', 'database error' were
    # removed — they can appear on ordinary pages (marketing copy, docs) that have
    # nothing to do with an injection.
    ERROR_INDICATORS = [
        'MongoError',
        'MongooseError',
        'unknown operator',
        'unknown top level operator',
        'CastError',
        'BSONError',
        'E11000 duplicate key',
        "Cannot use '\\$where'",
        'CouchDB Error',
    ]

    def __init__(self, session):
        super().__init__(session)
        self.name = "NoSQL Injection Scanner"

    def _baseline(self, target: Target, param: str) -> str:
        """Payload-free control request; establishes the page's normal body so an
        error signature is only trusted if the payload actually introduced it."""
        try:
            response = self.session.get(target.url, params={param: 'miku_beam_baseline_1'}, timeout=5)
            return response.text.lower()
        except Exception:
            return ""

    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for NoSQL Injection vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting NoSQL scan on {target.url}")

        params = ['id', 'user', 'username', 'search', 'q']

        for param in params:
            if callback:
                callback(f"NoSQL operator injection on '{param}'")

            baseline_text = self._baseline(target, param)

            # --- Boolean-differential: a real operator vs. a value that cannot match ---
            try:
                sep = '&' if '?' in target.url else '?'
                # $ne against a fixed sentinel matches any document where the field is
                # simply not equal to that (near-universally true) sentinel.
                true_url = f"{target.url}{sep}{param}[$ne]=miku_beam_impossible_9f8e7d6c"
                # A value nothing will ever equal — the query-logic control.
                false_url = f"{target.url}{sep}{param}[$eq]=miku_beam_impossible_9f8e7d6c"

                true_resp = self.session.get(true_url, timeout=5)
                false_resp = self.session.get(false_url, timeout=5)

                true_len = len(true_resp.content or b"")
                false_len = len(false_resp.content or b"")

                # Require a real, large divergence (not just a few bytes of noise)
                # AND that both branches actually succeeded — both are needed to
                # call this a genuine boolean-differential rather than two pages that
                # simply render slightly differently every time.
                meaningfully_more_data = true_len > false_len * 1.5 and true_len - false_len > 20
                if true_resp.status_code == 200 and false_resp.status_code == 200 and meaningfully_more_data:
                    # Confirm the divergence is caused by the operator and not by
                    # page-to-page noise unrelated to it (a randomized "related items"
                    # widget, rotating ads, request-order-dependent rate limiting):
                    # re-issue the SAME true_url and require its size to reproduce.
                    # A genuinely operator-driven response is stable; noise is not.
                    confirm_resp = self.session.get(true_url, timeout=5)
                    confirm_len = len(confirm_resp.content or b"")
                    reproducible = (
                        confirm_resp.status_code == 200
                        and abs(confirm_len - true_len) < max(20, true_len * 0.1)
                    )

                    if reproducible:
                        vulnerabilities.append(Vulnerability(
                            name="NoSQL Injection (Boolean-Based)",
                            severity="HIGH",
                            description=(
                                f"The '{param}' parameter appears to accept MongoDB-style operator injection: "
                                "a '$ne' condition (matches almost anything) returned substantially more data "
                                "than a '$eq' condition against an impossible value, reproducibly."
                            ),
                            evidence=(
                                f"True branch ({param}[$ne]=...): {true_resp.status_code}, {true_len} bytes "
                                f"(reproduced at {confirm_len} bytes). "
                                f"False branch ({param}[$eq]=...): {false_resp.status_code}, {false_len} bytes."
                            ),
                            url=true_url,
                            recommendation="Reject non-scalar/operator input on fields used in database queries; validate and cast types server-side before querying.",
                            proof_of_concept=f"curl '{true_url}'",
                        ))
                        logger.warning(f"NoSQL boolean-differential injection found at {true_url}")
                        return vulnerabilities  # strong signal found, stop here

            except Exception as e:
                logger.debug(f"Error testing NoSQL boolean-differential on {param}: {e}")

            # --- Error-based (baseline-gated) ---
            try:
                error_url = f"{target.url}{'&' if '?' in target.url else '?'}{param}[$where]=this.constructor.constructor"
                error_resp = self.session.get(error_url, timeout=5)
                error_text_lower = error_resp.text.lower()

                for indicator in self.ERROR_INDICATORS:
                    indicator_lower = indicator.lower()
                    if indicator_lower in error_text_lower and indicator_lower not in baseline_text:
                        vulnerabilities.append(Vulnerability(
                            name="NoSQL Injection (Error-Based)",
                            severity="HIGH",
                            description=f"Application discloses a NoSQL/query-engine error triggered by a malformed operator on '{param}', indicating unsanitized input reaches the query layer.",
                            evidence=f"Parameter: {param}\nError signature: {indicator} (absent from the payload-free baseline)\nResponse preview: {error_resp.text[:300]}",
                            url=error_url,
                            recommendation="Validate and sanitize all input used in database queries; never pass raw client input as a query operator.",
                            proof_of_concept=f"curl '{error_url}'",
                        ))
                        logger.warning(f"NoSQL error-based injection found at {error_url}")
                        return vulnerabilities

            except Exception as e:
                logger.debug(f"Error testing NoSQL error-based on {param}: {e}")

        return vulnerabilities
