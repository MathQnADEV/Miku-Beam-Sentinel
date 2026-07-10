"""
Mass Assignment Scanner
Tests for over-posting vulnerabilities
"""
import logging
from .base import BaseScanner, Vulnerability
from typing import List
from ..core.target import Target

logger = logging.getLogger(__name__)

class MassAssignmentScanner(BaseScanner):
    """Scanner for detecting mass assignment vulnerabilities"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "Mass Assignment Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for Mass Assignment vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting Mass Assignment scan on {target.url}")
        
        # Privileged fields a client should never be able to set. 'price'/'status'
        # were removed: they are ordinary API response keys, so seeing them proves
        # nothing.
        test_fields = {
            'is_admin': True,
            'is_superuser': True,
            'role': 'admin',
            'admin': True,
            'permissions': 'all',
        }

        try:
            # Test POST with privileged fields
            response = self.session.post(
                target.url,
                json=test_fields,
                timeout=5
            )

            body = response.text or ""
            if response.status_code in (200, 201):
                for field in test_fields:
                    # Require the field to be echoed back as a JSON *key* (e.g. "is_admin":).
                    # A normal page won't do that; the bare word appearing anywhere is
                    # not evidence. Reported as a candidate for manual review, not HIGH.
                    if f'"{field}"' in body:
                        vulnerabilities.append(Vulnerability(
                            name="Possible Mass Assignment",
                            severity="MEDIUM",
                            description="The endpoint echoed a privileged field back after it was submitted, which MAY indicate the field was bound to the object (over-posting). Manual verification required.",
                            evidence=f"Submitted privileged field '{field}' was reflected as a key in the response (HTTP {response.status_code}).",
                            url=target.url,
                            recommendation="Use allow-lists (explicit DTOs / serializer field lists) so clients cannot set privileged attributes.",
                        ))
                        break
                        
        except Exception as e:
            logger.debug(f"Error testing mass assignment: {e}")
        
        return vulnerabilities
