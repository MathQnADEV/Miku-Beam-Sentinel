"""
API Rate Limiting Scanner
Tests for missing rate limiting
"""
import logging
import time
from typing import List
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)

class RateLimitScanner(BaseScanner):
    """Scanner for detecting missing rate limiting"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "Rate Limiting Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for Rate Limiting vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting Rate Limit scan on {target.url}")
        
        try:
            # Send multiple rapid requests
            num_requests = 20
            successful_requests = 0
            rate_limited = False

            for i in range(num_requests):
                response = self.session.get(target.url, timeout=5)
                if response.status_code in (429, 503):
                    rate_limited = True
                    break
                if response.status_code == 200:
                    successful_requests += 1

            # 20 requests is nowhere near enough to *prove* rate limiting is absent, so
            # this is reported as low-confidence INFO and only when we never saw a 429/503.
            if not rate_limited and successful_requests >= num_requests * 0.9:
                vulnerabilities.append(Vulnerability(
                    name="No Rate Limiting Observed",
                    severity="INFO",
                    description=(
                        f"No rate limiting (HTTP 429/503) was triggered within {num_requests} rapid "
                        "requests. Informational and NOT conclusive — confirm with a proper load test "
                        "against authentication or other sensitive endpoints."
                    ),
                    evidence=f"{successful_requests}/{num_requests} rapid requests returned 200; no 429/503 seen.",
                    url=target.url,
                    recommendation="Apply rate limiting / throttling to authentication and expensive endpoints.",
                ))

        except Exception as e:
            logger.debug(f"Error testing rate limiting: {e}")
        
        return vulnerabilities
