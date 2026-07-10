
"""
JWT Vulnerabilities Scanner
Tests for JWT-specific security issues
"""
import logging
import base64
import json
from typing import List
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)

class JWTScanner(BaseScanner):
    """Scanner for detecting JWT vulnerabilities"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "JWT Vulnerabilities Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for JWT vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting JWT scan on {target.url}")
        
        try:
            response = self.session.get(target.url, timeout=5)
            
            # Check Authorization header for JWT
            jwt_token = None
            if 'Authorization' in response.headers:
                auth_header = response.headers['Authorization']
                if 'Bearer ' in auth_header:
                    jwt_token = auth_header.split('Bearer ')[1]
            
            # Also check for JWT in response body
            if 'eyJ' in response.text:  # JWT tokens start with eyJ
                import re
                tokens = re.findall(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', response.text)
                if tokens:
                    jwt_token = tokens[0]
            
            if jwt_token:
                # Decode JWT header
                try:
                    parts = jwt_token.split('.')
                    if len(parts) >= 2:
                        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                        
                        # Only the 'none' algorithm is a vulnerability on its own
                        # (it disables signature verification). HS256/384/512 are
                        # normal, secure choices — flagging them was a false positive
                        # (the RS256->HS256 key-confusion attack can't be inferred
                        # just from seeing an HS256 token).
                        if header.get('alg') == 'none':
                            vulnerabilities.append(Vulnerability(
                                name="JWT None Algorithm",
                                severity="CRITICAL",
                                description="JWT uses 'none' algorithm, allowing signature bypass",
                                evidence=f"JWT header: {header}",
                                url=target.url
                            ))

                except Exception as e:
                    logger.debug(f"Error decoding JWT: {e}")
                    
        except Exception as e:
            logger.error(f"Error during JWT scan: {e}")
        
        return vulnerabilities
