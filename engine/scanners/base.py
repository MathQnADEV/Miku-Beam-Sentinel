from abc import ABC, abstractmethod
from typing import List, Dict
from ..core.target import Target
import requests

class Vulnerability:
    def __init__(self, name: str, description: str, severity: str, evidence: str,
                 url: str = None, recommendation: str = None, proof_of_concept: str = None):
        self.name = name
        self.description = description
        self.severity = severity
        self.evidence = evidence
        self.url = url
        self.recommendation = recommendation
        self.proof_of_concept = proof_of_concept

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "url": self.url,
            "recommendation": self.recommendation,
            "proof_of_concept": self.proof_of_concept,
        }

class BaseScanner(ABC):
    # A path that should never legitimately exist, used to detect servers that
    # answer 2xx for everything (SPAs, catch-all routers). Fixed (not random) so
    # behaviour is deterministic and testable.
    NONEXISTENT_PROBE = "/miku-beam-nonexistent-9x7q2z"

    def __init__(self, session: requests.Session):
        self.session = session

    def server_soft_404s(self, base_url: str, timeout: int = 5) -> bool:
        """Return True if the server answers 2xx for a path that cannot exist.

        When it does, a 200 on any guessed path (``/admin``, ``/.env`` …) carries
        no signal, so scanners must not treat "200" as "resource found". Fails
        safe: on any error it returns False (do not suppress findings on error).
        """
        try:
            probe = base_url.rstrip("/") + self.NONEXISTENT_PROBE
            resp = self.session.get(probe, timeout=timeout)
            return 200 <= resp.status_code < 300
        except Exception:
            return False

    @abstractmethod
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """
        Scan the target for vulnerabilities
        
        Args:
            target: Target object containing URL and metadata
            callback: Optional function to call with progress updates (e.g. payload tested)
            
        Returns:
            List of Vulnerability objects found
        """
        raise NotImplementedError("Subclasses must implement scan method")
