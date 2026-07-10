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
    def __init__(self, session: requests.Session):
        self.session = session

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
