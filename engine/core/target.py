from dataclasses import dataclass, field
from typing import List, Dict, Optional
from urllib.parse import urlparse

@dataclass
class Target:
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    
    # Recon data
    ip_address: Optional[str] = None
    server_header: Optional[str] = None
    tech_stack: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    
    # Enhanced Recon Data
    subdomains: List[str] = field(default_factory=list)
    subdirectories: List[str] = field(default_factory=list)
    open_ports: List[Dict] = field(default_factory=list)
    detailed_tech_stack: Dict = field(default_factory=dict)
    # URLs found by the crawler. Previously set dynamically (profiler.py did
    # `target.discovered_urls = ...` without this being a declared field) --
    # harmless for plain attribute access, but silently dropped by
    # dataclasses.replace(), which only carries declared fields into the copy
    # (needed by engine/core/endpoint_selection.py to build per-endpoint Targets).
    discovered_urls: List[str] = field(default_factory=list)

    @property
    def domain(self) -> str:
        return urlparse(self.url).netloc

    @property
    def scheme(self) -> str:
        return urlparse(self.url).scheme
