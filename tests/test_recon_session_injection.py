"""Tests for issue #10: reconnaissance modules must accept an injected session
(so an Authenticator's headers/cookies actually reach recon requests) and
DirectoryDiscoverer must size its connection pool to its actual concurrency
level instead of relying on requests' small default.
"""
import requests
from unittest.mock import patch, MagicMock

from engine.core.tech_detector import TechDetector
from engine.core.dir_discovery import DirectoryDiscoverer
from engine.core.crawler import Crawler
from engine.core.profiler import Profiler
from engine.core.target import Target


# ---- Backward compatibility: no session given -> module creates its own ----

def test_tech_detector_creates_own_session_when_none_given():
    detector = TechDetector("http://x.local")
    assert isinstance(detector.session, requests.Session)
    assert "Mozilla" in detector.session.headers["User-Agent"]


def test_dir_discoverer_creates_own_session_when_none_given():
    discoverer = DirectoryDiscoverer("http://x.local")
    assert isinstance(discoverer.session, requests.Session)
    assert "Mozilla" in discoverer.session.headers["User-Agent"]


def test_crawler_creates_own_session_when_none_given():
    crawler = Crawler("http://x.local")
    assert isinstance(crawler.session, requests.Session)
    assert "Miku-Beam-Sentinel-Crawler" in crawler.session.headers["User-Agent"]


# ---- An injected (e.g. authenticated) session is actually used -------------

def test_tech_detector_uses_injected_session_and_sends_its_auth_header(make_session):
    session = make_session(text="<html></html>")
    session.headers["Authorization"] = "Bearer test-token"

    detector = TechDetector("http://x.local", session=session)
    assert detector.session is session
    detector.detect()

    assert session.calls, "expected at least one request"
    # The header is set on the session itself (as a real Authenticator would),
    # so every request made through it carries it -- this is what proves the
    # session, not a fresh unauthenticated one, was actually used.
    assert session.headers["Authorization"] == "Bearer test-token"


def test_dir_discoverer_uses_injected_session_and_sends_its_auth_header(make_session):
    session = make_session(text="ok", status_code=200)
    session.headers["Authorization"] = "Bearer test-token"

    discoverer = DirectoryDiscoverer("http://x.local", session=session)
    assert discoverer.session is session
    discoverer.discover(paths=["/admin"], max_workers=2)

    assert session.calls, "expected at least one request"
    assert session.headers["Authorization"] == "Bearer test-token"


def test_crawler_uses_injected_session_and_sends_its_auth_header(make_session):
    session = make_session(text="<html><body>no links</body></html>")
    session.headers["Authorization"] = "Bearer test-token"

    crawler = Crawler("http://x.local", session=session)
    assert crawler.session is session
    crawler.crawl()

    assert session.calls, "expected at least one request"
    assert session.headers["Authorization"] == "Bearer test-token"


# ---- DirectoryDiscoverer connection pool sizing (thread-safety) -----------

def test_discover_sizes_connection_pool_to_max_workers():
    session = requests.Session()
    discoverer = DirectoryDiscoverer("http://x.local", session=session)

    # No paths -> no real network calls, only exercises the pool-sizing logic.
    discoverer.discover(paths=[], max_workers=45)

    adapter = session.get_adapter("http://x.local")
    assert adapter._pool_maxsize >= 45


def test_discover_pool_size_never_shrinks_below_a_sane_floor():
    session = requests.Session()
    discoverer = DirectoryDiscoverer("http://x.local", session=session)

    discoverer.discover(paths=[], max_workers=1)

    adapter = session.get_adapter("http://x.local")
    assert adapter._pool_maxsize >= 10


# ---- Profiler wires its (authenticatable) session into every HTTP-based ---
# ---- recon module, not just the ones it uses directly ---------------------

def test_profiler_passes_its_session_to_tech_detector_dir_discoverer_and_crawler():
    profiler = Profiler(Target(url="http://x.local"))

    mock_port_scanner = MagicMock()
    mock_port_scanner.return_value.scan.return_value = []
    mock_subdomain_enum = MagicMock()
    mock_subdomain_enum.return_value.enumerate.return_value = []
    mock_tech_detector = MagicMock()
    mock_tech_detector.return_value.detect.return_value = {}
    mock_dir_discoverer = MagicMock()
    mock_dir_discoverer.return_value.discover.return_value = []
    mock_crawler = MagicMock()
    mock_crawler.return_value.crawl.return_value = []

    with patch("engine.core.port_scanner.PortScanner", mock_port_scanner), \
         patch("engine.core.subdomain_enum.SubdomainEnumerator", mock_subdomain_enum), \
         patch("engine.core.tech_detector.TechDetector", mock_tech_detector), \
         patch("engine.core.dir_discovery.DirectoryDiscoverer", mock_dir_discoverer), \
         patch("engine.core.crawler.Crawler", mock_crawler):
        profiler.profile()

    assert mock_tech_detector.call_args.kwargs.get("session") is profiler.session
    assert mock_dir_discoverer.call_args.kwargs.get("session") is profiler.session
    assert mock_crawler.call_args.kwargs.get("session") is profiler.session
