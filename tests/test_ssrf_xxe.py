"""Regression tests for the SSRF/XXE indicator-matching fixes.

- SSRF: mixed-case indicators (computeMetadata, GCE_METADATA, Azure) previously never
  matched because they were compared against a pre-lowercased response.
- XXE: reflection-prone markers (<!ENTITY, <!DOCTYPE, localhost, 127.0.0.1) were removed
  so a server that merely echoes the payload is no longer a false positive.
"""
from engine.scanners.ssrf import SSRFScanner
from engine.scanners.xxe import XXEScanner
from engine.core.target import Target


def test_ssrf_detects_mixed_case_indicator(make_session):
    # 'computeMetadata' is mixed-case; it must now match case-insensitively.
    session = make_session(text="{ ... computeMetadata/v1/instance ... }", status_code=200)
    result = SSRFScanner(session).scan(Target(url="http://x.local/fetch"))
    assert any("SSRF" in v.name for v in result)


def test_ssrf_clean_response_no_finding(make_session):
    session = make_session(text="welcome to the homepage", status_code=200)
    assert SSRFScanner(session).scan(Target(url="http://x.local/fetch")) == []


def test_xxe_reflected_payload_is_not_flagged(make_session):
    # Server echoes the XML back (contains <!DOCTYPE / <!ENTITY) but leaks no file
    # content -> must NOT be reported (this was the false positive the fix removes).
    echoed = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]> was received'
    session = make_session(text=echoed, status_code=200)
    assert XXEScanner(session).scan(Target(url="http://x.local/xml")) == []


def test_xxe_flags_on_leaked_file_content(make_session):
    # Actual /etc/passwd content leaked back -> genuine XXE.
    session = make_session(text="root:x:0:0:root:/root:/bin/bash\n", status_code=200)
    result = XXEScanner(session).scan(Target(url="http://x.local/xml"))
    assert any("XXE" in v.name for v in result)
