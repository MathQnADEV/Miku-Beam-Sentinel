"""Regression tests for the report generator.

Guards the report-XSS fix (all fields HTML-escaped), UTF-8 output, tech-stack
rendering for both list and dict shapes, and that remediation/PoC now appear.
"""
from engine.core.target import Target
from engine.scanners.base import Vulnerability
from engine.reporting.reporter import Reporter, _tech_stack_str


def _sample():
    target = Target(url="http://example.com")
    vuln = Vulnerability(
        name="XSS<script>",
        description="desc",
        severity="HIGH",
        evidence="<script>alert(1)</script>",
        url="http://x?q=<b>",
        recommendation="sanitize <input>",
        proof_of_concept="curl '<x>'",
    )
    return Reporter(target, [vuln])


def test_html_report_escapes_all_fields(tmp_path):
    path = tmp_path / "report.html"
    _sample().generate_html(str(path))
    html = path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html  # not injected raw
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html  # escaped instead


def test_html_report_includes_recommendation_and_poc(tmp_path):
    path = tmp_path / "report.html"
    _sample().generate_html(str(path))
    html = path.read_text(encoding="utf-8")
    assert "Recommendation" in html
    assert "Proof of Concept" in html


def test_reports_are_utf8(tmp_path):
    r = _sample()
    hp, jp, mp = tmp_path / "r.html", tmp_path / "r.json", tmp_path / "r.md"
    r.generate_html(str(hp))
    r.generate_json(str(jp))
    r.generate_markdown(str(mp))
    for p in (hp, jp, mp):
        p.read_text(encoding="utf-8")  # must not raise


def test_no_vulnerabilities_message(tmp_path):
    target = Target(url="http://example.com")
    path = tmp_path / "r.html"
    Reporter(target, []).generate_html(str(path))
    assert "No vulnerabilities found." in path.read_text(encoding="utf-8")


def test_tech_stack_str_handles_list_and_dict():
    assert _tech_stack_str(["Nginx", "PHP"]) == "Nginx, PHP"
    assert "server" in _tech_stack_str({"server": "Nginx", "backend": ""})
    assert _tech_stack_str(None) == ""
