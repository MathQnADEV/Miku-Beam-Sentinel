"""Tests for issue #6: the CLI's --scan-<key> flags are now generated from the
shared scanner registry instead of being hand-listed, so every registry entry
must actually be reachable as a flag and behave the way the old hand-written
flags did (each is independent; --scan-all is a separate umbrella flag).
"""
from cli.main import build_parser
from engine.scanners.registry import REGISTRY


def test_parser_has_a_flag_for_every_registry_entry():
    parser = build_parser()
    args = parser.parse_args(["--url", "http://x.local"])
    for spec in REGISTRY:
        assert hasattr(args, f"scan_{spec.key}"), f"missing --scan-{spec.key} flag"
        assert getattr(args, f"scan_{spec.key}") is False  # not passed -> off


def test_individual_scan_flag_only_enables_that_one():
    parser = build_parser()
    args = parser.parse_args(["--url", "http://x.local", "--scan-ldap"])
    assert args.scan_ldap is True
    assert args.scan_all is False
    for spec in REGISTRY:
        if spec.key != "ldap":
            assert getattr(args, f"scan_{spec.key}") is False


def test_previously_unreachable_flags_parse_correctly():
    # These flags existed before but their scanners could never be selected by
    # the web path; the CLI flags themselves must keep working unchanged.
    for key in ("ldap", "xpath", "xml", "oauth", "hpp", "ratelimit", "mass", "logic", "logging", "auth"):
        parser = build_parser()
        args = parser.parse_args(["--url", "http://x.local", f"--scan-{key}"])
        assert getattr(args, f"scan_{key}") is True


def test_scan_all_flag_still_present_and_independent():
    parser = build_parser()
    args = parser.parse_args(["--url", "http://x.local", "--scan-all"])
    assert args.scan_all is True
    # scan-all is a separate flag the main loop OR's against each key -- it
    # does not itself flip the individual flags.
    assert args.scan_sqli is False


def test_hyphenated_key_gets_an_explicit_underscored_dest(monkeypatch):
    # Regression guard from adversarial review: a future ScannerSpec with a
    # hyphenated key (e.g. "rate-limit") must still produce a valid, correctly
    # named attribute -- relying on argparse's own hyphen-to-underscore dest
    # mangling would work today by coincidence (no current key has a hyphen),
    # but build_parser() sets dest= explicitly so this can't silently diverge.
    import cli.main as cli_main
    from engine.scanners.registry import ScannerSpec, SQLInjectionScanner

    fake_registry = [ScannerSpec("rate-limit", "Rate Limit Test", SQLInjectionScanner)]
    monkeypatch.setattr(cli_main, "REGISTRY", fake_registry)

    parser = cli_main.build_parser()
    args = parser.parse_args(["--url", "http://x.local", "--scan-rate-limit"])
    assert getattr(args, "scan_rate_limit") is True
