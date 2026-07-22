"""Tests for issue #5's endpoint selection (engine/core/endpoint_selection.py).

Reconnaissance (the crawler, directory discovery) maps far more of the attack
surface than the single URL a user configures -- select_scan_targets turns
that data into actual additional Targets to scan, bounded and filtered so it
doesn't uncontrollably multiply an already request-heavy scan (issue #21).
"""
from engine.core.endpoint_selection import select_scan_targets
from engine.core.target import Target


def test_base_target_is_always_first_and_always_included():
    target = Target(url="http://x.local/")
    result = select_scan_targets(target)
    assert result == [target]


def test_discovered_urls_become_additional_targets():
    target = Target(
        url="http://x.local/",
        discovered_urls=["http://x.local/search?q=foo"],
    )
    result = select_scan_targets(target)
    assert [t.url for t in result] == ["http://x.local/", "http://x.local/search?q=foo"]


def test_subdirectories_become_additional_targets_as_dicts_or_bare_strings():
    target = Target(
        url="http://x.local/",
        subdirectories=["/admin", {"path": "/api/users"}],
    )
    result = select_scan_targets(target)
    urls = [t.url for t in result]
    assert "http://x.local/admin" in urls
    assert "http://x.local/api/users" in urls


def test_off_domain_discovered_urls_are_excluded():
    target = Target(
        url="http://x.local/",
        discovered_urls=["http://evil.com/x", "http://x.local/ok"],
    )
    result = select_scan_targets(target)
    urls = [t.url for t in result]
    assert "http://evil.com/x" not in urls
    assert "http://x.local/ok" in urls


def test_static_assets_are_excluded():
    target = Target(
        url="http://x.local/",
        discovered_urls=[
            "http://x.local/logo.png", "http://x.local/app.js",
            "http://x.local/style.css", "http://x.local/page.html",
        ],
    )
    result = select_scan_targets(target)
    urls = [t.url for t in result]
    assert "http://x.local/logo.png" not in urls
    assert "http://x.local/app.js" not in urls
    assert "http://x.local/style.css" not in urls
    assert "http://x.local/page.html" in urls


def test_urls_with_query_strings_are_prioritized_over_bare_paths():
    target = Target(
        url="http://x.local/",
        discovered_urls=["http://x.local/about", "http://x.local/search?q=1"],
    )
    result = select_scan_targets(target)
    urls = [t.url for t in result[1:]]  # skip the base target
    assert urls.index("http://x.local/search?q=1") < urls.index("http://x.local/about")


def test_max_extra_bounds_the_number_of_added_targets():
    target = Target(
        url="http://x.local/",
        discovered_urls=[f"http://x.local/page{i}?id={i}" for i in range(50)],
    )
    result = select_scan_targets(target, max_extra=3)
    assert len(result) == 1 + 3


def test_duplicate_and_already_present_urls_are_not_added_twice():
    target = Target(
        url="http://x.local/",
        discovered_urls=["http://x.local/", "http://x.local/dup", "http://x.local/dup"],
    )
    result = select_scan_targets(target)
    urls = [t.url for t in result]
    assert urls.count("http://x.local/") == 1
    assert urls.count("http://x.local/dup") == 1


def test_additional_targets_share_the_base_targets_method_headers_and_body():
    target = Target(
        url="http://x.local/",
        method="POST",
        headers={"X-Auth": "token"},
        body="a=1",
        discovered_urls=["http://x.local/search?q=1"],
    )
    result = select_scan_targets(target)
    extra = result[1]
    assert extra.method == "POST"
    assert extra.headers == {"X-Auth": "token"}
    assert extra.body == "a=1"


def test_non_string_discovered_url_entries_are_skipped_not_crashed():
    target = Target(url="http://x.local/", discovered_urls=[None, 123, "http://x.local/ok"])
    result = select_scan_targets(target)
    assert [t.url for t in result] == ["http://x.local/", "http://x.local/ok"]


# ---- Regression coverage from adversarial review ----------------------------

def test_subdirectory_dict_entry_uses_its_own_url_not_a_path_join():
    # DirectoryDiscoverer resolves every COMMON_PATHS entry (always a leading
    # "/") via urljoin(base_url, path) -- a root-absolute path REPLACES the
    # base URL's own path, it isn't appended to it. When target.url has a
    # non-root path ("/v2/users"), naively concatenating "/admin" onto it
    # would target a URL recon never verified ("/v2/users/admin") while
    # dropping the real, confirmed one ("/admin"). The dict's own 'url' field
    # is already the correct, resolved URL -- it must be used as-is.
    target = Target(
        url="http://x.local/v2/users",
        subdirectories=[{"path": "/admin", "url": "http://x.local/admin", "status": 200}],
    )
    result = select_scan_targets(target)
    urls = [t.url for t in result]
    assert "http://x.local/admin" in urls
    assert "http://x.local/v2/users/admin" not in urls


def test_subdirectory_bare_string_entry_resolves_via_urljoin_not_concatenation():
    # profiler.py's CLI path stores bare path strings (no 'url' key available)
    # -- these must still resolve the same root-absolute way DirectoryDiscoverer
    # itself resolved them, not by naive concatenation onto the target's path.
    target = Target(url="http://x.local/v2/users", subdirectories=["/admin"])
    result = select_scan_targets(target)
    urls = [t.url for t in result]
    assert "http://x.local/admin" in urls
    assert "http://x.local/v2/users/admin" not in urls


def test_relative_subdirectory_path_still_joins_onto_the_targets_own_path():
    # A genuinely relative (non-leading-slash) path entry should still resolve
    # relative to the target URL, per normal urljoin semantics.
    target = Target(url="http://x.local/v2/users", subdirectories=["reports"])
    result = select_scan_targets(target)
    urls = [t.url for t in result]
    assert "http://x.local/v2/reports" in urls


def test_query_bearing_url_with_a_static_looking_extension_is_not_excluded():
    # A dynamic export/report/thumbnail endpoint carrying a real parameter
    # (e.g. "/report.pdf?id=5") must not be dropped just because its path ends
    # in a "static" extension -- the query string is exactly what parameter
    # fuzzing needs, regardless of the path's extension.
    target = Target(
        url="http://x.local/",
        discovered_urls=["http://x.local/report.pdf?id=5", "http://x.local/logo.png"],
    )
    result = select_scan_targets(target)
    urls = [t.url for t in result]
    assert "http://x.local/report.pdf?id=5" in urls
    assert "http://x.local/logo.png" not in urls


def test_trailing_slash_variant_of_the_base_url_is_not_added_as_a_duplicate():
    # A crawler resolving a nav-bar "href=/" link (via urljoin) always produces
    # a trailing-slash URL, regardless of how the user typed the target URL --
    # this must be recognized as the SAME endpoint, not scanned a second time
    # under a second Target.
    target = Target(url="http://x.local", discovered_urls=["http://x.local/", "http://x.local/about"])
    result = select_scan_targets(target)
    urls = [t.url for t in result]
    assert urls.count("http://x.local") == 1
    assert "http://x.local/" not in urls
    assert "http://x.local/about" in urls
