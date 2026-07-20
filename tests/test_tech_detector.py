"""Tests for issue #12: evidence-based technology fingerprinting.

Covers the exact bug named in the issue ('java' in 'javascript' matching any
page that merely mentions JavaScript), that strong single signals (headers,
cookies, <meta generator>, script filenames) still correctly detect real
technologies, that weak body-only mentions alone are not enough, and that a
per-technology confidence/evidence breakdown is returned.
"""
from engine.core.tech_detector import TechDetector
from engine.core.target import Target  # noqa: F401 (not used directly, keeps parity with other recon tests)


def _detect(make_session, **response_kwargs):
    session = make_session(**response_kwargs)
    return TechDetector("http://x.local", session=session).detect()


# ---- The exact false positive named in the issue --------------------------

def test_java_not_falsely_detected_from_javascript_mention(make_session):
    # The old code did `'java' in body.lower()` -- matches any page mentioning
    # "javascript" at all, which is nearly every modern web page.
    result = _detect(
        make_session,
        text="<html><body>We love javascript and modern web development.</body></html>",
    )
    assert "Java" not in result["languages"]
    assert "Java" not in result["confidence"]


def test_vue_not_falsely_detected_from_prose_substring(make_session):
    # 'vue' as a bare substring appears in ordinary words (avenue, revue, ...).
    result = _detect(make_session, text="<html><body>Come see the avenue and enjoy the revue.</body></html>")
    assert result["frontend"] != "Vue.js"


def test_react_not_falsely_detected_from_prose_substring(make_session):
    result = _detect(make_session, text="<html><body>How users react to change matters.</body></html>")
    assert result["frontend"] != "React"


def test_plain_page_detects_nothing(make_session):
    result = _detect(make_session, text="<html><body>Welcome to our site.</body></html>")
    assert result["backend"] == "Unknown"
    assert result["cms"] == "None"
    assert result["frontend"] == "Unknown"
    assert result["frameworks"] == []
    assert result["languages"] == ["Unknown"]


# ---- True positives via strong, specific signals ---------------------------

def test_wordpress_detected_via_meta_generator(make_session):
    result = _detect(
        make_session,
        text='<html><head><meta name="generator" content="WordPress 6.4"></head></html>',
    )
    assert result["cms"] == "WordPress"
    assert result["confidence"]["WordPress"]["confidence"] >= 40


def test_drupal_detected_via_x_generator_header(make_session):
    result = _detect(make_session, text="<html></html>", headers={"X-Generator": "Drupal 10"})
    assert result["cms"] == "Drupal"


def test_django_detected_via_csrftoken_cookie(make_session):
    result = _detect(make_session, text="<html></html>", cookies={"csrftoken": "abc123"})
    assert result["backend"] == "Django"
    assert "Python" in result["languages"]
    assert result["database"] == "PostgreSQL/MySQL"


def test_django_detected_via_csrfmiddlewaretoken_body(make_session):
    result = _detect(
        make_session,
        text='<form><input type="hidden" name="csrfmiddlewaretoken" value="x"></form>',
    )
    assert result["backend"] == "Django"


def test_laravel_detected_via_session_cookie(make_session):
    result = _detect(make_session, text="<html></html>", cookies={"laravel_session": "xyz"})
    assert result["backend"] == "Laravel"
    assert "PHP" in result["languages"]


def test_express_detected_via_x_powered_by_header(make_session):
    result = _detect(make_session, text="<html></html>", headers={"X-Powered-By": "Express"})
    assert result["backend"] == "Express.js"
    assert "Node.js" in result["languages"]


def test_aspnet_detected_via_x_aspnet_version_header(make_session):
    result = _detect(make_session, text="<html></html>", headers={"X-AspNet-Version": "4.0.30319"})
    assert result["backend"] == "ASP.NET"
    assert "C#/.NET" in result["languages"]


def test_php_detected_via_phpsessid_cookie(make_session):
    result = _detect(make_session, text="<html></html>", cookies={"PHPSESSID": "abc"})
    assert result["backend"] == "PHP"
    assert "PHP" in result["languages"]


def test_java_detected_via_jsessionid_cookie(make_session):
    result = _detect(make_session, text="<html></html>", cookies={"JSESSIONID": "abc"})
    assert "Java" in result["languages"]


def test_react_detected_via_data_reactroot(make_session):
    result = _detect(make_session, text='<div data-reactroot="">app</div>')
    assert result["frontend"] == "React"


def test_vue_detected_via_scoped_data_attribute(make_session):
    result = _detect(make_session, text='<div data-v-1a2b3c4d>app</div>')
    assert result["frontend"] == "Vue.js"


def test_nextjs_detected_via_next_data_marker(make_session):
    result = _detect(make_session, text='<script id="__NEXT_DATA__" type="application/json">{}</script>')
    assert result["frontend"] == "Next.js"


def test_jquery_detected_via_script_filename(make_session):
    result = _detect(make_session, text='<script src="/static/js/jquery-3.6.0.min.js"></script>')
    assert "jQuery" in result["frameworks"]


def test_bootstrap_detected_via_versioned_cdn_filename(make_session):
    # A bare "bootstrap.min.css" is also a common convention for a project's
    # OWN unrelated init script/stylesheet (e.g. Laravel Mix's default
    # resources/js/bootstrap.js) -- detection requires a version number or a
    # recognizable vendor/CDN path, matching a real-world CDN reference.
    result = _detect(
        make_session,
        text='<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">',
    )
    assert "Bootstrap" in result["frameworks"]


def test_bootstrap_own_named_init_script_not_falsely_detected(make_session):
    # Regression guard for the false positive found in review: a project's own
    # bootstrap.js (unrelated to the CSS framework) must not count alone.
    result = _detect(make_session, text='<script src="/js/bootstrap.js"></script>')
    assert "Bootstrap" not in result["frameworks"]


def test_graphql_detected_via_typename_plus_endpoint_mention(make_session):
    # __typename alone is corroborating-only (see false-positive test below);
    # paired with an actual "graphql" mention (e.g. the endpoint reflected in
    # the page), together they clear the threshold.
    result = _detect(make_session, text='Data via <a href="/graphql">GraphQL</a>: {"__typename": "Query"}')
    assert "GraphQL" in result["frameworks"]


def test_graphql_typename_alone_does_not_qualify(make_session):
    # Regression guard for the false positive found in review: a REST API that
    # merely kept a field named __typename (e.g. an Apollo cache-normalization
    # convention retained after migrating off GraphQL) must not count alone.
    result = _detect(make_session, text='{"id": 1, "__typename": "User"}')
    assert "GraphQL" not in result["frameworks"]


def test_cloudflare_detected_via_cf_ray_header(make_session):
    result = _detect(make_session, text="<html></html>", headers={"CF-RAY": "abc123-SIN"})
    assert result["server"] == "Cloudflare"


# ---- Regression guards from adversarial review -----------------------------
# Each of these pins a concrete false positive an independent review reproduced
# live against an earlier version of RULES, to make sure it doesn't come back.

def test_laravel_not_falsely_detected_from_xsrf_token_cookie_alone(make_session):
    # XSRF-TOKEN is not Laravel-specific: it's the default cookie name for
    # Angular's HttpClientXsrfModule and the convention axios reads for its
    # double-submit CSRF pattern -- used by countless non-Laravel backends.
    result = _detect(make_session, text="<app-root></app-root>", cookies={"XSRF-TOKEN": "abcd1234"})
    assert result["backend"] != "Laravel"


def test_materialui_not_falsely_detected_from_unrelated_mui_css_framework(make_session):
    # "Mui CSS" (muicss.com) is an unrelated CSS framework whose own class
    # convention is literally "mui-btn", "mui-container", etc. -- must not be
    # confused with React MaterialUI's "MuiButton-root"-style classes.
    result = _detect(make_session, text='<button class="mui-btn mui-btn--primary">Click</button>')
    assert "MaterialUI" not in result["frameworks"]


def test_materialui_detected_via_genuine_mui_class_prefix(make_session):
    result = _detect(make_session, text='<button class="MuiButton-root MuiButton-contained">Click</button>')
    assert "MaterialUI" in result["frameworks"]


def test_iis_not_falsely_detected_from_unrelated_microsoft_server_header(make_session):
    # Microsoft-HTTPAPI/2.0 (Windows http.sys) and Microsoft-Azure-Application-
    # Gateway are real, common Server header values from non-IIS products.
    result = _detect(make_session, text="<html></html>", headers={"Server": "Microsoft-HTTPAPI/2.0"})
    assert result["server"] != "IIS"


def test_iis_detected_via_proper_product_token(make_session):
    result = _detect(make_session, text="<html></html>", headers={"Server": "Microsoft-IIS/10.0"})
    assert result["server"] == "IIS"


def test_express_header_not_falsely_matched_by_similar_product_name(make_session):
    result = _detect(make_session, text="<html></html>", headers={"X-Powered-By": "ExpressionEngine"})
    assert result["backend"] != "Express.js"


def test_php_detected_via_php_link_corroborating_with_header(make_session):
    # The body .php-link signal is corroborating-only (30, below threshold
    # alone); paired with the header it should push PHP over the line.
    result = _detect(
        make_session,
        text='<a href="/contact.php">Contact</a>',
        headers={"X-Powered-By": "PHP/8.2"},
    )
    assert result["backend"] == "PHP"


def test_php_link_alone_does_not_qualify(make_session):
    result = _detect(make_session, text='<a href="/contact.php">Contact</a><a href="/index.php?id=1">Home</a>')
    assert result["backend"] != "PHP"


def test_angular_ng_app_boundary_does_not_match_unrelated_hyphenated_class(make_session):
    # `\bng-app\b` alone is satisfied by a following hyphen (a non-word char),
    # so it used to match inside "ng-app-icon" too -- an unrelated class name
    # that merely starts with the same three-letter-plus-hyphen prefix.
    result = _detect(make_session, text='<div class="ng-app-icon"></div>')
    assert result["frontend"] != "Angular"


def test_angular_ng_app_still_detected_as_a_whole_token(make_session):
    result = _detect(make_session, text='<html ng-app="myApp"><body ng-controller="MainCtrl"></body></html>')
    assert result["frontend"] == "Angular"


def test_angular_bare_app_root_tag_alone_does_not_qualify(make_session):
    # <app-root> is also used by non-Angular custom-element boilerplates
    # (Stencil, Lit, hand-rolled) -- corroborating-only.
    result = _detect(make_session, text="<app-root></app-root>")
    assert result["frontend"] != "Angular"


# ---- Weak signals alone are not enough -------------------------------------

def test_weak_body_only_mention_does_not_qualify_alone(make_session):
    # "flask" appearing in ordinary text (weight 25) is below the confidence
    # threshold (40) on its own -- unlike the old code's bare substring check.
    result = _detect(make_session, text="<html><body>We use a flask of coffee daily.</body></html>")
    assert result["backend"] != "Flask"
    assert "Flask" not in result["confidence"]


def test_graphql_bare_word_mention_qualifies_alone(make_session):
    # Unlike "flask"/"java"/"react"/"vue" (all common English words this
    # engine deliberately keeps sub-threshold), "graphql" has low prose-
    # collision risk, so a plain mention -- e.g. nav text linking to a
    # /graphql endpoint, the old detector's main source of true positives
    # here -- is reasonable evidence on its own.
    result = _detect(make_session, text="<html><body>Explore our GraphQL API.</body></html>")
    assert "GraphQL" in result["frameworks"]


# ---- Confidence/evidence output ---------------------------------------------

def test_confidence_dict_has_score_and_evidence_per_technology(make_session):
    result = _detect(
        make_session,
        text='<html><head><meta name="generator" content="WordPress 6.4"></head></html>',
    )
    entry = result["confidence"]["WordPress"]
    assert isinstance(entry["confidence"], int)
    assert 0 < entry["confidence"] <= 100
    assert entry["evidence"]
    assert all(isinstance(e, str) for e in entry["evidence"])


def test_multiple_matching_signals_increase_confidence(make_session):
    # WordPress via meta generator (95) alone vs. also having wp-content in a
    # script src (90) and body (80) -- both should be capped at 100 but the
    # richer-evidence case should have more evidence entries recorded.
    single = _detect(make_session, text='<meta name="generator" content="WordPress">')
    richer = _detect(
        make_session,
        text='<meta name="generator" content="WordPress"><script src="/wp-content/theme.js"></script> wp-content',
    )
    assert len(richer["confidence"]["WordPress"]["evidence"]) >= len(single["confidence"]["WordPress"]["evidence"])


# ---- Output shape stays backward-compatible for existing consumers --------

def test_output_shape_matches_existing_consumers(make_session):
    # web/backend/projects/scan_executor.py's _select_scanners reads these as
    # plain strings/lists (e.g. tech_stack.get('database', '').lower()), and
    # the frontend renders them directly -- the shape must not change.
    result = _detect(make_session, text="<html></html>")
    assert isinstance(result["server"], str)
    assert isinstance(result["backend"], str)
    assert isinstance(result["database"], str)
    assert isinstance(result["frontend"], str)
    assert isinstance(result["cms"], str)
    assert isinstance(result["languages"], list)
    assert isinstance(result["frameworks"], list)
    assert isinstance(result["headers"], dict)
    assert isinstance(result["cookies"], dict)
    assert isinstance(result["confidence"], dict)


def test_detection_failure_falls_back_to_default_tech():
    class RaisingSession:
        def get(self, *a, **kw):
            raise ConnectionError("boom")

    result = TechDetector("http://x.local", session=RaisingSession()).detect()
    assert result["server"] == "Unknown"
    assert result["languages"] == ["Unknown"]
    assert result["confidence"] == {}
