"""
Technology Detection Module
Identifies web technologies, frameworks, and stack components.

Detection is evidence-based (Wappalyzer-style) rather than bare substring
matching. The previous implementation did things like ``'java' in body.lower()``
to flag Java — which matches any page merely containing the word "javascript",
since "java" is a literal substring of it. Every signal here is either anchored
to a specific header/cookie name, a ``<meta name="generator">`` value, a
script/link filename, or a word-bounded regex against the body — and a
technology is only reported once its accumulated evidence clears a confidence
threshold, with the evidence that produced it retained for inspection.
"""
import re
import logging
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class Signal:
    """One piece of evidence for a technology.

    ``kind`` selects which extracted haystack to search (see Evidence);
    ``pattern`` is a regex matched case-insensitively (and per-line, since
    header/cookie/script haystacks are newline-joined); ``weight`` is the
    confidence (0-100) this signal contributes if it matches.
    """

    def __init__(self, kind, pattern, weight):
        self.kind = kind
        self.pattern = pattern
        self.weight = weight
        self._regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)

    def matches(self, evidence: "Evidence") -> bool:
        haystack = {
            "header": evidence.headers_text,
            "cookie": evidence.cookie_names_text,
            "meta_generator": evidence.meta_generator,
            "script_src": evidence.script_srcs_text,
            "body": evidence.body,
        }[self.kind]
        return bool(self._regex.search(haystack))

    def describe(self) -> str:
        return f"{self.kind}:/{self.pattern}/"


class Evidence:
    """Extracted, reusable evidence from a single HTTP response — computed once
    and shared across every technology rule's signal checks."""

    def __init__(self, response, soup: BeautifulSoup):
        self.headers_text = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        self.cookie_names_text = "\n".join(c.name for c in response.cookies)

        meta = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
        self.meta_generator = meta.get("content", "") if meta else ""

        sources = []
        for tag in soup.find_all("script"):
            src = tag.get("src")
            if src:
                sources.append(src)
        for tag in soup.find_all("link"):
            href = tag.get("href")
            if href:
                sources.append(href)
        self.script_srcs_text = "\n".join(sources)

        self.body = response.text or ""


# Each entry: (technology name, category, [Signal, ...]).
# Categories: server, cms, backend, frontend, framework.
# Weights are calibrated so that ONE strong, hard-to-coincidentally-match
# signal (a specific header, cookie name, or generator tag: 75-95) is enough
# on its own, while weak/generic body mentions (25-40) only count when they
# corroborate something else.
RULES = [
    # --- Servers ---
    ("Nginx", "server", [Signal("header", r"^Server:\s*nginx", 90)]),
    ("Apache", "server", [Signal("header", r"^Server:\s*apache", 90)]),
    ("IIS", "server", [Signal("header", r"^Server:.*Microsoft-IIS/", 85)]),
    ("Cloudflare", "server", [
        Signal("header", r"^Server:\s*cloudflare", 80),
        Signal("header", r"^cf-ray:", 90),
    ]),

    # --- CMS ---
    ("WordPress", "cms", [
        Signal("meta_generator", r"wordpress", 95),
        Signal("script_src", r"wp-content|wp-includes", 90),
        # A bare "wp-content" mention in body TEXT is often just prose (a
        # migration write-up, a tutorial) rather than a live asset reference —
        # corroborating-only; the script_src/meta_generator signals above are
        # the strong, primary evidence.
        Signal("body", r"\bwp-content\b", 30),
        Signal("header", r"^Link:.*wp-json", 85),
    ]),
    ("Drupal", "cms", [
        Signal("meta_generator", r"drupal", 95),
        Signal("header", r"^X-Generator:.*drupal", 95),
        Signal("body", r"\bDrupal\.settings\b", 80),
        Signal("cookie", r"^SESS[0-9a-f]{32}$", 75),
    ]),
    ("Joomla", "cms", [
        Signal("meta_generator", r"joomla", 95),
        Signal("body", r"\bJoomla!", 80),
        Signal("body", r"/components/com_\w+", 65),
    ]),
    ("Shopify", "cms", [
        Signal("header", r"^X-ShopId:", 95),
        Signal("header", r"^X-Shopify", 90),
        Signal("script_src", r"cdn\.shopify\.com", 90),
        Signal("body", r"\bShopify\.shop\b", 80),
    ]),

    # --- Backend frameworks ---
    ("Django", "backend", [
        Signal("cookie", r"^csrftoken$", 75),
        Signal("cookie", r"^sessionid$", 30),
        Signal("body", r"\bcsrfmiddlewaretoken\b", 85),
        # "django" itself has low prose-collision risk (unlike "flask"/"java"),
        # so a plain, word-bounded mention is reasonable corroborating-only
        # evidence — restores some of the recall lost by dropping the old
        # unguarded body substring check, without reintroducing its risk.
        Signal("body", r"\bdjango\b", 35),
    ]),
    ("Laravel", "backend", [
        Signal("cookie", r"laravel_session", 90),
        # XSRF-TOKEN is NOT Laravel-specific: it's the default cookie name for
        # Angular's HttpClientXsrfModule and the convention axios reads for its
        # double-submit CSRF pattern — used by countless non-Laravel backends.
        # Corroborating-only; laravel_session above is the real signal.
        Signal("cookie", r"XSRF-TOKEN", 15),
        Signal("body", r"\blaravel\b", 35),
    ]),
    ("Express.js", "backend", [
        # Word-bounded so it doesn't match e.g. "X-Powered-By: ExpressionEngine".
        Signal("header", r"^X-Powered-By:\s*express\b", 90),
    ]),
    ("Flask", "backend", [
        Signal("header", r"^Server:.*werkzeug", 90),
        Signal("body", r"\bflask\b", 25),
    ]),
    ("ASP.NET", "backend", [
        Signal("header", r"^X-Powered-By:.*asp\.net", 90),
        Signal("header", r"^X-AspNet-Version:", 95),
        Signal("cookie", r"ASP\.NET_SessionId", 90),
    ]),
    ("PHP", "backend", [
        # Word-bounded so it doesn't match an unrelated "X-Powered-By: PHPxyz".
        Signal("header", r"^X-Powered-By:\s*php\b", 90),
        Signal("cookie", r"^PHPSESSID$", 85),
        # .php links/actions are ubiquitous on real PHP sites (a decent,
        # low-collision signal the old code relied on) but not proof on their
        # own — e.g. a page could link to someone else's .php endpoint.
        # Corroborating-only; the header/cookie signals above are the strong,
        # primary evidence. Terminator-anchored so it requires an actual link/
        # query boundary, not just the 3 letters "php" anywhere in the body.
        Signal("body", r"\.php(\?|[\"'\s]|$)", 30),
    ]),

    # --- Frontend frameworks ---
    ("React", "frontend", [
        Signal("script_src", r"react(-dom)?[.\-][\w.]*\.js", 75),
        Signal("body", r"\bdata-reactroot\b|\bReactDOM\.render\b|__REACT_DEVTOOLS_GLOBAL_HOOK__", 75),
    ]),
    ("Angular", "frontend", [
        # ng-version is an Angular(2+)-exclusive attribute the CLI stamps onto
        # the root element — strong enough alone.
        Signal("body", r"\bng-version\s*=", 80),
        # <app-root> alone is just a common "root app element" naming
        # convention also used by non-Angular custom-element boilerplates
        # (Stencil, Lit, hand-rolled) — corroborating-only.
        Signal("body", r"<app-root\b", 25),
        # `\b` after a hyphenated token like "ng-app" is satisfied by the
        # following hyphen too (a non-word char), so `\bng-app\b` alone still
        # matches inside "ng-app-icon". Use an explicit non-word/non-hyphen
        # lookaround so a trailing "-something" correctly does NOT count.
        Signal("body", r"(?<![\w-])ng-app(?![\w-])|(?<![\w-])ng-controller(?![\w-])", 60),
        Signal("script_src", r"angular(\.min)?\.js|zone\.js", 65),
    ]),
    ("Vue.js", "frontend", [
        Signal("body", r"\bdata-v-[0-9a-f]{6,8}\b", 85),
        Signal("body", r"\b__vue__\b", 70),
        Signal("script_src", r"vue(\.min)?\.js|vue\.runtime", 65),
    ]),
    ("Next.js", "frontend", [
        Signal("body", r"__NEXT_DATA__", 90),
        Signal("script_src", r"/_next/static/", 85),
    ]),

    # --- Libraries / misc frameworks ---
    ("Bootstrap", "framework", [
        # A bare "bootstrap.js"/"bootstrap.min.css" filename is also a common
        # convention for a project's OWN init script (e.g. Laravel Mix's
        # default resources/js/bootstrap.js) unrelated to the CSS framework.
        # Require a version number or a vendor/CDN path segment instead.
        Signal("script_src", r"bootstrap[@.-]?\d|/bootstrap/dist/|cdn\.jsdelivr\.net/npm/bootstrap|stackpath\.bootstrapcdn\.com", 80),
        Signal("body", r"\bdata-bs-toggle\b", 65),
    ]),
    ("jQuery", "framework", [
        Signal("script_src", r"jquery(-[\d.]+)?(\.min)?\.js", 85),
    ]),
    ("Tailwind", "framework", [
        Signal("script_src", r"tailwind(\.min)?\.css", 70),
        Signal("body", r"\btailwindcss\b", 30),
    ]),
    ("MaterialUI", "framework", [
        # Require a genuine MUI-generated class prefix (MuiButton-root,
        # MuiPaper-root, ...), not a bare "mui-" token — the latter collides
        # with the unrelated "Mui CSS" framework (muicss.com), whose own class
        # convention is literally "mui-btn", "mui-container", etc.
        Signal("body", r"\bMui[A-Z]\w*-root\b", 70),
        Signal("script_src", r"material-ui|@mui", 70),
    ]),
    ("GraphQL", "framework", [
        # __typename alone is a client-side data-shape convention (Apollo
        # cache normalization) that can persist even on REST APIs after
        # migrating off GraphQL — corroborating-only.
        Signal("body", r"__typename\b", 25),
        # "graphql" has low prose-collision risk (unlike "flask"/"java"), so a
        # plain mention — e.g. nav text linking to a /graphql endpoint, the old
        # detector's main source of true positives here — is reasonable
        # evidence on its own.
        Signal("body", r"\bgraphql\b", 45),
    ]),

    # --- Language markers not implied by a backend framework above ---
    ("Java", "language_direct", [
        Signal("cookie", r"^JSESSIONID$", 85),
        Signal("body", r"\.jsp\b", 25),
    ]),
]

# A detected backend framework strongly implies its language even though the
# language itself often isn't independently observable over HTTP.
LANGUAGE_BY_BACKEND = {
    "PHP": "PHP",
    "Django": "Python",
    "Flask": "Python",
    "Express.js": "Node.js",
    "ASP.NET": "C#/.NET",
    "Laravel": "PHP",
}

# The database is a backend implementation detail with no direct HTTP-observable
# signal; this remains an inference from the detected backend, kept for the
# existing 'database' output field, and is intentionally excluded from the
# per-technology confidence scores below (it is a guess, not evidence).
DATABASE_BY_BACKEND = {
    "Django": "PostgreSQL/MySQL",
    "Laravel": "MySQL",
    "PHP": "MySQL",
    "ASP.NET": "MSSQL",
    "Express.js": "MongoDB/MySQL",
    "Flask": "PostgreSQL/SQLite",
}

# Minimum accumulated confidence (sum of matching signal weights, capped at
# 100) before a technology is reported at all. Calibrated so a single weak
# body-only signal (25-40) is never enough alone, but any one strong
# header/cookie/generator signal (75+) is.
CONFIDENCE_THRESHOLD = 40


class TechDetector:
    def __init__(self, target_url, timeout=5, session=None):
        """
        Args:
            target_url: Target URL to profile
            timeout: Request timeout in seconds
            session: Optional pre-configured requests.Session (e.g. one carrying
                auth headers/cookies applied by an Authenticator). When omitted, a
                plain, unauthenticated session is created as before.
        """
        self.target_url = target_url
        self.timeout = timeout
        self.session = session if session is not None else requests.Session()
        if session is None:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            })

    def detect(self):
        """Detect technologies and return the stack plus a per-technology
        confidence/evidence breakdown (under the 'confidence' key)."""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text or "", "html.parser")
            evidence = Evidence(response, soup)

            scored = {}
            for name, category, signals in RULES:
                matched = [s for s in signals if s.matches(evidence)]
                if not matched:
                    continue
                score = min(100, sum(s.weight for s in matched))
                if score < CONFIDENCE_THRESHOLD:
                    continue
                scored[name] = {
                    "category": category,
                    "confidence": score,
                    "evidence": [s.describe() for s in matched],
                }

            tech = self._build_output(scored, response)
            tech["confidence"] = {
                name: {"confidence": v["confidence"], "evidence": v["evidence"]}
                for name, v in scored.items()
            }

            logger.info(f"Technology detection complete for {self.target_url}: {sorted(scored.keys())}")
            return tech

        except Exception as e:
            logger.error(f"Technology detection failed: {e}")
            return self._get_default_tech()

    @staticmethod
    def _best_in_category(scored, category):
        candidates = [(name, v["confidence"]) for name, v in scored.items() if v["category"] == category]
        if not candidates:
            return "Unknown"
        return max(candidates, key=lambda c: c[1])[0]

    def _build_output(self, scored, response):
        server = self._best_in_category(scored, "server")
        if server == "Unknown":
            # No rule matched (e.g. an unrecognized server) -- fall back to the
            # raw header value rather than discarding it entirely.
            server = response.headers.get("Server", "Unknown")

        backend = self._best_in_category(scored, "backend")
        cms = self._best_in_category(scored, "cms")
        frontend = self._best_in_category(scored, "frontend")
        frameworks = sorted(name for name, v in scored.items() if v["category"] == "framework")

        languages = []
        if backend in LANGUAGE_BY_BACKEND:
            languages.append(LANGUAGE_BY_BACKEND[backend])
        if "Java" in scored and "Java" not in languages:
            languages.append("Java")
        languages = languages or ["Unknown"]

        return {
            "server": server,
            "backend": backend,
            "database": DATABASE_BY_BACKEND.get(backend, "Unknown"),
            "frontend": frontend,
            "cms": cms if cms != "Unknown" else "None",
            "languages": languages,
            "frameworks": frameworks,
            "headers": self._extract_headers(response),
            "cookies": self._extract_cookies(response),
        }

    def _extract_headers(self, response):
        """Extract security-relevant headers"""
        return {
            'X-Frame-Options': response.headers.get('X-Frame-Options', 'Missing'),
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', 'Missing'),
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'Missing'),
            'Content-Security-Policy': response.headers.get('Content-Security-Policy', 'Missing'),
            'X-XSS-Protection': response.headers.get('X-XSS-Protection', 'Missing')
        }

    def _extract_cookies(self, response):
        """Extract cookie information"""
        cookies = {}
        for cookie in response.cookies:
            cookies[cookie.name] = {
                'secure': cookie.secure,
                'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                'samesite': cookie.get_nonstandard_attr('SameSite', 'None')
            }
        return cookies

    def _get_default_tech(self):
        """Default tech stack when detection fails"""
        return {
            'server': 'Unknown',
            'backend': 'Unknown',
            'database': 'Unknown',
            'frontend': 'Unknown',
            'cms': 'None',
            'languages': ['Unknown'],
            'frameworks': [],
            'headers': {},
            'cookies': {},
            'confidence': {},
        }
