"""
Endpoint selection (issue #5): choose which discovered URLs/paths actually get
scanned, instead of testing only the single URL a user configured.

Reconnaissance (the crawler, directory discovery) maps far more of the attack
surface than that one URL, but until now that data was only ever printed or
streamed to the UI -- never fed back into vulnerability scanning, so the
"reconnaissance-first" design was reconnaissance-only in practice.
"""
from dataclasses import replace
from typing import List
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit

from .target import Target

# Extensions that are virtually never worth fuzzing for injection-style
# scanners -- they dominate a typical crawl (images, fonts, styles, scripts)
# and testing them just spends request budget with no realistic chance of a
# finding. This filter is skipped entirely for a URL carrying a query string
# (see _looks_scannable) -- a real parameter riding along (e.g. a dynamic
# "/report.pdf?id=5" export/download endpoint) is exactly what parameter
# fuzzing is for, regardless of what the path happens to end in.
_STATIC_EXTENSIONS = (
    '.css', '.js', '.mjs', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.map', '.pdf', '.zip', '.mp4', '.webp',
    '.avif', '.bmp',
)


def _looks_scannable(url: str) -> bool:
    parts = urlparse(url)
    if parts.query:
        return True
    return not parts.path.lower().endswith(_STATIC_EXTENSIONS)


def _directory_entry_to_url(entry, base_url: str) -> str:
    """Resolve a subdirectory-discovery entry to its actual absolute URL.

    A dict entry from DirectoryDiscoverer.discover() already carries the
    correct, resolved 'url' -- prefer that over reconstructing one. Every
    entry in DirectoryDiscoverer.COMMON_PATHS starts with a leading '/', and
    urljoin() treats a leading-'/' path as root-absolute (it replaces the
    base URL's own path entirely, it is not appended to it) -- exactly how
    DirectoryDiscoverer.check_path() itself resolves it via
    ``urljoin(self.base_url, path)``. Reconstructing the URL by naively
    concatenating the bare path onto target.url's EXISTING path (e.g.
    ".../api/users" + "/admin" -> ".../api/users/admin") would silently
    target a path recon never actually verified, while dropping the real,
    confirmed one (".../admin") -- only correct by coincidence when the
    target URL is already at domain root. A bare string entry (as produced by
    profiler.py, which discards the dict's 'url') is resolved the same way,
    via urljoin, for the identical reason.
    """
    if isinstance(entry, dict):
        url = entry.get('url')
        if isinstance(url, str) and url:
            return url
        path = entry.get('path', '')
    else:
        path = str(entry)
    if not path:
        return ''
    return urljoin(base_url, path)


def _dedup_key(url: str) -> str:
    """Normalizes a URL for "already have this endpoint" comparisons, treating
    a bare trailing-slash variant as identical to its non-trailing-slash form
    (e.g. a crawler that resolves a nav-bar "href=/" link to
    "http://x.local/" is the same page as a target configured without a
    trailing slash, "http://x.local") -- exact string equality would treat
    those as two distinct endpoints and scan the homepage twice."""
    parts = urlsplit(url)
    path = parts.path.rstrip('/') or '/'
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ''))


def select_scan_targets(target: Target, max_extra: int = 8) -> List[Target]:
    """Return [target] plus up to `max_extra` additional Targets built from
    discovered_urls (crawler) and subdirectories (directory discovery),
    sharing the base target's method/headers/body/auth.

    Endpoints carrying a query string are prioritized -- that's what parameter
    fuzzing (engine/core/url_utils.py) actually has something to act on -- and
    off-domain links (e.g. a CDN or third-party asset the crawler followed)
    and static assets (unless they carry a query string) are excluded. The
    result is capped so this doesn't uncontrollably multiply an already
    request-heavy scan (see issue #21): max_extra bounds the ADDED endpoints,
    independent of how much the crawler or directory discovery actually found.
    """
    base_domain = urlparse(target.url).netloc
    seen = {_dedup_key(target.url)}
    candidates: List[str] = []

    for url in (target.discovered_urls or []):
        if not isinstance(url, str):
            continue
        key = _dedup_key(url)
        if key in seen:
            continue
        if urlparse(url).netloc != base_domain:
            continue  # stay in-scope; don't fuzz third-party/CDN links
        if not _looks_scannable(url):
            continue
        seen.add(key)
        candidates.append(url)

    for entry in (target.subdirectories or []):
        full_url = _directory_entry_to_url(entry, target.url)
        if not full_url:
            continue
        key = _dedup_key(full_url)
        if key in seen or not _looks_scannable(full_url):
            continue
        seen.add(key)
        candidates.append(full_url)

    # URLs with a query string first -- that's where parameter fuzzing acts.
    candidates.sort(key=lambda u: '?' not in u)

    targets = [target]
    targets.extend(replace(target, url=url) for url in candidates[:max_extra])
    return targets
