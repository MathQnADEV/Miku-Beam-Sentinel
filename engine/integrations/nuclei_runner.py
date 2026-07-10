"""
Nuclei integration — runs ProjectDiscovery's Nuclei as an external scanning engine
and maps its findings into Miku Beam Sentinel `Vulnerability` objects.

Nuclei is a Go binary and is NOT bundled. If it is not installed / not on PATH,
`is_available()` returns False and `run()` returns an empty list, so scans keep
working without it.

Install nuclei (any one):
  * Windows: download nuclei_*_windows_amd64.zip from
    https://github.com/projectdiscovery/nuclei/releases and put nuclei.exe on PATH
  * With Go:   go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  * Homebrew:  brew install nuclei
Run `nuclei -update-templates` once after installing.
"""
import json
import logging
import shutil
import subprocess
from typing import List, Optional

from engine.scanners.base import Vulnerability

logger = logging.getLogger(__name__)

# Nuclei severities -> our qualitative scale
_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "unknown": "INFO",
}


def is_available() -> bool:
    """True if the `nuclei` binary is found on PATH."""
    return shutil.which("nuclei") is not None


def _to_vuln(obj: dict) -> Optional[Vulnerability]:
    """Map one nuclei JSONL record to a Vulnerability. Returns None if unparseable."""
    if not isinstance(obj, dict):
        return None

    info = obj.get("info") or {}
    template_id = obj.get("template-id") or obj.get("templateID") or "nuclei"
    name = info.get("name") or template_id
    severity = _SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), "INFO")
    matched = obj.get("matched-at") or obj.get("matched") or obj.get("host") or ""
    description = info.get("description") or f"Nuclei template '{template_id}' matched."

    evidence_parts = [f"Template: {template_id}"]
    if matched:
        evidence_parts.append(f"Matched: {matched}")
    if obj.get("extracted-results"):
        evidence_parts.append(f"Extracted: {obj['extracted-results']}")
    if info.get("tags"):
        evidence_parts.append(f"Tags: {info['tags']}")
    if obj.get("curl-command"):
        evidence_parts.append(f"PoC: {obj['curl-command']}")

    reference = info.get("reference")
    remediation = info.get("remediation")

    return Vulnerability(
        name=f"[nuclei] {name}",
        description=description,
        severity=severity,
        evidence="\n".join(str(p) for p in evidence_parts),
        url=matched or None,
        recommendation=remediation or (f"References: {reference}" if reference else None),
        proof_of_concept=obj.get("curl-command"),
    )


def run(target_url: str, timeout: int = 300, extra_args: Optional[list] = None, callback=None) -> List[Vulnerability]:
    """
    Run nuclei against target_url and return a list of Vulnerability objects.
    Safe no-op (returns []) when nuclei is not installed or on any error.
    """
    if not is_available():
        logger.warning("nuclei not found on PATH; skipping nuclei stage")
        return []

    cmd = ["nuclei", "-u", target_url, "-jsonl", "-silent", "-disable-update-check"]
    if extra_args:
        cmd += list(extra_args)

    vulns: List[Vulnerability] = []
    try:
        logger.info("Running nuclei: %s", " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            vuln = _to_vuln(obj)
            if vuln is not None:
                vulns.append(vuln)
                if callback:
                    try:
                        callback(f"{vuln.severity}: {vuln.name}")
                    except Exception:
                        pass
        if proc.returncode not in (0, None) and not vulns:
            logger.debug("nuclei exited %s; stderr: %s", proc.returncode, (proc.stderr or "")[:500])
    except subprocess.TimeoutExpired:
        logger.warning("nuclei timed out after %ss", timeout)
    except Exception as e:  # pragma: no cover - defensive
        logger.error("nuclei run failed: %s", e)

    logger.info("nuclei produced %d findings", len(vulns))
    return vulns
