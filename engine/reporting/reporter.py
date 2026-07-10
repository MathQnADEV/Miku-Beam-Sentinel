import html
import json
from typing import List
from ..scanners.base import Vulnerability
from ..core.target import Target


def _tech_stack_str(tech_stack) -> str:
    """Render the target tech stack whether it is a list or a dict."""
    if isinstance(tech_stack, dict):
        return ', '.join(f"{k}: {v}" for k, v in tech_stack.items() if v)
    if isinstance(tech_stack, (list, tuple, set)):
        return ', '.join(str(t) for t in tech_stack)
    return str(tech_stack or '')


class Reporter:
    def __init__(self, target: Target, vulnerabilities: List[Vulnerability]):
        self.target = target
        self.vulnerabilities = vulnerabilities

    def generate_json(self, filepath: str):
        data = {
            "target": self.target.url,
            "tech_stack": self.target.tech_stack,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities]
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    def generate_markdown(self, filepath: str):
        content = f"# Scan Report for {self.target.url}\n\n"
        content += "## Target Information\n"
        content += f"- **URL**: {self.target.url}\n"
        content += f"- **Tech Stack**: {_tech_stack_str(self.target.tech_stack)}\n\n"
        content += "## Vulnerabilities\n"

        if not self.vulnerabilities:
            content += "No vulnerabilities found.\n"
        else:
            for v in self.vulnerabilities:
                content += f"### {v.name}\n"
                content += f"- **Severity**: {v.severity}\n"
                content += f"- **Description**: {v.description}\n"
                if v.url:
                    content += f"- **URL**: {v.url}\n"
                content += f"- **Evidence**:\n\n```\n{v.evidence}\n```\n"
                if v.recommendation:
                    content += f"- **Recommendation**: {v.recommendation}\n"
                if v.proof_of_concept:
                    content += f"- **Proof of Concept**:\n\n```\n{v.proof_of_concept}\n```\n"
                content += "\n"

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

    def generate_html(self, filepath: str):
        # NOTE: every value below is HTML-escaped. Evidence contains attacker- or
        # target-controlled text (payloads, raw response snippets); interpolating it
        # unescaped would let a hostile target inject scripts into the report.
        def esc(value) -> str:
            return html.escape(str(value if value is not None else ''))

        out = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Scan Report - {esc(self.target.url)}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; }}
        .vuln {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 10px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #e74c3c; }}
        .high {{ border-left: 5px solid #e67e22; }}
        .medium {{ border-left: 5px solid #f1c40f; }}
        .low {{ border-left: 5px solid #3498db; }}
        .info {{ border-left: 5px solid #95a5a6; }}
        pre {{ white-space: pre-wrap; word-break: break-word; background: #f7f7f7; padding: 8px; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>Scan Report: {esc(self.target.url)}</h1>
    <p><strong>Tech Stack:</strong> {esc(_tech_stack_str(self.target.tech_stack))}</p>
    <h2>Vulnerabilities</h2>
"""

        if not self.vulnerabilities:
            out += "<p>No vulnerabilities found.</p>"
        else:
            for v in self.vulnerabilities:
                severity_class = esc(v.severity).lower()
                out += f"""
    <div class="vuln {severity_class}">
        <h3>{esc(v.name)} <span style="font-size: 0.8em; color: #7f8c8d;">({esc(v.severity)})</span></h3>
        <p>{esc(v.description)}</p>
"""
                if v.url:
                    out += f'        <p><strong>URL:</strong> <code>{esc(v.url)}</code></p>\n'
                out += f"        <pre>{esc(v.evidence)}</pre>\n"
                if v.recommendation:
                    out += f'        <p><strong>Recommendation:</strong> {esc(v.recommendation)}</p>\n'
                if v.proof_of_concept:
                    out += f'        <p><strong>Proof of Concept:</strong></p>\n        <pre>{esc(v.proof_of_concept)}</pre>\n'
                out += "    </div>\n"

        out += "</body></html>"

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(out)
