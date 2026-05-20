"""Render Sureguard findings as SARIF v2.1.0.

GitHub code scanning and most CI systems consume SARIF natively, so this is
the path of least resistance for Pattern A (deterministic CI gate).
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .models import Finding, Severity

_SARIF_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def findings_to_sarif(findings: list[Finding], tool_run_name: str = "sureguard") -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        if f.id not in rules:
            rules[f.id] = {
                "id": f.id,
                "name": f.id.split(".")[-1],
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.message},
                "helpUri": f.references[0] if f.references else None,
                "properties": {
                    "category": f.category,
                    "cwe": f.cwe_ids,
                    "owasp": f.owasp,
                },
            }

        result: dict[str, Any] = {
            "ruleId": f.id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "properties": {
                "severity": f.severity.value,
                "cve": f.cve_ids,
                "risk_score": f.risk_score,
                "in_kev": f.in_kev,
                "epss": f.epss,
            },
        }

        if f.location and f.location.path:
            loc: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location.path},
                }
            }
            if f.location.line is not None:
                region: dict[str, Any] = {"startLine": f.location.line}
                if f.location.column is not None:
                    region["startColumn"] = f.location.column
                if f.location.end_line is not None:
                    region["endLine"] = f.location.end_line
                if f.location.end_column is not None:
                    region["endColumn"] = f.location.end_column
                if f.location.snippet:
                    region["snippet"] = {"text": f.location.snippet}
                loc["physicalLocation"]["region"] = region
            result["locations"] = [loc]

        if f.fix:
            result["fixes"] = [{"description": {"text": f.fix}}]

        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_run_name,
                        "version": __version__,
                        "informationUri": "https://github.com/sureguard/sureguard",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
