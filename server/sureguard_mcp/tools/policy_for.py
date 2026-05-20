"""policy_for tool — return rule pack metadata so upstream agents can self-correct.

The point: if an AI agent calls this *before* generating, it gets back the
list of patterns we'd flag, so it can avoid emitting them in the first place.
That's Pattern B's preventive half. Reactive scanning is good; never
generating the bad pattern is better.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def _load_rules_for(language: str) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    target = _RULES_DIR / language.lower()
    if not target.exists():
        return rules
    for path in sorted(target.glob("*.yml")):
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError:
            continue
        for r in (doc or {}).get("rules", []) or []:
            rules.append(
                {
                    "id": r.get("id"),
                    "message": (r.get("message") or "").strip(),
                    "severity": r.get("severity"),
                    "category": (r.get("metadata") or {}).get("category"),
                    "cwe": (r.get("metadata") or {}).get("cwe"),
                    "fix": (r.get("metadata") or {}).get("fix"),
                }
            )
    return rules


async def policy_for(language: str, framework: str | None = None) -> dict[str, Any]:
    """Return the guardrail policy for a given language + optional framework."""
    rules = _load_rules_for(language)
    return {
        "language": language,
        "framework": framework,
        "rule_count": len(rules),
        "guidance": (
            "Avoid emitting any code matching these patterns. When you must use a "
            "primitive in this list, prefer the fix suggested for that rule."
        ),
        "rules": rules,
        "general_principles": [
            "Never disable TLS verification (no `verify=False`, no `NODE_TLS_REJECT_UNAUTHORIZED=0`).",
            "Never use MD5/SHA1 for security purposes; use SHA-256+ or bcrypt/argon2 for passwords.",
            "Never accept JWT alg=none; pin the expected algorithm explicitly.",
            "Never concatenate strings into SQL; use parameterized queries.",
            "Never hardcode credentials; read from a secrets manager or env.",
            "Before adding a dependency, confirm the package name exists in the registry "
            "(call verify_package).",
        ],
    }
