"""Semgrep wrapper.

We shell out to the `semgrep` CLI with our bundled rule pack and parse the
JSON. Semgrep is Apache-licensed, fast, and has reasonable cross-language
coverage; the bundled pack focuses on patterns AI agents emit, not the
firehose of generic SAST rules.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

from ..models import Finding, Location, Severity

_RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


_SEVERITY_MAP = {
    "INFO": Severity.INFO,
    "WARNING": Severity.MEDIUM,
    "ERROR": Severity.HIGH,
}


class SemgrepNotInstalled(RuntimeError):
    """semgrep binary is missing — surfaced as a warning rather than crashing."""


async def run_semgrep(
    target_path: Path,
    rule_paths: list[Path] | None = None,
    timeout_seconds: int = 60,
) -> list[Finding]:
    """Run semgrep over a path and return normalized findings."""
    binary = shutil.which("semgrep")
    if not binary:
        raise SemgrepNotInstalled(
            "semgrep not found on PATH. Install via `pip install semgrep` or "
            "`brew install semgrep`. Sureguard works without it but skips SAST."
        )

    rule_args: list[str] = []
    for rp in rule_paths or [_RULES_DIR]:
        rule_args.extend(["--config", str(rp)])

    cmd = [
        binary,
        *rule_args,
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--metrics=off",
        "--timeout",
        str(timeout_seconds),
        str(target_path),
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds + 10)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise

    if not stdout:
        return []
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for r in payload.get("results", []):
        extra = r.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        severity = _SEVERITY_MAP.get(extra.get("severity", "WARNING"), Severity.MEDIUM)
        rule_id = r.get("check_id", "semgrep.unknown")
        start = r.get("start", {}) or {}
        end = r.get("end", {}) or {}
        findings.append(
            Finding(
                id=f"sureguard.{rule_id}" if not rule_id.startswith("sureguard.") else rule_id,
                title=metadata.get("shortDescription") or rule_id.split(".")[-1],
                severity=severity,
                category="insecure-pattern",
                message=extra.get("message") or "",
                location=Location(
                    path=r.get("path"),
                    line=start.get("line"),
                    column=start.get("col"),
                    end_line=end.get("line"),
                    end_column=end.get("col"),
                    snippet=(extra.get("lines") or "")[:240] or None,
                ),
                cwe_ids=_listify(metadata.get("cwe")),
                owasp=_listify(metadata.get("owasp")),
                fix=metadata.get("fix") or extra.get("fix"),
                references=_listify(metadata.get("references")),
            )
        )
    return findings


def _listify(v: object) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]
