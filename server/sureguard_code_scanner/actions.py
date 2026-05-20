"""Action plan: collapse N findings into M moves.

The terminal CLI and the web UI both render the same action plan. Keeping it
in its own module means neither has to import private names from the other —
and a future SARIF/JSON exporter can call this too.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from packaging.version import InvalidVersion, Version

from .models import Finding, Severity

SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


_SCORE_WEIGHTS = {
    Severity.CRITICAL: 15.0,
    Severity.HIGH: 3.0,
    Severity.MEDIUM: 1.0,
    Severity.LOW: 0.3,
    Severity.INFO: 0.05,
}


def project_score(counts: dict[Severity, int]) -> tuple[int, str]:
    """Return (score 0-100, letter grade). Start at 100, deduct per finding by severity.

    Weights are calibrated so a clean small project scores 100, a project with
    one HIGH and a handful of LOW/INFO findings lands in the 80s, and a project
    with multiple HIGHs or any CRITICAL drops into C/D/F.
    """
    penalty = sum(counts.get(sev, 0) * weight for sev, weight in _SCORE_WEIGHTS.items())
    score = max(0, int(round(100 - penalty)))
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    return score, grade


@dataclass
class Action:
    """One row in the action plan."""

    kind: str  # "code" | "secret" | "hallucinated" | "upgrade"
    title: str
    detail: str
    severity: Severity
    finding_count: int
    install_command: str | None = None
    ecosystem: str | None = None
    package: str | None = None
    target_version: str | None = None


# Captures "Upgrade <package> to >= <version>." (the format scan_dependencies emits)
_FIX_RE = re.compile(r"Upgrade\s+(\S+?)\s+to\s+>=\s+([0-9A-Za-z._\-+]+?)\.?\s*$")


def _safe_version(s: str) -> Version | None:
    try:
        return Version(s)
    except InvalidVersion:
        return None


def _rel(path: str | None, root: Path | None) -> str:
    """Best-effort relativize a path against the scan root for display."""
    if not path:
        return "(unknown)"
    if root is None:
        return path
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except (ValueError, OSError):
        return path


def build_action_plan(findings: list[Finding], target: Path | None = None) -> list[Action]:
    """Collapse 100s of findings into the handful of moves that resolve them."""
    actions: list[Action] = []

    # --- SAST findings: group by file, one action per file ---
    sast_by_file: dict[str, list[Finding]] = {}
    for f in findings:
        if f.category != "insecure-pattern":
            continue
        path = _rel(f.location.path if f.location else None, target)
        sast_by_file.setdefault(path, []).append(f)
    for path, fs in sorted(sast_by_file.items(), key=lambda kv: -len(kv[1])):
        worst = max(fs, key=lambda f: SEVERITY_ORDER.index(f.severity))
        line_suffix = f":{worst.location.line}" if worst.location and worst.location.line else ""
        detail = worst.fix or worst.title
        actions.append(
            Action(
                kind="code",
                title=f"Fix insecure pattern in {path}{line_suffix}",
                detail=(detail.split("\n", 1)[0][:160] if detail else worst.title),
                severity=worst.severity,
                finding_count=len(fs),
            )
        )

    # --- Secrets: one action per file ---
    secrets_by_file: dict[str, list[Finding]] = {}
    for f in findings:
        if f.category != "secret":
            continue
        path = _rel(f.location.path if f.location else None, target)
        secrets_by_file.setdefault(path, []).append(f)
    for path, fs in secrets_by_file.items():
        actions.append(
            Action(
                kind="secret",
                title=f"Rotate hardcoded secret in {path}",
                detail="Treat as compromised. Rotate the credential, then move it to a secrets manager / env var.",
                severity=Severity.HIGH,
                finding_count=len(fs),
            )
        )

    # --- Hallucinated packages: one action per package ---
    for f in findings:
        if f.category != "hallucinated-package":
            continue
        actions.append(
            Action(
                kind="hallucinated",
                title=f.title,
                detail=f.fix or "Verify this package name actually exists in the registry; remove if not.",
                severity=f.severity,
                finding_count=1,
            )
        )

    # --- CVE findings: group by (ecosystem, package), take max recommended fix version ---
    @dataclass
    class _Bucket:
        package: str
        ecosystem: str
        fix_versions: list[Version] = field(default_factory=list)
        findings: list[Finding] = field(default_factory=list)
        titles: list[str] = field(default_factory=list)

    buckets: dict[tuple[str, str], _Bucket] = {}
    for f in findings:
        if f.category != "vulnerability":
            continue
        if not f.fix:
            continue
        m = _FIX_RE.search(f.fix)
        if not m:
            continue
        pkg, fix_ver_str = m.group(1), m.group(2)
        path = (f.location.path if f.location else "") or ""
        if path.endswith(".txt") or path.endswith("pyproject.toml"):
            ecosystem = "pypi"
        elif path.endswith(".json"):
            ecosystem = "npm"
        else:
            ecosystem = "unknown"
        key = (ecosystem, pkg)
        bucket = buckets.setdefault(key, _Bucket(package=pkg, ecosystem=ecosystem))
        v = _safe_version(fix_ver_str)
        if v is not None:
            bucket.fix_versions.append(v)
        bucket.findings.append(f)
        bucket.titles.append(f.title)

    for (ecosystem, pkg), bucket in buckets.items():
        if not bucket.fix_versions:
            continue
        target_v = max(bucket.fix_versions)
        worst = max(bucket.findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
        if ecosystem == "pypi":
            install = f'pip install -U "{pkg}>={target_v}"'
        elif ecosystem == "npm":
            install = f"npm install {pkg}@^{target_v}"
        else:
            install = None
        sev_summary = []
        for sev in reversed(SEVERITY_ORDER):
            n = sum(1 for f in bucket.findings if f.severity == sev)
            if n:
                sev_summary.append(f"{n} {sev.value}")
        sample = bucket.titles[0]
        sample = re.sub(r"^[A-Z\-]+\d[\w\-]*\s+in\s+", "", sample)
        actions.append(
            Action(
                kind="upgrade",
                title=f"Upgrade {pkg} → {target_v}",
                detail=f"clears {len(bucket.findings)} CVE(s) ({', '.join(sev_summary)}) — e.g. {sample[:80]}",
                severity=worst.severity,
                finding_count=len(bucket.findings),
                install_command=install,
                ecosystem=ecosystem,
                package=pkg,
                target_version=str(target_v),
            )
        )

    actions.sort(key=lambda a: (-SEVERITY_ORDER.index(a.severity), -a.finding_count))
    return actions
