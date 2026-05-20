"""In-process scan runner used by the web UI.

This is a thin orchestrator over the same engine/source modules the CLI uses:
clone the repo shallow, run Semgrep + Gitleaks + scan_dependencies, return the
findings and the action plan.

Hard caps live here rather than in the CLI because this code runs on a public
endpoint where a hostile / huge repo would otherwise DoS the service.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from sureguard_code_scanner.actions import (
    Action,
    SEVERITY_ORDER,
    build_action_plan,
    project_score,
)
from sureguard_code_scanner.engines.gitleaks import (
    GitleaksNotInstalled,
    fallback_scan_text,
    run_gitleaks,
)
from sureguard_code_scanner.engines.semgrep import SemgrepNotInstalled, run_semgrep
from sureguard_code_scanner.models import Finding, Location, Severity
from sureguard_code_scanner.tools.scan_dependencies import scan_dependencies

# Same skip-list the CLI uses, applied to the manifest walk.
_SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    ".next",
    ".nuxt",
    ".turbo",
    ".svelte-kit",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "target",
    "vendor",
    "third_party",
    "site-packages",
}
_MANIFESTS = {"requirements.txt", "package.json", "package-lock.json", "pyproject.toml"}

# Safety caps. Tuned for a 1-vCPU container; bump if you give the worker more.
MAX_REPO_BYTES = 200 * 1024 * 1024  # 200 MB cloned
MAX_SCAN_SECONDS = 120  # hard wall-clock cap

# Only allow github.com URLs. No tokens, no other hosts.
_GITHUB_URL_RE = re.compile(
    r"^https?://github\.com/([A-Za-z0-9._\-]+)/([A-Za-z0-9._\-]+?)(?:\.git)?/?$"
)


class ScanError(RuntimeError):
    """User-presentable failure (bad URL, repo too big, timed out, etc.)."""


@dataclass
class ScanReport:
    target_url: str
    score: int
    grade: str
    severity_counts: dict[str, int]
    category_counts: dict[str, int]
    actions: list[Action]
    findings: list[Finding]
    warnings: list[str]
    elapsed_ms: int


def parse_github_url(url: str) -> tuple[str, str]:
    """Return (owner, repo). Raises ScanError if the URL isn't a plain public github URL."""
    url = url.strip()
    m = _GITHUB_URL_RE.match(url)
    if not m:
        raise ScanError(
            "Only public GitHub URLs are accepted (https://github.com/<owner>/<repo>)."
        )
    return m.group(1), m.group(2)


async def _git_clone_shallow(url: str, dest: Path) -> None:
    proc = await asyncio.create_subprocess_exec(
        "git",
        "clone",
        "--depth=1",
        "--single-branch",
        "--no-tags",
        url,
        str(dest),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},  # never prompt for creds
    )
    try:
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise ScanError("Git clone timed out after 60s.") from None
    if proc.returncode != 0:
        msg = (stderr or b"").decode("utf-8", errors="replace")[:200].strip()
        raise ScanError(f"Git clone failed: {msg or 'unknown error'}")


def _dir_size_bytes(path: Path) -> int:
    total = 0
    for root, dirs, files in os.walk(path):
        # Don't follow symlinks; don't recurse into .git for size accounting since
        # we already shallow-cloned, but it's still real bytes.
        for name in files:
            try:
                total += (Path(root) / name).stat(follow_symlinks=False).st_size
            except OSError:
                pass
        if total > MAX_REPO_BYTES:
            return total
    return total


def _iter_manifests(root: Path):
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.name in _MANIFESTS:
            yield path


async def scan_github_url(url: str) -> ScanReport:
    """Clone + scan a public GitHub URL. Always cleans up the temp dir."""
    parse_github_url(url)  # validate early
    started = time.monotonic()
    warnings: list[str] = []
    findings: list[Finding] = []

    workdir = Path(tempfile.mkdtemp(prefix="sureguard-web-"))
    try:
        await _git_clone_shallow(url, workdir / "repo")
        repo = workdir / "repo"

        size = _dir_size_bytes(repo)
        if size > MAX_REPO_BYTES:
            raise ScanError(
                f"Repo is too large ({size // 1024 // 1024} MB > "
                f"{MAX_REPO_BYTES // 1024 // 1024} MB cap)."
            )

        # The whole pipeline is wrapped in a wall-clock timeout so a runaway
        # Semgrep or stuck OSV request can't keep the worker occupied forever.
        try:
            await asyncio.wait_for(
                _run_pipeline(repo, findings, warnings),
                timeout=MAX_SCAN_SECONDS,
            )
        except asyncio.TimeoutError:
            warnings.append(
                f"Scan exceeded {MAX_SCAN_SECONDS}s and was cut short — results may be partial."
            )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    counts: dict[Severity, int] = dict.fromkeys(SEVERITY_ORDER, 0)
    cat_counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] += 1
        cat_counts[f.category] = cat_counts.get(f.category, 0) + 1

    score, grade = project_score(counts)
    actions = build_action_plan(findings, target=workdir / "repo")
    elapsed_ms = int((time.monotonic() - started) * 1000)

    return ScanReport(
        target_url=url,
        score=score,
        grade=grade,
        severity_counts={s.value: counts[s] for s in SEVERITY_ORDER},
        category_counts=cat_counts,
        actions=actions,
        findings=findings,
        warnings=warnings,
        elapsed_ms=elapsed_ms,
    )


async def _run_pipeline(repo: Path, findings: list[Finding], warnings: list[str]) -> None:
    # SAST
    try:
        findings.extend(await run_semgrep(repo))
    except SemgrepNotInstalled as e:
        warnings.append(str(e))

    # Secrets — gitleaks if available, fallback otherwise.
    try:
        findings.extend(await run_gitleaks(repo))
    except (GitleaksNotInstalled, FileNotFoundError):
        # Apply the cheap fallback pattern detector across text files in the repo.
        for path in repo.rglob("*"):
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            if not path.is_file():
                continue
            if path.stat().st_size > 1_000_000:  # 1MB per file ceiling for fallback
                continue
            try:
                content = path.read_text(errors="ignore")
            except OSError:
                continue
            for f in fallback_scan_text(content, path=str(path.relative_to(repo))):
                if f.location:
                    f.location.path = str(path.relative_to(repo))
                findings.append(f)
        warnings.append(
            "gitleaks not installed — using built-in pattern+entropy fallback. Recall is lower."
        )

    # SCA over discovered manifests.
    for manifest in _iter_manifests(repo):
        try:
            res = await scan_dependencies(manifest.name, manifest.read_text())
        except Exception as e:
            warnings.append(f"{manifest.name}: {e}")
            continue
        rel = str(manifest.relative_to(repo))
        for f in res.findings:
            if f.location is None:
                f.location = Location(path=rel)
            else:
                f.location.path = rel
            findings.append(f)
        warnings.extend(res.warnings)
