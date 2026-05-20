"""Sureguard CLI.

Two subcommands:

  sureguard scan <dir>    — point at a local directory and print a SAST/SCA/secret summary.
  sureguard ci [...]      — CI mode, emits SARIF for GitHub code scanning.

The MCP server is invoked separately via `sureguard-code-scanner` (or `python -m
sureguard_code_scanner`), not through this CLI.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

from .actions import Action, build_action_plan, project_score
from .engines.gitleaks import GitleaksNotInstalled, run_gitleaks
from .engines.semgrep import SemgrepNotInstalled, run_semgrep
from .models import Finding, Location, Severity
from .sarif import findings_to_sarif
from .tools.scan_dependencies import scan_dependencies

_SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_MANIFESTS = {"requirements.txt", "package.json", "package-lock.json", "pyproject.toml"}
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


def _meets_threshold(sev: Severity, threshold: Severity) -> bool:
    return _SEV_ORDER.index(sev) >= _SEV_ORDER.index(threshold)


def _color(name: str) -> str:
    """ANSI color helper. Suppressed when not a TTY or when NO_COLOR is set."""
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return ""
    return {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "red": "\033[91m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "gray": "\033[90m",
    }.get(name, "")


_SEV_STYLE = {
    Severity.CRITICAL: ("red", "bold"),
    Severity.HIGH: ("red", ""),
    Severity.MEDIUM: ("yellow", ""),
    Severity.LOW: ("blue", ""),
    Severity.INFO: ("gray", ""),
}


def _fmt_sev(sev: Severity) -> str:
    color, weight = _SEV_STYLE[sev]
    return f"{_color(weight)}{_color(color)}{sev.value.upper():<8}{_color('reset')}"


def _grade_color(grade: str) -> str:
    return {"A": "blue", "B": "blue", "C": "yellow", "D": "yellow", "F": "red"}.get(grade, "reset")


# Friendly labels for the category breakdown.
_CATEGORY_LABELS = {
    "hallucinated-package": "Hallucinated / typosquat packages",
    "vulnerability": "Dependency CVEs",
    "insecure-pattern": "Insecure code patterns",
    "secret": "Hardcoded secrets",
    "outdated": "Outdated components",
    "license": "License issues",
    "supply-chain": "Supply-chain risks",
}


# Action / build_action_plan / project_score live in actions.py — see imports at top of file.


_KIND_LABEL = {
    "code": ("CODE", "red"),
    "secret": ("SECRET", "red"),
    "hallucinated": ("PKG?", "red"),
    "upgrade": ("UPGRADE", "blue"),
}


def _print_action_plan(actions: list[Action]) -> None:
    if not actions:
        return

    print()
    print(f"  {_color('bold')}Next actions{_color('reset')}  {_color('dim')}(fix these in order){_color('reset')}")
    print(f"  {_color('dim')}{'─' * 70}{_color('reset')}")

    for i, a in enumerate(actions, start=1):
        label, label_color = _KIND_LABEL.get(a.kind, ("ACTION", "blue"))
        sev_color, sev_weight = _SEV_STYLE[a.severity]
        print(
            f"   {_color('bold')}{i:>2}.{_color('reset')} "
            f"{_color(label_color)}{label:<8}{_color('reset')} "
            f"{_color(sev_weight)}{_color(sev_color)}[{a.severity.value}]{_color('reset')} "
            f"{a.title}"
        )
        print(f"        {_color('dim')}{a.detail}{_color('reset')}")

    # Group install commands by ecosystem so the user can copy-paste one block per stack.
    pypi_upgrades = [a for a in actions if a.kind == "upgrade" and a.ecosystem == "pypi"]
    npm_upgrades = [a for a in actions if a.kind == "upgrade" and a.ecosystem == "npm"]
    if pypi_upgrades or npm_upgrades:
        print()
        print(f"  {_color('bold')}Copy-paste install commands{_color('reset')}")
        if pypi_upgrades:
            pkgs = " ".join(f'"{a.package}>={a.target_version}"' for a in pypi_upgrades)
            print(f"    {_color('dim')}# Python{_color('reset')}")
            print(f"    pip install -U {pkgs}")
        if npm_upgrades:
            pkgs = " ".join(f"{a.package}@^{a.target_version}" for a in npm_upgrades)
            print(f"    {_color('dim')}# Node{_color('reset')}")
            print(f"    npm install {pkgs}")


def _print_summary(
    target: Path,
    findings: list[Finding],
    warnings: list[str],
    elapsed_ms: int,
    top: int | None,
    actions_only: bool = False,
) -> None:
    counts: dict[Severity, int] = dict.fromkeys(_SEV_ORDER, 0)
    cat_counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] += 1
        cat_counts[f.category] = cat_counts.get(f.category, 0) + 1

    score, grade = project_score(counts)

    print()
    print(f"{_color('bold')}Sureguard scan{_color('reset')}  {_color('dim')}{target}{_color('reset')}")
    print(f"{_color('dim')}{'─' * 72}{_color('reset')}")

    # Score banner.
    gcolor = _grade_color(grade)
    print(
        f"  {_color('bold')}Sureguard Score:{_color('reset')} "
        f"{_color('bold')}{_color(gcolor)}{score} / 100  ({grade}){_color('reset')}"
    )

    if not findings:
        print()
        print(f"  {_color('blue')}no findings{_color('reset')}")
    else:
        # Severity row.
        parts = []
        for sev in reversed(_SEV_ORDER):
            if counts[sev]:
                color, weight = _SEV_STYLE[sev]
                parts.append(
                    f"{_color(weight)}{_color(color)}{counts[sev]} {sev.value}{_color('reset')}"
                )
        print("  " + "   ".join(parts))

        # Category breakdown.
        if cat_counts:
            print()
            print(f"  {_color('dim')}By category:{_color('reset')}")
            for cat, n in sorted(cat_counts.items(), key=lambda kv: -kv[1]):
                label = _CATEGORY_LABELS.get(cat, cat)
                print(f"    {n:>4}  {label}")

        # Action plan — what to actually do, in priority order.
        actions = build_action_plan(findings, target=target)
        if actions:
            _print_action_plan(actions)

        if actions_only:
            # Skip the detailed finding list entirely. The action plan above is the takeaway.
            if warnings:
                print()
                for w in warnings:
                    print(f"  {_color('yellow')}note:{_color('reset')} {w}")
            print()
            print(f"{_color('dim')}{len(findings)} finding(s) in {elapsed_ms} ms{_color('reset')}")
            return

        ordered = sorted(
            findings,
            key=lambda f: (
                -_SEV_ORDER.index(f.severity),
                -(f.risk_score or 0),
                f.location.path if f.location and f.location.path else "",
                f.location.line if f.location and f.location.line else 0,
            ),
        )

        shown = ordered if top is None else ordered[:top]
        hidden = len(ordered) - len(shown)

        print()
        if top is not None and hidden > 0:
            print(
                f"  {_color('bold')}Supporting detail — top {len(shown)} findings{_color('reset')}  "
                f"{_color('dim')}({hidden} more hidden; --all for everything, --actions-only to suppress this list, --json for raw output){_color('reset')}"
            )
        else:
            print(f"  {_color('bold')}Supporting detail — all findings{_color('reset')}")
        print()

        for f in shown:
            loc = ""
            if f.location and f.location.path:
                loc = f.location.path
                if f.location.line:
                    loc += f":{f.location.line}"
            print(f"  {_fmt_sev(f.severity)} {_color('dim')}{loc}{_color('reset')}")
            print(f"           {f.title}")
            if f.message and f.message.strip() != f.title.strip():
                first = f.message.strip().split("\n", 1)[0]
                print(f"           {_color('dim')}{first[:200]}{_color('reset')}")
            if f.fix:
                first = f.fix.strip().split("\n", 1)[0]
                print(f"           {_color('blue')}↳ {first[:200]}{_color('reset')}")

    if warnings:
        print()
        for w in warnings:
            print(f"  {_color('yellow')}note:{_color('reset')} {w}")

    print()
    print(f"{_color('dim')}{len(findings)} finding(s) in {elapsed_ms} ms{_color('reset')}")


def _iter_manifests(root: Path):
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.name in _MANIFESTS:
            yield path


def _status(msg: str, quiet: bool) -> None:
    """Print a single-line status update to stderr. Suppressed in --quiet."""
    if quiet:
        return
    print(f"  {_color('dim')}…{_color('reset')} {msg}", file=sys.stderr, flush=True)


async def _run_scan(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"error: {target} does not exist", file=sys.stderr)
        return 2
    if not target.is_dir():
        print(f"error: {target} is not a directory (use `sureguard scan <dir>`)", file=sys.stderr)
        return 2

    started = time.monotonic()
    findings: list[Finding] = []
    warnings: list[str] = []

    _status(f"scanning {target}", args.quiet)

    if not args.no_sast:
        sast_started = time.monotonic()
        _status("running Semgrep (SAST)…", args.quiet)
        try:
            sast_findings = await run_semgrep(target)
            findings.extend(sast_findings)
            _status(
                f"Semgrep done in {int((time.monotonic() - sast_started) * 1000)}ms — "
                f"{len(sast_findings)} finding(s)",
                args.quiet,
            )
        except SemgrepNotInstalled as e:
            warnings.append(str(e))
            _status("Semgrep not installed — skipping SAST", args.quiet)

    if not args.no_secrets:
        sec_started = time.monotonic()
        _status("scanning for secrets (Gitleaks)…", args.quiet)
        try:
            sec_findings = await run_gitleaks(target)
            findings.extend(sec_findings)
            _status(
                f"Gitleaks done in {int((time.monotonic() - sec_started) * 1000)}ms — "
                f"{len(sec_findings)} finding(s)",
                args.quiet,
            )
        except (GitleaksNotInstalled, FileNotFoundError):
            warnings.append(
                "gitleaks not installed — skipping secrets scan. Install with "
                "`brew install gitleaks`."
            )
            _status("Gitleaks not installed — skipping secrets scan", args.quiet)

    if not args.no_deps:
        manifests = list(_iter_manifests(target))
        if manifests:
            _status(
                f"found {len(manifests)} manifest(s): "
                + ", ".join(m.name for m in manifests),
                args.quiet,
            )
        for manifest in manifests:
            man_started = time.monotonic()
            rel = str(manifest.relative_to(target))
            _status(
                f"scanning {rel} (registry verify → OSV → KEV → EPSS, may take 10–60s on first run)…",
                args.quiet,
            )
            try:
                res = await scan_dependencies(manifest.name, manifest.read_text())
            except Exception as e:
                warnings.append(f"{manifest}: {e}")
                _status(f"{rel} failed: {e}", args.quiet)
                continue
            for f in res.findings:
                if f.location is None:
                    f.location = Location(path=rel)
                else:
                    f.location.path = rel
                findings.append(f)
            warnings.extend(res.warnings)
            _status(
                f"{rel} done in {int((time.monotonic() - man_started) * 1000)}ms — "
                f"{len(res.findings)} finding(s)",
                args.quiet,
            )

    elapsed_ms = int((time.monotonic() - started) * 1000)

    if args.json:
        print(json.dumps([f.model_dump(mode="json") for f in findings], indent=2))
    elif args.sarif:
        Path(args.sarif).write_text(json.dumps(findings_to_sarif(findings), indent=2))
        print(f"SARIF written to {args.sarif}", file=sys.stderr)
        _print_summary(
            target,
            findings,
            warnings,
            elapsed_ms,
            top=None if args.all else args.top,
            actions_only=args.actions_only,
        )
    else:
        _print_summary(
            target,
            findings,
            warnings,
            elapsed_ms,
            top=None if args.all else args.top,
            actions_only=args.actions_only,
        )

    threshold = Severity(args.fail_on)
    blockers = [f for f in findings if _meets_threshold(f.severity, threshold)]
    return 1 if blockers else 0


async def _run_ci(args: argparse.Namespace) -> int:
    from .tools.scan_diff import scan_diff

    all_findings: list[Finding] = []

    if args.scan_diff:
        diff = subprocess.check_output(
            ["git", "diff", "--unified=0", args.base, "HEAD"], text=True
        )
        if diff.strip():
            res = await scan_diff(diff)
            all_findings.extend(res.findings)

    if args.manifest:
        manifest_path = Path(args.manifest)
        res = await scan_dependencies(manifest_path.name, manifest_path.read_text())
        all_findings.extend(res.findings)

    sarif = findings_to_sarif(all_findings)
    Path(args.sarif).write_text(json.dumps(sarif, indent=2))

    threshold = Severity(args.fail_on)
    blockers = [f for f in all_findings if _meets_threshold(f.severity, threshold)]
    if blockers:
        print(
            f"sureguard: {len(blockers)} finding(s) at or above {threshold.value}. "
            f"SARIF written to {args.sarif}.",
            file=sys.stderr,
        )
        return 1
    print(
        f"sureguard: {len(all_findings)} finding(s) total, none above {threshold.value}.",
        file=sys.stderr,
    )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sureguard", description="AI-aware secure code review.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser(
        "scan", help="Scan a local directory (SAST + secrets + manifests) and print a summary."
    )
    scan.add_argument("path", help="Directory to scan.")
    scan.add_argument(
        "--fail-on",
        default="high",
        choices=[s.value for s in Severity],
        help="Exit nonzero if any finding meets this severity (default: high).",
    )
    scan.add_argument("--no-sast", action="store_true", help="Skip Semgrep SAST.")
    scan.add_argument("--no-secrets", action="store_true", help="Skip secrets scan.")
    scan.add_argument("--no-deps", action="store_true", help="Skip manifest / SCA scan.")
    scan.add_argument("--json", action="store_true", help="Emit findings as JSON instead of summary.")
    scan.add_argument("--sarif", help="Write SARIF to this path (still prints summary).")
    scan.add_argument(
        "--top",
        type=int,
        default=20,
        help="Show only the top N findings in the summary (default: 20). Use --all to show everything.",
    )
    scan.add_argument(
        "--all",
        action="store_true",
        help="Show every finding in the supporting-detail section (overrides --top).",
    )
    scan.add_argument(
        "--actions-only",
        action="store_true",
        help="Print only the action plan, no supporting-detail finding list.",
    )
    scan.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity. -v: status per stage. -vv: per-package HTTP calls (loud).",
    )
    scan.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress status lines; only print the summary."
    )

    ci = sub.add_parser("ci", help="CI mode — emit SARIF for GitHub code scanning.")
    ci.add_argument("--fail-on", default="high", choices=[s.value for s in Severity])
    ci.add_argument("--manifest", default=None)
    ci.add_argument("--scan-diff", action="store_true")
    ci.add_argument("--base", default="HEAD~1")
    ci.add_argument("--sarif", default="sureguard.sarif")

    return parser


def _configure_logging(verbose: int) -> None:
    # 0 = warnings only, 1 = info from sureguard, 2 = debug from sureguard + per-request httpx
    if verbose >= 2:
        level = logging.DEBUG
    elif verbose >= 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    logging.basicConfig(
        level=level,
        format=f"  {_color('dim')}[%(name)s]{_color('reset')} %(message)s",
        stream=sys.stderr,
    )
    # Libraries that produce a firehose at DEBUG — clamp them regardless of -v.
    # httpcore in particular dumps every TLS handshake step *with full response headers*.
    for noisy in ("httpcore", "httpcore.http11", "httpcore.connection", "asyncio", "anyio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    # httpx is the friendly one — one line per request at INFO. Allow it at -vv only.
    if verbose >= 2:
        logging.getLogger("httpx").setLevel(logging.INFO)
    else:
        logging.getLogger("httpx").setLevel(logging.WARNING)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _configure_logging(getattr(args, "verbose", 0))
    if args.cmd == "scan":
        return asyncio.run(_run_scan(args))
    if args.cmd == "ci":
        return asyncio.run(_run_ci(args))
    parser.error(f"unknown command: {args.cmd}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
