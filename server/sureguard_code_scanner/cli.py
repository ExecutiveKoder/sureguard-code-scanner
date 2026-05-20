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
import os
import subprocess
import sys
import time
from pathlib import Path

from .engines.gitleaks import GitleaksNotInstalled, run_gitleaks
from .engines.semgrep import SemgrepNotInstalled, run_semgrep
from .models import Finding, Location, Severity
from .sarif import findings_to_sarif
from .tools.scan_dependencies import scan_dependencies

_SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_MANIFESTS = {"requirements.txt", "package.json", "package-lock.json", "pyproject.toml"}
_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", "dist", "build"}


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


def _print_summary(
    target: Path, findings: list[Finding], warnings: list[str], elapsed_ms: int
) -> None:
    counts: dict[Severity, int] = dict.fromkeys(_SEV_ORDER, 0)
    for f in findings:
        counts[f.severity] += 1

    print()
    print(f"{_color('bold')}Sureguard scan{_color('reset')}  {_color('dim')}{target}{_color('reset')}")
    print(f"{_color('dim')}{'─' * 72}{_color('reset')}")

    if not findings:
        print(f"  {_color('blue')}no findings{_color('reset')}")
    else:
        parts = []
        for sev in reversed(_SEV_ORDER):
            if counts[sev]:
                color, weight = _SEV_STYLE[sev]
                parts.append(
                    f"{_color(weight)}{_color(color)}{counts[sev]} {sev.value}{_color('reset')}"
                )
        print("  " + "   ".join(parts))
        print()

        ordered = sorted(
            findings,
            key=lambda f: (
                -_SEV_ORDER.index(f.severity),
                f.location.path if f.location and f.location.path else "",
                f.location.line if f.location and f.location.line else 0,
            ),
        )
        for f in ordered:
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

    if not args.no_sast:
        try:
            findings.extend(await run_semgrep(target))
        except SemgrepNotInstalled as e:
            warnings.append(str(e))

    if not args.no_secrets:
        try:
            findings.extend(await run_gitleaks(target))
        except (GitleaksNotInstalled, FileNotFoundError):
            warnings.append(
                "gitleaks not installed — skipping secrets scan. Install with "
                "`brew install gitleaks`."
            )

    if not args.no_deps:
        for manifest in _iter_manifests(target):
            try:
                res = await scan_dependencies(manifest.name, manifest.read_text())
            except Exception as e:
                warnings.append(f"{manifest}: {e}")
                continue
            rel = str(manifest.relative_to(target))
            for f in res.findings:
                if f.location is None:
                    f.location = Location(path=rel)
                else:
                    f.location.path = rel
                findings.append(f)
            warnings.extend(res.warnings)

    elapsed_ms = int((time.monotonic() - started) * 1000)

    if args.json:
        print(json.dumps([f.model_dump(mode="json") for f in findings], indent=2))
    elif args.sarif:
        Path(args.sarif).write_text(json.dumps(findings_to_sarif(findings), indent=2))
        print(f"SARIF written to {args.sarif}", file=sys.stderr)
        _print_summary(target, findings, warnings, elapsed_ms)
    else:
        _print_summary(target, findings, warnings, elapsed_ms)

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

    ci = sub.add_parser("ci", help="CI mode — emit SARIF for GitHub code scanning.")
    ci.add_argument("--fail-on", default="high", choices=[s.value for s in Severity])
    ci.add_argument("--manifest", default=None)
    ci.add_argument("--scan-diff", action="store_true")
    ci.add_argument("--base", default="HEAD~1")
    ci.add_argument("--sarif", default="sureguard.sarif")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "scan":
        return asyncio.run(_run_scan(args))
    if args.cmd == "ci":
        return asyncio.run(_run_ci(args))
    parser.error(f"unknown command: {args.cmd}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
