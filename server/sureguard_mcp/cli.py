"""Thin CLI used by the GitHub Action and pre-commit hook (Pattern A).

The MCP server (`sureguard-mcp`) is the primary surface. This CLI calls the
same tool functions directly so CI doesn't need an MCP client.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
from pathlib import Path

from .models import Severity
from .sarif import findings_to_sarif
from .tools.scan_dependencies import scan_dependencies
from .tools.scan_diff import scan_diff

_SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _meets_threshold(sev: Severity, threshold: Severity) -> bool:
    return _SEV_ORDER.index(sev) >= _SEV_ORDER.index(threshold)


async def _run_ci(args: argparse.Namespace) -> int:
    all_findings = []

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sureguard")
    sub = parser.add_subparsers(dest="cmd", required=True)

    ci = sub.add_parser("ci", help="Run Sureguard in CI mode and emit SARIF.")
    ci.add_argument("--fail-on", default="high", choices=[s.value for s in Severity])
    ci.add_argument("--manifest", default=None)
    ci.add_argument("--scan-diff", action="store_true")
    ci.add_argument("--base", default="HEAD~1")
    ci.add_argument("--sarif", default="sureguard.sarif")

    args = parser.parse_args(argv)
    if args.cmd == "ci":
        return asyncio.run(_run_ci(args))
    parser.error(f"unknown command: {args.cmd}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
