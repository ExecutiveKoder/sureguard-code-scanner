"""scan_secrets tool — Gitleaks if installed, regex+entropy fallback otherwise."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from ..engines.gitleaks import GitleaksNotInstalled, fallback_scan_text, run_gitleaks
from ..models import ScanResult


async def scan_secrets(content: str, filename: str | None = None) -> ScanResult:
    started = time.monotonic()
    warnings: list[str] = []

    with tempfile.TemporaryDirectory(prefix="sureguard-") as td:
        path = Path(td) / (filename or "snippet.txt")
        path.write_text(content)
        try:
            findings = await run_gitleaks(Path(td))
            engine = "gitleaks"
        except (GitleaksNotInstalled, FileNotFoundError):
            findings = fallback_scan_text(content, path=filename)
            warnings.append(
                "gitleaks not installed; using built-in pattern+entropy fallback. "
                "Install gitleaks for higher recall."
            )
            engine = "fallback"

    if filename:
        for f in findings:
            if f.location:
                f.location.path = filename

    elapsed = int((time.monotonic() - started) * 1000)
    return ScanResult(
        tool=f"scan_secrets ({engine})",
        findings=findings,
        scanned_files=1,
        elapsed_ms=elapsed,
        warnings=warnings,
    )
