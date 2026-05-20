"""scan_code tool — Semgrep over raw code with the bundled AI-aware rule pack."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from ..engines.semgrep import SemgrepNotInstalled, run_semgrep
from ..models import ScanResult

_LANG_EXTENSIONS = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "go": ".go",
    "java": ".java",
    "ruby": ".rb",
    "php": ".php",
}


async def scan_code(content: str, language: str = "python", filename: str | None = None) -> ScanResult:
    """Scan a single code block. Writes to a temp file because Semgrep needs paths."""
    started = time.monotonic()
    ext = _LANG_EXTENSIONS.get(language.lower(), "")
    with tempfile.TemporaryDirectory(prefix="sureguard-") as td:
        target = Path(td) / (filename or f"snippet{ext}")
        target.write_text(content)
        try:
            findings = await run_semgrep(target)
        except SemgrepNotInstalled as e:
            return ScanResult(
                tool="scan_code",
                warnings=[str(e)],
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )

    # Re-relativize paths so the snippet name we passed in shows up cleanly.
    for f in findings:
        if f.location and f.location.path:
            f.location.path = filename or target.name

    elapsed = int((time.monotonic() - started) * 1000)
    return ScanResult(
        tool="scan_code",
        findings=findings,
        scanned_files=1,
        elapsed_ms=elapsed,
    )
