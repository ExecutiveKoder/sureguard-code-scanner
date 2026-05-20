"""scan_diff tool — extract added lines from a unified diff and run scan_code.

This is the workhorse for PR-review and pre-commit. We only scan added/changed
lines, not the whole file, so we don't drown reviewers in legacy findings.
"""

from __future__ import annotations

import time
from pathlib import Path

from unidiff import PatchSet

from ..models import ScanResult
from .scan_code import scan_code

_EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rb": "ruby",
    ".java": "java",
    ".php": "php",
}


async def scan_diff(diff: str) -> ScanResult:
    started = time.monotonic()
    try:
        patch = PatchSet(diff)
    except Exception as e:
        return ScanResult(tool="scan_diff", warnings=[f"Failed to parse diff: {e}"])

    all_findings = []
    scanned = 0
    for f in patch:
        if f.is_removed_file:
            continue
        path = f.target_file or f.source_file or ""
        # strip leading a/ b/ markers
        if path.startswith(("a/", "b/")):
            path = path[2:]
        ext = Path(path).suffix.lower()
        language = _EXT_TO_LANG.get(ext)
        if not language:
            continue

        # Reconstruct just the added content (concatenated for context, with line numbers preserved).
        added_lines: list[str] = []
        for hunk in f:
            for line in hunk:
                if line.is_added:
                    added_lines.append(line.value.rstrip("\n"))
        if not added_lines:
            continue
        snippet = "\n".join(added_lines)

        result = await scan_code(snippet, language=language, filename=path)
        all_findings.extend(result.findings)
        scanned += 1

    elapsed = int((time.monotonic() - started) * 1000)
    return ScanResult(
        tool="scan_diff",
        findings=all_findings,
        scanned_files=scanned,
        elapsed_ms=elapsed,
    )
