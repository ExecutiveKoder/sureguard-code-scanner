"""Shallow git clone helper, shared between the CLI and the web app.

Two callers, two trust models:
- CLI: runs on the user's own box; we accept any git remote URL (github,
  gitlab, ssh, etc.) and rely on git itself to reject what it can't clone.
- Web: runs as a public endpoint; the caller validates with parse_github_url()
  first to refuse anything outside github.com/<owner>/<repo>.

Both share the actual `git clone --depth=1` call so we don't drift.
"""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path

# Strict github-only matcher used by the web endpoint. Refuses tokens in the
# URL by structure — only `https://github.com/<owner>/<repo>(.git)?` shapes.
_STRICT_GITHUB_URL_RE = re.compile(
    r"^https?://github\.com/([A-Za-z0-9._\-]+)/([A-Za-z0-9._\-]+?)(?:\.git)?/?$"
)

# Permissive matcher used by the CLI to decide "is this a URL or a local path".
# Matches any common git remote URL shape; git itself decides if it can clone.
_URL_LIKE_RE = re.compile(r"^(?:https?|git|ssh)://")


class CloneError(RuntimeError):
    """User-presentable failure (bad URL, clone timeout, auth failure, etc.)."""


def parse_github_url(url: str) -> tuple[str, str]:
    """Return (owner, repo). Raises CloneError if the URL isn't plain public github.com."""
    url = url.strip()
    m = _STRICT_GITHUB_URL_RE.match(url)
    if not m:
        raise CloneError(
            "Only public GitHub URLs are accepted here (https://github.com/<owner>/<repo>)."
        )
    return m.group(1), m.group(2)


def looks_like_url(s: str) -> bool:
    """True if the input looks like a git remote URL rather than a filesystem path."""
    if not s:
        return False
    s = s.strip()
    if _URL_LIKE_RE.match(s):
        return True
    # `git@github.com:owner/repo.git` style SSH URL.
    if s.startswith("git@") and ":" in s:
        return True
    return False


async def git_clone_shallow(url: str, dest: Path, timeout_seconds: int = 60) -> None:
    """`git clone --depth=1` into dest, with creds prompt disabled and a hard timeout.

    Raises CloneError on any failure with the most useful stderr line we can find.
    """
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
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise CloneError(f"Git clone timed out after {timeout_seconds}s.") from None
    if proc.returncode != 0:
        msg = (stderr or b"").decode("utf-8", errors="replace").strip()
        # Take the last non-empty line — git's most-specific error is usually last.
        last = next((line for line in reversed(msg.splitlines()) if line.strip()), msg)
        raise CloneError(f"Git clone failed: {last[:240] or 'unknown error'}")
