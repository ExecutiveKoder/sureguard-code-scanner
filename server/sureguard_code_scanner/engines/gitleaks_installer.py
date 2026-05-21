"""Fetch a vetted gitleaks binary on demand.

Gitleaks is a Go binary, so it can't ride along as a Python dependency. Asking
every user to `brew install gitleaks` is the kind of friction that makes a
security tool quietly stop being used. So on first run, if we don't see one
on PATH, we fetch the upstream release archive for the current platform,
verify its SHA-256 against the same release's checksums file, and cache the
binary under `~/.cache/sureguard/bin/gitleaks`.

Trust model: TOFU. We pin a known-good version, fetch the binary and the
checksums file from the same GitHub release URL over HTTPS, and reject the
binary unless the hash matches. If the GitHub release itself is compromised,
both files would be poisoned together — which is the same trust model rustup,
pip, and Homebrew use. Sigstore verification would be the next step up but
is overkill for v0.

Opt-out: set `SUREGUARD_NO_AUTO_INSTALL=1` to skip the download and fall back
to the built-in pattern detector.
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

log = logging.getLogger("sureguard.gitleaks-install")

# Pin a known-good gitleaks release. Bump alongside an actual test against
# the new version's output format — the JSON shape has changed in the past.
GITLEAKS_VERSION = "8.21.2"

# Where the cached binary lives. Aligns with the rest of the on-disk cache.
CACHE_DIR = Path.home() / ".cache" / "sureguard" / "bin"


def _platform_slug() -> str | None:
    """Return the slug gitleaks uses in its release archive names, or None if unsupported."""
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Darwin":
        if machine in ("arm64", "aarch64"):
            return "darwin_arm64"
        if machine in ("x86_64", "amd64"):
            return "darwin_x64"
    elif system == "Linux":
        if machine in ("aarch64", "arm64"):
            return "linux_arm64"
        if machine in ("x86_64", "amd64"):
            return "linux_x64"
    # Windows is .zip, not .tar.gz — handle in a v0.2 once someone asks.
    return None


def _archive_url(slug: str) -> str:
    return (
        f"https://github.com/gitleaks/gitleaks/releases/download/"
        f"v{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_{slug}.tar.gz"
    )


def _checksums_url() -> str:
    return (
        f"https://github.com/gitleaks/gitleaks/releases/download/"
        f"v{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_checksums.txt"
    )


def _http_get(url: str, timeout: int) -> bytes:
    """Tiny urllib wrapper with a Sureguard user-agent and timeout."""
    req = urllib.request.Request(url, headers={"User-Agent": "sureguard-code-scanner"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _expected_checksum(checksums_text: str, archive_name: str) -> str | None:
    """Parse `<sha256>  <filename>` lines and return the hash for archive_name."""
    for line in checksums_text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == archive_name:
            return parts[0]
    return None


def _safe_extract_member(tar: tarfile.TarFile, member_name: str, dest_dir: Path) -> Path | None:
    """Extract exactly one named member to dest_dir, refusing path traversal."""
    try:
        member = tar.getmember(member_name)
    except KeyError:
        return None
    # Defense in depth: reject anything that isn't a plain regular file with a sane name.
    if not member.isreg() or "/" in member.name or ".." in member.name:
        return None
    out_path = dest_dir / member.name
    with tar.extractfile(member) as src, open(out_path, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return out_path


def find_existing_gitleaks() -> Path | None:
    """Return a usable gitleaks binary if one already exists, else None.

    Checks PATH first (a user `brew install gitleaks` wins), then the cache.
    """
    system = shutil.which("gitleaks")
    if system:
        return Path(system)
    cached = CACHE_DIR / "gitleaks"
    if cached.exists() and os.access(cached, os.X_OK):
        return cached
    return None


def ensure_gitleaks(*, auto_install: bool | None = None) -> Path | None:
    """Return a Path to a usable gitleaks binary, fetching one on first run if needed.

    Returns None if the binary can't be made available (unsupported platform,
    network failure, checksum mismatch, or opt-out via env var). Callers should
    treat None as "fall back to the built-in pattern detector".
    """
    existing = find_existing_gitleaks()
    if existing:
        return existing

    if auto_install is None:
        auto_install = os.environ.get("SUREGUARD_NO_AUTO_INSTALL", "").strip() == ""

    if not auto_install:
        log.info("auto-install disabled via SUREGUARD_NO_AUTO_INSTALL")
        return None

    slug = _platform_slug()
    if not slug:
        log.info(
            "gitleaks auto-install: unsupported platform %s/%s; "
            "install manually (brew install gitleaks) or set SUREGUARD_NO_AUTO_INSTALL=1.",
            platform.system(),
            platform.machine(),
        )
        return None

    archive_name = f"gitleaks_{GITLEAKS_VERSION}_{slug}.tar.gz"
    print(
        f"sureguard: first-run setup — fetching gitleaks {GITLEAKS_VERSION} ({slug}). "
        "Cached locally; future scans are instant.",
        file=sys.stderr,
        flush=True,
    )

    try:
        checksums_text = _http_get(_checksums_url(), timeout=30).decode("utf-8")
    except (OSError, ValueError) as e:
        log.warning("gitleaks auto-install: could not fetch checksums (%s)", e)
        return None

    expected = _expected_checksum(checksums_text, archive_name)
    if not expected:
        log.warning("gitleaks auto-install: no checksum entry for %s", archive_name)
        return None

    try:
        archive_bytes = _http_get(_archive_url(slug), timeout=120)
    except (OSError, ValueError) as e:
        log.warning("gitleaks auto-install: download failed (%s)", e)
        return None

    actual = hashlib.sha256(archive_bytes).hexdigest()
    if actual != expected:
        log.warning(
            "gitleaks auto-install: checksum mismatch (expected %s, got %s) — refusing to install",
            expected,
            actual,
        )
        return None

    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tmp.write(archive_bytes)
        tmp_path = Path(tmp.name)
    try:
        with tarfile.open(tmp_path, mode="r:gz") as tar:
            extracted = _safe_extract_member(tar, "gitleaks", CACHE_DIR)
    finally:
        tmp_path.unlink(missing_ok=True)

    if not extracted or not extracted.exists():
        log.warning("gitleaks auto-install: archive did not contain expected 'gitleaks' entry")
        return None

    # Make it executable.
    mode = extracted.stat().st_mode
    extracted.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"sureguard: gitleaks installed at {extracted}", file=sys.stderr, flush=True)
    return extracted
