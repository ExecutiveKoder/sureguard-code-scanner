"""Offline tests for the gitleaks auto-installer helpers."""

from __future__ import annotations

from unittest.mock import patch

from sureguard_code_scanner.engines.gitleaks_installer import (
    GITLEAKS_VERSION,
    _archive_url,
    _checksums_url,
    _expected_checksum,
    _platform_slug,
)


def test_platform_slug_known_combos():
    with patch("platform.system", return_value="Darwin"), patch("platform.machine", return_value="arm64"):
        assert _platform_slug() == "darwin_arm64"
    with patch("platform.system", return_value="Darwin"), patch("platform.machine", return_value="x86_64"):
        assert _platform_slug() == "darwin_x64"
    with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
        assert _platform_slug() == "linux_x64"
    with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="aarch64"):
        assert _platform_slug() == "linux_arm64"


def test_platform_slug_unsupported_returns_none():
    with patch("platform.system", return_value="Windows"), patch("platform.machine", return_value="AMD64"):
        assert _platform_slug() is None
    with patch("platform.system", return_value="Plan9"), patch("platform.machine", return_value="riscv64"):
        assert _platform_slug() is None


def test_urls_contain_pinned_version():
    url = _archive_url("darwin_arm64")
    assert GITLEAKS_VERSION in url
    assert url.startswith("https://github.com/gitleaks/gitleaks/releases/download/")
    assert _checksums_url().endswith("_checksums.txt")


def test_expected_checksum_parses_release_format():
    text = (
        "abc123  gitleaks_8.21.2_darwin_x64.tar.gz\n"
        "def456  gitleaks_8.21.2_darwin_arm64.tar.gz\n"
        "fff999  gitleaks_8.21.2_linux_x64.tar.gz\n"
    )
    assert _expected_checksum(text, "gitleaks_8.21.2_darwin_arm64.tar.gz") == "def456"
    assert _expected_checksum(text, "gitleaks_8.21.2_linux_x64.tar.gz") == "fff999"


def test_expected_checksum_missing_returns_none():
    text = "abc123  gitleaks_8.21.2_darwin_x64.tar.gz\n"
    assert _expected_checksum(text, "gitleaks_8.21.2_windows_x64.zip") is None
