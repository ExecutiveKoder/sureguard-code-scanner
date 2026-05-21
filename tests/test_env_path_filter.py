"""Tests for the .env* secret filter."""

from __future__ import annotations

from sureguard_code_scanner.engines.gitleaks import is_env_file_path


def test_plain_env_file_is_excluded():
    assert is_env_file_path(".env")
    assert is_env_file_path("backend/.env")


def test_env_variants_are_excluded():
    for p in [
        ".env.local",
        ".env.production",
        ".env.development",
        ".env.bak",
        "frontend/.env.local",
        "deep/nested/dir/.env.staging",
        ".env-prod",
        "infra/.env-staging",
    ]:
        assert is_env_file_path(p), p


def test_non_env_files_are_kept():
    for p in [
        "src/config.py",
        "backend/.envrc",   # direnv config, not a dotenv values file
        "envoy.yaml",
        "envelope.txt",
        "README.md",
        ".github/workflows/ci.yml",
        ".env_example.md",  # docs about .env are still scanned
    ]:
        assert not is_env_file_path(p), p


def test_none_and_empty():
    assert not is_env_file_path(None)
    assert not is_env_file_path("")
