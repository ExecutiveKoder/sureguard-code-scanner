"""Tests for the secret-finding path filters (.env, docs, tests, IDE config)."""

from __future__ import annotations

from sureguard_code_scanner.engines.gitleaks import (
    is_doc_file_path,
    is_env_file_path,
    is_ide_config_path,
    is_test_file_path,
    should_drop_secret,
)


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


def test_doc_paths_detected():
    for p in [
        "README.md",
        "docs/setup.md",
        "AUTH0_MIGRATION.md",
        "guide.mdx",
        "manual.rst",
        "notes.txt",
        "spec.adoc",
        "deep/nested/CHANGELOG.MD",  # case-insensitive
    ]:
        assert is_doc_file_path(p), p


def test_doc_path_negatives():
    for p in ["src/main.py", "config.json", "Makefile", "deploy.sh"]:
        assert not is_doc_file_path(p), p


def test_test_paths_detected():
    for p in [
        "tests/test_foo.py",
        "test/foo.py",
        "TestCases/test_concurrent_warmup.py",
        "src/__tests__/Button.test.tsx",
        "spec/user_spec.rb",
        "fixtures/sample.json",
        "fixture/payload.json",
        "test_start.py",
        "foo_test.go",
        "Button.test.js",
        "api.spec.ts",
    ]:
        assert is_test_file_path(p), p


def test_test_path_negatives():
    for p in [
        "src/main.py",
        "testing.txt",  # not in a test dir, not a test_*.py
        "contests/leaderboard.py",  # 'tests' substring but not at boundary
    ]:
        assert not is_test_file_path(p), p


def test_ide_config_paths():
    assert is_ide_config_path(".claude/settings.local.json")
    assert is_ide_config_path(".vscode/settings.json")
    assert is_ide_config_path(".idea/workspace.xml")
    assert is_ide_config_path(".cursor/config.json")
    assert not is_ide_config_path("src/.claude.py")
    assert not is_ide_config_path("vscode/something.json")


def test_should_drop_secret_default_drops_noise():
    assert should_drop_secret(
        ".env",
        include_env_secrets=False,
        include_doc_secrets=False,
        include_test_secrets=False,
        include_ide_secrets=False,
    )
    assert should_drop_secret(
        "README.md",
        include_env_secrets=False,
        include_doc_secrets=False,
        include_test_secrets=False,
        include_ide_secrets=False,
    )
    # Real source code is never dropped, regardless of flag combinations.
    assert not should_drop_secret(
        "src/app.py",
        include_env_secrets=False,
        include_doc_secrets=False,
        include_test_secrets=False,
        include_ide_secrets=False,
    )


def test_should_drop_secret_respects_overrides():
    # With include_doc_secrets=True, the README hit comes through.
    assert not should_drop_secret(
        "README.md",
        include_env_secrets=False,
        include_doc_secrets=True,
        include_test_secrets=False,
        include_ide_secrets=False,
    )
