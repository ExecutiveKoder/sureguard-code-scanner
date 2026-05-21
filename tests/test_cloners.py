"""Offline tests for the URL/path detector and the strict GitHub URL parser."""

from __future__ import annotations

import pytest

from sureguard_code_scanner.cloners import CloneError, looks_like_url, parse_github_url


def test_https_github_url_is_url():
    assert looks_like_url("https://github.com/foo/bar")
    assert looks_like_url("https://github.com/foo/bar.git")
    assert looks_like_url("http://example.com/repo.git")


def test_ssh_url_is_url():
    assert looks_like_url("git@github.com:foo/bar.git")
    assert looks_like_url("ssh://git@github.com/foo/bar.git")
    assert looks_like_url("git://github.com/foo/bar")


def test_local_paths_are_not_urls():
    for p in ["/tmp/repo", "./foo", "../foo", "~/code", "relative/dir", "C:\\code", ""]:
        assert not looks_like_url(p), p


def test_parse_github_url_accepts_valid():
    assert parse_github_url("https://github.com/foo/bar") == ("foo", "bar")
    assert parse_github_url("https://github.com/foo/bar.git") == ("foo", "bar")
    assert parse_github_url("https://github.com/foo/bar/") == ("foo", "bar")


def test_parse_github_url_rejects_non_github():
    with pytest.raises(CloneError):
        parse_github_url("https://gitlab.com/foo/bar")
    with pytest.raises(CloneError):
        parse_github_url("https://github.com/foo/bar/tree/main")
    with pytest.raises(CloneError):
        parse_github_url("git@github.com:foo/bar.git")
    with pytest.raises(CloneError):
        parse_github_url("/tmp/local")
