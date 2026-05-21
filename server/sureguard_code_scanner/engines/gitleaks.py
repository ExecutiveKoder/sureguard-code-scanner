"""Gitleaks wrapper for secret detection.

We use Gitleaks because it ships a curated default rule set and runs fast
on raw filesystem trees (not just git history). If it isn't installed, we
fall back to a small pattern-and-entropy detector so `scan_secrets` always
returns *something* useful — important for the demo path.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
from pathlib import Path

from ..models import Finding, Location, Severity


class GitleaksNotInstalled(RuntimeError):
    pass


# Each of these path-pattern groups represents a category of file where a
# gitleaks hit is *usually* a false positive. By default we filter them out so
# the score and the action plan reflect real risk. Opt-back-in flags exist on
# the CLI for users who need exhaustive scanning (audits, leak hunts).
#
#   .env*        : local-only environment files; if committed at all, the fix
#                  is "stop committing it," not "rotate every value here."
#   docs         : tutorial files routinely contain example tokens like
#                  "Bearer eyJ..." that gitleaks can't tell apart from real keys.
#   tests        : fixtures and unit tests use throwaway tokens by design.
#   IDE config   : .claude/, .vscode/, .idea/ — editor settings, sometimes
#                  contain local API keys but never get pushed to prod.

_ENV_PATH_PATTERNS = (
    re.compile(r"(^|/)\.env(\..+)?$"),  # .env, .env.local, .env.bak, .env.production
    re.compile(r"(^|/)\.env-[^/]+$"),  # .env-staging, .env-prod
)

_DOC_PATH_PATTERNS = (
    re.compile(r"\.(md|mdx|markdown|rst|adoc|txt)$", re.IGNORECASE),
)

_TEST_PATH_PATTERNS = (
    re.compile(r"(^|/)tests?(/|$)"),
    re.compile(r"(^|/)TestCases(/|$)"),
    re.compile(r"(^|/)__tests__(/|$)"),
    re.compile(r"(^|/)fixtures?(/|$)"),
    re.compile(r"(^|/)spec(/|$)"),
    re.compile(r"(^|/)test_[^/]+\.[a-zA-Z]+$"),  # test_*.py, test_*.go
    re.compile(r"(^|/)[^/]+_test\.[a-zA-Z]+$"),  # *_test.py, *_test.go
    re.compile(r"(^|/)[^/]+\.test\.[a-zA-Z]+$"),  # *.test.js, *.test.ts
    re.compile(r"(^|/)[^/]+\.spec\.[a-zA-Z]+$"),  # *.spec.js, *.spec.ts
)

_IDE_PATH_PATTERNS = (
    re.compile(r"(^|/)\.claude(/|$)"),
    re.compile(r"(^|/)\.vscode(/|$)"),
    re.compile(r"(^|/)\.idea(/|$)"),
    re.compile(r"(^|/)\.cursor(/|$)"),
)


def is_env_file_path(path: str | None) -> bool:
    """True if the path looks like a `.env*` file."""
    if not path:
        return False
    return any(p.search(path) for p in _ENV_PATH_PATTERNS)


def is_doc_file_path(path: str | None) -> bool:
    """True if the path looks like a documentation file (.md, .rst, etc.)."""
    if not path:
        return False
    return any(p.search(path) for p in _DOC_PATH_PATTERNS)


def is_test_file_path(path: str | None) -> bool:
    """True if the path looks like a test fixture / test file."""
    if not path:
        return False
    return any(p.search(path) for p in _TEST_PATH_PATTERNS)


def is_ide_config_path(path: str | None) -> bool:
    """True if the path lives inside an IDE / editor config directory."""
    if not path:
        return False
    return any(p.search(path) for p in _IDE_PATH_PATTERNS)


def should_drop_secret(
    path: str | None,
    *,
    include_env_secrets: bool,
    include_doc_secrets: bool,
    include_test_secrets: bool,
    include_ide_secrets: bool,
) -> bool:
    """Single decision point: should this secret finding be dropped as low-signal noise?"""
    if not include_env_secrets and is_env_file_path(path):
        return True
    if not include_doc_secrets and is_doc_file_path(path):
        return True
    if not include_test_secrets and is_test_file_path(path):
        return True
    if not include_ide_secrets and is_ide_config_path(path):
        return True
    return False


_FALLBACK_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "sureguard.secret.aws-access-key",
        "AWS access key id",
        re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
    ),
    (
        "sureguard.secret.aws-secret-key",
        "AWS secret access key (heuristic)",
        re.compile(r"(?i)aws(.{0,20})?(secret|sk)[^\n]{0,3}[:=][^\n]{0,3}([A-Za-z0-9/+=]{40})"),
    ),
    (
        "sureguard.secret.openai-key",
        "OpenAI API key",
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
    ),
    (
        "sureguard.secret.anthropic-key",
        "Anthropic API key",
        re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    ),
    (
        "sureguard.secret.github-token",
        "GitHub token",
        re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}"),
    ),
    (
        "sureguard.secret.slack-token",
        "Slack token",
        re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"),
    ),
    (
        "sureguard.secret.private-key",
        "Private key block",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


async def run_gitleaks(
    target_path: Path,
    timeout_seconds: int = 60,
    *,
    include_env_secrets: bool = False,
    include_doc_secrets: bool = False,
    include_test_secrets: bool = False,
    include_ide_secrets: bool = False,
) -> list[Finding]:
    # Auto-installs on first run if not already on PATH or cached. Returns None
    # only if the platform is unsupported, the download fails, or the user
    # opted out via SUREGUARD_NO_AUTO_INSTALL.
    from .gitleaks_installer import ensure_gitleaks

    binary_path = ensure_gitleaks()
    if binary_path is None:
        raise GitleaksNotInstalled(
            "gitleaks unavailable (auto-install skipped or failed). "
            "Falling back to built-in pattern+entropy detector."
        )
    binary = str(binary_path)

    report = target_path / ".sureguard-gitleaks.json"
    if report.exists():
        report.unlink()

    cmd = [
        binary,
        "detect",
        "--no-git",
        "--source",
        str(target_path),
        "--report-format",
        "json",
        "--report-path",
        str(report),
        "--exit-code",
        "0",
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await asyncio.wait_for(proc.wait(), timeout=timeout_seconds)

    if not report.exists():
        return []
    try:
        records = json.loads(report.read_text())
    except json.JSONDecodeError:
        return []
    finally:
        report.unlink(missing_ok=True)

    findings: list[Finding] = []
    for rec in records or []:
        file_path = rec.get("File")
        if should_drop_secret(
            file_path,
            include_env_secrets=include_env_secrets,
            include_doc_secrets=include_doc_secrets,
            include_test_secrets=include_test_secrets,
            include_ide_secrets=include_ide_secrets,
        ):
            continue
        findings.append(
            Finding(
                id=f"sureguard.secret.{rec.get('RuleID', 'unknown')}",
                title=f"Secret: {rec.get('Description', rec.get('RuleID', 'unknown'))}",
                severity=Severity.HIGH,
                category="secret",
                message=rec.get("Description") or "Hardcoded secret detected.",
                location=Location(
                    path=file_path,
                    line=rec.get("StartLine"),
                    end_line=rec.get("EndLine"),
                    snippet=(rec.get("Match") or "")[:240] or None,
                ),
                fix="Move the value to a secrets manager (Vault, AWS Secrets Manager, env vars) and rotate this credential — it must be considered compromised.",
            )
        )
    return findings


def fallback_scan_text(content: str, path: str | None = None) -> list[Finding]:
    """Pattern + entropy detector for environments without gitleaks installed."""
    findings: list[Finding] = []
    for finding_id, title, pattern in _FALLBACK_PATTERNS:
        for m in pattern.finditer(content):
            line = content.count("\n", 0, m.start()) + 1
            findings.append(
                Finding(
                    id=finding_id,
                    title=title,
                    severity=Severity.HIGH,
                    category="secret",
                    message=f"Looks like a {title.lower()} embedded in source.",
                    location=Location(path=path, line=line, snippet=m.group(0)[:120]),
                    fix="Rotate immediately and move to a secrets manager.",
                )
            )

    # High-entropy long literals — common LLM mistake when it invents a "placeholder" that looks real.
    for m in re.finditer(r'["\']([A-Za-z0-9+/=_\-]{32,})["\']', content):
        token = m.group(1)
        if _entropy(token) > 4.5:
            line = content.count("\n", 0, m.start()) + 1
            findings.append(
                Finding(
                    id="sureguard.secret.high-entropy-literal",
                    title="High-entropy literal",
                    severity=Severity.MEDIUM,
                    category="secret",
                    message="Long, high-entropy string literal looks like a credential. AI-generated code frequently embeds real-looking tokens 'for the example'.",
                    location=Location(path=path, line=line, snippet=token[:60] + "…"),
                    fix="If this is a real secret, rotate it. If it's an example, use an obvious placeholder like 'REPLACE_ME'.",
                )
            )
    return findings
