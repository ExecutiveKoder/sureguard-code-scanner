"""FastMCP server wiring for Sureguard.

The MCP surface here is the contract for both Pattern A (CI thin client) and
Pattern B (AI reviewer). Keep argument names stable; agents key off them.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from . import __version__
from .sarif import findings_to_sarif
from .tools.check_runtime_risk import check_runtime_risk as _check_runtime_risk
from .tools.policy_for import policy_for as _policy_for
from .tools.scan_code import scan_code as _scan_code
from .tools.scan_dependencies import scan_dependencies as _scan_dependencies
from .tools.scan_diff import scan_diff as _scan_diff
from .tools.scan_secrets import scan_secrets as _scan_secrets
from .tools.verify_package import verify_package as _verify_package

mcp = FastMCP("sureguard")


@mcp.tool()
async def scan_code(content: str, language: str = "python", filename: str | None = None) -> dict[str, Any]:
    """SAST pass over a code block using Sureguard's AI-aware rule pack (via Semgrep).

    Use this to vet code an AI agent just generated, before writing it to disk.

    Args:
        content: The source code to scan.
        language: Source language. Supported: python, javascript, typescript, go, java, ruby, php.
        filename: Optional filename hint; affects display path in findings.
    """
    return (await _scan_code(content, language=language, filename=filename)).model_dump(mode="json")


@mcp.tool()
async def scan_dependencies(
    manifest_filename: str,
    content: str,
    verify_existence: bool = True,
) -> dict[str, Any]:
    """SCA pass over a manifest file. Cross-references OSV.dev + CISA KEV + EPSS.

    Args:
        manifest_filename: e.g. "requirements.txt", "package.json", "package-lock.json", "pyproject.toml".
        content: The full text of the manifest file.
        verify_existence: If True, also probe each package's registry to catch hallucinations
            and typosquats. Slower but the single most valuable check for AI-generated code.
    """
    return (
        await _scan_dependencies(manifest_filename, content, verify_existence=verify_existence)
    ).model_dump(mode="json")


@mcp.tool()
async def verify_package(
    name: str,
    ecosystem: str,
    version: str | None = None,
) -> dict[str, Any]:
    """Verify a single package exists in its registry. The slopsquatting catch.

    Call this BEFORE installing or importing a package an AI agent suggested.

    Args:
        name: Package name as the agent wrote it.
        ecosystem: One of pypi, npm, maven, rubygems, go, crates, nuget, packagist.
        version: Optional specific version to check (also detects yanked releases for PyPI).
    """
    return (
        await _verify_package(name=name, ecosystem=ecosystem, version=version)
    ).model_dump(mode="json")


@mcp.tool()
async def scan_diff(diff: str) -> dict[str, Any]:
    """Scan only the added lines from a unified diff. Use for PR review / pre-commit.

    Args:
        diff: A unified diff (`git diff` output, or a GitHub PR patch).
    """
    return (await _scan_diff(diff)).model_dump(mode="json")


@mcp.tool()
async def scan_secrets(content: str, filename: str | None = None) -> dict[str, Any]:
    """Detect hardcoded secrets via Gitleaks (or built-in pattern+entropy fallback).

    Args:
        content: Source text to scan.
        filename: Optional filename hint for display.
    """
    return (await _scan_secrets(content, filename=filename)).model_dump(mode="json")


@mcp.tool()
async def check_runtime_risk(sbom: dict[str, Any]) -> dict[str, Any]:
    """Cross-reference a deployed SBOM (CycloneDX or SPDX) against new CVE disclosures + KEV.

    Use this post-deploy to catch the case where a shipped dependency becomes
    vulnerable after release — the audit-grade control.

    Args:
        sbom: Parsed SBOM JSON. CycloneDX components[] with `purl`, or SPDX packages[].
    """
    return (await _check_runtime_risk(sbom)).model_dump(mode="json")


@mcp.tool()
async def policy_for(language: str, framework: str | None = None) -> dict[str, Any]:
    """Return Sureguard's guardrail rule pack for a language so an agent can self-correct.

    Call this at the start of a generation session and treat the returned rules
    as constraints to obey while writing code.
    """
    return await _policy_for(language=language, framework=framework)


@mcp.tool()
async def to_sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Convert a list of Sureguard Finding dicts to SARIF v2.1.0 for CI upload."""
    from .models import Finding

    parsed = [Finding.model_validate(f) for f in findings]
    return findings_to_sarif(parsed)


@mcp.tool()
def version() -> str:
    """Return the Sureguard server version."""
    return __version__


def main() -> None:
    mcp.run()
