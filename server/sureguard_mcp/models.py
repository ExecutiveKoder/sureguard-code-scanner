"""Shared pydantic models for Sureguard tool inputs and outputs.

The types here are the contract between the MCP tool surface and any consumer
(CI runners, AI reviewers, the SARIF emitter). Keep them stable.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Ecosystem(str, Enum):
    PYPI = "pypi"
    NPM = "npm"
    MAVEN = "maven"
    RUBYGEMS = "rubygems"
    GO = "go"
    CRATES = "crates"
    NUGET = "nuget"
    PACKAGIST = "packagist"


class Location(BaseModel):
    path: str | None = None
    line: int | None = None
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    snippet: str | None = None


class Finding(BaseModel):
    """One issue Sureguard wants to surface."""

    id: str = Field(..., description="Stable identifier, e.g. 'sureguard.python.md5'")
    title: str
    severity: Severity
    category: Literal[
        "vulnerability",
        "insecure-pattern",
        "hallucinated-package",
        "secret",
        "outdated",
        "license",
        "supply-chain",
    ]
    message: str
    location: Location | None = None
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    fix: str | None = None
    references: list[str] = Field(default_factory=list)
    risk_score: float | None = Field(
        default=None,
        description="Combined CVSS+EPSS+KEV score on a 0..10 scale. Higher = more urgent.",
    )
    in_kev: bool = False
    epss: float | None = None


class ScanResult(BaseModel):
    tool: str
    findings: list[Finding] = Field(default_factory=list)
    scanned_files: int = 0
    elapsed_ms: int = 0
    warnings: list[str] = Field(default_factory=list)


class PackageRef(BaseModel):
    name: str
    version: str | None = None
    ecosystem: Ecosystem


class PackageVerification(BaseModel):
    package: PackageRef
    exists: bool
    is_hallucinated: bool = Field(
        ...,
        description="True if the package cannot be found in the registry. The canonical slopsquatting catch.",
    )
    is_typosquat_suspect: bool = False
    typosquat_candidates: list[str] = Field(default_factory=list)
    first_seen: str | None = None
    download_count: int | None = None
    yanked: bool = False
    warnings: list[str] = Field(default_factory=list)


class SBOMComponent(BaseModel):
    name: str
    version: str
    ecosystem: Ecosystem
    purl: str | None = None
