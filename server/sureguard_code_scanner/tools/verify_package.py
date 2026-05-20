"""verify_package tool — the slopsquatting catch."""

from __future__ import annotations

from ..models import Ecosystem, PackageRef, PackageVerification
from ..sources.registries import RegistryClient


async def verify_package(
    name: str,
    ecosystem: str,
    version: str | None = None,
    client: RegistryClient | None = None,
) -> PackageVerification:
    """Verify that a package exists in its registry. Flag typosquat candidates."""
    try:
        eco = Ecosystem(ecosystem.lower())
    except ValueError as e:
        raise ValueError(
            f"Unknown ecosystem '{ecosystem}'. Use one of: {', '.join(e.value for e in Ecosystem)}"
        ) from e
    pkg = PackageRef(name=name, version=version, ecosystem=eco)
    rc = client or RegistryClient()
    try:
        return await rc.verify(pkg)
    finally:
        if client is None:
            await rc.aclose()
