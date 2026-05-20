"""Package registry probes for hallucination / typosquat detection.

The hallucination check is dead simple: ask the registry "does this exist?".
If a model emitted `import requestz` and `requestz` isn't on PyPI, we have a
slopsquat-bait situation regardless of whether it's already malicious.

The typosquat heuristic uses Damerau-Levenshtein against a list of the
top packages per ecosystem. If a name is distance 1 from a popular package
but isn't that package, flag it.
"""

from __future__ import annotations

import logging

import httpx

from ..cache import Cache, default_cache
from ..models import Ecosystem, PackageRef, PackageVerification

log = logging.getLogger("sureguard.registry")

_REGISTRY_TTL = 6 * 3600

# Curated top-package lists used for typosquat distance checks. Intentionally
# small at v0 — replace with a periodically-refreshed list in v0.2.
_POPULAR: dict[Ecosystem, set[str]] = {
    Ecosystem.PYPI: {
        "requests", "urllib3", "boto3", "botocore", "numpy", "pandas",
        "django", "flask", "fastapi", "sqlalchemy", "pydantic", "httpx",
        "pytest", "setuptools", "wheel", "pip", "cryptography", "openai",
        "anthropic", "langchain", "transformers", "torch", "tensorflow",
    },
    Ecosystem.NPM: {
        "react", "react-dom", "lodash", "axios", "express", "next",
        "vue", "webpack", "vite", "typescript", "eslint", "prettier",
        "tailwindcss", "jest", "vitest", "openai", "anthropic",
        "@anthropic-ai/sdk", "langchain",
    },
}


def _damerau_levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    da: dict[str, int] = {}
    maxd = len(a) + len(b)
    d = [[0] * (len(b) + 2) for _ in range(len(a) + 2)]
    d[0][0] = maxd
    for i in range(len(a) + 1):
        d[i + 1][0] = maxd
        d[i + 1][1] = i
    for j in range(len(b) + 1):
        d[0][j + 1] = maxd
        d[1][j + 1] = j
    for i in range(1, len(a) + 1):
        db_idx = 0
        for j in range(1, len(b) + 1):
            k = da.get(b[j - 1], 0)
            ll = db_idx
            cost = 0 if a[i - 1] == b[j - 1] else 1
            if cost == 0:
                db_idx = j
            d[i + 1][j + 1] = min(
                d[i][j] + cost,
                d[i + 1][j] + 1,
                d[i][j + 1] + 1,
                d[k][ll] + (i - k - 1) + 1 + (j - ll - 1),
            )
        da[a[i - 1]] = i
    return d[len(a) + 1][len(b) + 1]


def typosquat_candidates(name: str, ecosystem: Ecosystem) -> list[str]:
    popular = _POPULAR.get(ecosystem, set())
    if name in popular:
        return []
    return sorted(p for p in popular if _damerau_levenshtein(name.lower(), p.lower()) == 1)


class RegistryClient:
    def __init__(self, cache: Cache | None = None, http: httpx.AsyncClient | None = None) -> None:
        self.cache = cache or default_cache()
        self.http = http or httpx.AsyncClient(timeout=httpx.Timeout(10.0))

    async def aclose(self) -> None:
        await self.http.aclose()

    async def verify(self, pkg: PackageRef) -> PackageVerification:
        cached = self.cache.get("registry", f"{pkg.ecosystem.value}|{pkg.name}")
        if cached is not None:
            log.debug("registry cache hit: %s/%s", pkg.ecosystem.value, pkg.name)
            base = PackageVerification.model_validate(cached)
            base.package = pkg
            return base

        log.info("verifying %s/%s against registry", pkg.ecosystem.value, pkg.name)
        if pkg.ecosystem == Ecosystem.PYPI:
            v = await self._verify_pypi(pkg)
        elif pkg.ecosystem == Ecosystem.NPM:
            v = await self._verify_npm(pkg)
        else:
            v = PackageVerification(
                package=pkg,
                exists=True,
                is_hallucinated=False,
                warnings=[f"registry probe not yet implemented for {pkg.ecosystem.value}"],
            )

        v.typosquat_candidates = typosquat_candidates(pkg.name, pkg.ecosystem)
        v.is_typosquat_suspect = bool(v.typosquat_candidates) and not v.exists
        self.cache.set(
            "registry",
            f"{pkg.ecosystem.value}|{pkg.name}",
            v.model_dump(mode="json"),
            _REGISTRY_TTL,
        )
        return v

    async def _verify_pypi(self, pkg: PackageRef) -> PackageVerification:
        resp = await self.http.get(f"https://pypi.org/pypi/{pkg.name}/json")
        if resp.status_code == 404:
            return PackageVerification(package=pkg, exists=False, is_hallucinated=True)
        resp.raise_for_status()
        data = resp.json()
        info = data.get("info", {})
        releases = data.get("releases", {})
        yanked = False
        if pkg.version and pkg.version in releases:
            yanked = all(r.get("yanked", False) for r in releases[pkg.version])
        return PackageVerification(
            package=pkg,
            exists=True,
            is_hallucinated=False,
            first_seen=(info.get("upload_time") or None),
            yanked=yanked,
        )

    async def _verify_npm(self, pkg: PackageRef) -> PackageVerification:
        resp = await self.http.get(f"https://registry.npmjs.org/{pkg.name}")
        if resp.status_code == 404:
            return PackageVerification(package=pkg, exists=False, is_hallucinated=True)
        resp.raise_for_status()
        data = resp.json()
        first_seen = (data.get("time") or {}).get("created")
        return PackageVerification(
            package=pkg,
            exists=True,
            is_hallucinated=False,
            first_seen=first_seen,
        )
