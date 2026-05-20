"""OSV.dev client.

OSV is the highest-leverage single integration: one API unifies GHSA, PyPI,
npm, RubyGems, crates, Maven, Go, and Packagist advisories. The batched
endpoint accepts up to 1000 queries at a time, which is what makes
scan_dependencies fast on large manifests.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ..cache import Cache, default_cache
from ..models import Ecosystem, PackageRef

log = logging.getLogger("sureguard.osv")

OSV_API = "https://api.osv.dev"
_TTL_SECONDS = 24 * 3600  # OSV updates daily-ish

_ECOSYSTEM_NAME = {
    Ecosystem.PYPI: "PyPI",
    Ecosystem.NPM: "npm",
    Ecosystem.MAVEN: "Maven",
    Ecosystem.RUBYGEMS: "RubyGems",
    Ecosystem.GO: "Go",
    Ecosystem.CRATES: "crates.io",
    Ecosystem.NUGET: "NuGet",
    Ecosystem.PACKAGIST: "Packagist",
}


class OSVClient:
    def __init__(self, cache: Cache | None = None, http: httpx.AsyncClient | None = None) -> None:
        self.cache = cache or default_cache()
        self.http = http or httpx.AsyncClient(timeout=httpx.Timeout(15.0))

    async def aclose(self) -> None:
        await self.http.aclose()

    def _cache_key(self, pkg: PackageRef) -> str:
        return f"{pkg.ecosystem.value}|{pkg.name}|{pkg.version or '*'}"

    async def query_batch(self, packages: list[PackageRef]) -> dict[str, list[dict[str, Any]]]:
        """Look up advisories for many packages in one request.

        Returns a dict keyed by `cache_key(pkg)` → list of OSV vuln records.
        """
        results: dict[str, list[dict[str, Any]]] = {}
        uncached: list[PackageRef] = []

        for pkg in packages:
            cached = self.cache.get("osv", self._cache_key(pkg))
            if cached is not None:
                results[self._cache_key(pkg)] = cached
            else:
                uncached.append(pkg)

        if uncached:
            log.info(
                "OSV: %d cached, %d to query in batches of up to 1000",
                len(packages) - len(uncached),
                len(uncached),
            )
        else:
            log.debug("OSV: all %d packages served from cache", len(packages))
            return results

        # OSV's batched endpoint takes up to 1000 queries per call.
        for chunk_start in range(0, len(uncached), 1000):
            chunk = uncached[chunk_start : chunk_start + 1000]
            log.info("OSV: posting batch of %d queries to %s/v1/querybatch", len(chunk), OSV_API)
            body = {
                "queries": [
                    {
                        "package": {
                            "name": p.name,
                            "ecosystem": _ECOSYSTEM_NAME[p.ecosystem],
                        },
                        **({"version": p.version} if p.version else {}),
                    }
                    for p in chunk
                ]
            }
            resp = await self.http.post(f"{OSV_API}/v1/querybatch", json=body)
            resp.raise_for_status()
            data = resp.json()
            for pkg, entry in zip(chunk, data.get("results", []), strict=True):
                vulns = entry.get("vulns") or []
                # querybatch returns IDs only; hydrate detail in parallel.
                hydrated = []
                for stub in vulns:
                    detail = await self._get_vuln(stub["id"])
                    if detail:
                        hydrated.append(detail)
                key = self._cache_key(pkg)
                results[key] = hydrated
                self.cache.set("osv", key, hydrated, _TTL_SECONDS)

        return results

    async def _get_vuln(self, vuln_id: str) -> dict[str, Any] | None:
        cached = self.cache.get("osv-vuln", vuln_id)
        if cached is not None:
            return cached
        resp = await self.http.get(f"{OSV_API}/v1/vulns/{vuln_id}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        self.cache.set("osv-vuln", vuln_id, data, _TTL_SECONDS)
        return data


def extract_cvss(vuln: dict[str, Any]) -> float | None:
    """Pull a CVSS v3.x base score from an OSV vulnerability record, if present."""
    for sev in vuln.get("severity", []) or []:
        if sev.get("type", "").startswith("CVSS_V3") and sev.get("score"):
            # OSV exposes the vector string; the base score is the first segment after CVSS:3.x/
            try:
                score_field = sev["score"]
                if "/" in score_field:
                    # vector form like "CVSS:3.1/AV:N/AC:L/..." — caller would need cvss lib to compute
                    # OSV also includes numeric scores in databaseSpecific for many records, but the
                    # canonical place is the GHSA/NVD-linked record. We rely on the affected → ranges.
                    continue
                return float(score_field)
            except (ValueError, KeyError):
                continue
    return None


def extract_cves(vuln: dict[str, Any]) -> list[str]:
    return [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
