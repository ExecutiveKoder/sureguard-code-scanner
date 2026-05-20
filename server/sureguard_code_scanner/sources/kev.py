"""CISA Known Exploited Vulnerabilities catalog.

KEV presence is the single best signal for "this is actively exploited in the
wild, not theoretical." We refresh hourly and treat KEV ∩ your dependencies
as a hard fail in default policy.
"""

from __future__ import annotations

import logging

import httpx

from ..cache import Cache, default_cache

log = logging.getLogger("sureguard.kev")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_TTL_SECONDS = 3600  # 1h — KEV updates are rare but always worth picking up fast


class KEVCatalog:
    def __init__(self, cache: Cache | None = None, http: httpx.AsyncClient | None = None) -> None:
        self.cache = cache or default_cache()
        self.http = http or httpx.AsyncClient(timeout=httpx.Timeout(15.0))
        self._cves: set[str] | None = None

    async def aclose(self) -> None:
        await self.http.aclose()

    async def cves(self) -> set[str]:
        if self._cves is not None:
            return self._cves
        cached = self.cache.get("kev", "catalog")
        if cached is not None:
            log.debug("KEV catalog served from cache (%d CVEs)", len(cached))
            self._cves = set(cached)
            return self._cves
        log.info("fetching CISA KEV catalog from %s", KEV_URL)
        resp = await self.http.get(KEV_URL)
        resp.raise_for_status()
        data = resp.json()
        cves = {v["cveID"] for v in data.get("vulnerabilities", [])}
        log.info("KEV catalog fetched: %d actively-exploited CVEs", len(cves))
        self.cache.set("kev", "catalog", sorted(cves), _TTL_SECONDS)
        self._cves = cves
        return cves

    async def contains(self, cve_id: str) -> bool:
        return cve_id in await self.cves()

    async def intersect(self, cve_ids: list[str]) -> list[str]:
        cat = await self.cves()
        return [c for c in cve_ids if c in cat]
