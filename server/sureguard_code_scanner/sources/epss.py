"""EPSS (Exploit Prediction Scoring System) client.

EPSS gives you a 0..1 probability that a CVE will be exploited in the wild
within the next 30 days. It's what lets you prioritize the 50 CVSS=7.5
findings instead of treating them all the same.
"""

from __future__ import annotations

import httpx

from ..cache import Cache, default_cache

EPSS_API = "https://api.first.org/data/v1/epss"
_TTL_SECONDS = 24 * 3600


class EPSSClient:
    def __init__(self, cache: Cache | None = None, http: httpx.AsyncClient | None = None) -> None:
        self.cache = cache or default_cache()
        self.http = http or httpx.AsyncClient(timeout=httpx.Timeout(15.0))

    async def aclose(self) -> None:
        await self.http.aclose()

    async def scores(self, cve_ids: list[str]) -> dict[str, float]:
        """Return {cve: epss_score} for as many as can be resolved."""
        result: dict[str, float] = {}
        uncached: list[str] = []
        for cve in cve_ids:
            cached = self.cache.get("epss", cve)
            if cached is not None:
                result[cve] = cached
            else:
                uncached.append(cve)
        if not uncached:
            return result

        # EPSS supports up to 100 CVEs per query via comma-separated cve param.
        for i in range(0, len(uncached), 100):
            chunk = uncached[i : i + 100]
            resp = await self.http.get(EPSS_API, params={"cve": ",".join(chunk)})
            resp.raise_for_status()
            payload = resp.json()
            for entry in payload.get("data", []):
                cve = entry.get("cve")
                score = entry.get("epss")
                if cve and score is not None:
                    score = float(score)
                    result[cve] = score
                    self.cache.set("epss", cve, score, _TTL_SECONDS)
        return result
