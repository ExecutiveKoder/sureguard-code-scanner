"""check_runtime_risk — cross-reference an SBOM against CISA KEV + OSV.

This is the post-deploy monitoring path: re-scan a deployed SBOM after new
disclosures land. It's the control your auditors will actually care about,
because it proves you keep tracking a release after it ships, not just
at merge time.
"""

from __future__ import annotations

import time

from ..models import Finding, Location, PackageRef, ScanResult, Severity
from ..scoring import combined_risk_score, severity_from_score
from ..sources.epss import EPSSClient
from ..sources.kev import KEVCatalog
from ..sources.osv import OSVClient, extract_cves


def _normalize_sbom(sbom: dict) -> list[PackageRef]:
    """Accept CycloneDX-ish or SPDX-ish SBOMs and pull out (name, version, ecosystem)."""
    from ..models import Ecosystem

    components = sbom.get("components") or sbom.get("packages") or []
    refs: list[PackageRef] = []
    for c in components:
        name = c.get("name")
        version = c.get("version") or c.get("versionInfo")
        if not name or not version:
            continue
        purl = c.get("purl") or ""
        eco: Ecosystem | None = None
        if purl.startswith("pkg:pypi/"):
            eco = Ecosystem.PYPI
        elif purl.startswith("pkg:npm/"):
            eco = Ecosystem.NPM
        elif purl.startswith("pkg:maven/"):
            eco = Ecosystem.MAVEN
        elif purl.startswith("pkg:gem/"):
            eco = Ecosystem.RUBYGEMS
        elif purl.startswith("pkg:golang/"):
            eco = Ecosystem.GO
        elif purl.startswith("pkg:cargo/"):
            eco = Ecosystem.CRATES
        else:
            # Best-effort default — caller-provided 'ecosystem' field overrides.
            eco_field = (c.get("ecosystem") or "").lower()
            if eco_field:
                try:
                    eco = Ecosystem(eco_field)
                except ValueError:
                    pass
        if not eco:
            continue
        refs.append(PackageRef(name=name, version=version, ecosystem=eco, purl=purl or None))
    return refs


async def check_runtime_risk(sbom: dict) -> ScanResult:
    started = time.monotonic()
    components = _normalize_sbom(sbom)
    if not components:
        return ScanResult(
            tool="check_runtime_risk",
            warnings=[
                "Couldn't extract any components from the SBOM. Supported: CycloneDX (components[] with purl) "
                "and SPDX (packages[] with purl/versionInfo)."
            ],
        )

    osv = OSVClient()
    kev = KEVCatalog()
    epss = EPSSClient()

    findings: list[Finding] = []
    try:
        osv_results = await osv.query_batch(components)
        all_cves: list[str] = []
        for vulns in osv_results.values():
            for v in vulns:
                all_cves.extend(extract_cves(v))
        kev_set = await kev.cves()
        epss_scores = await epss.scores(sorted(set(all_cves)))

        for pkg in components:
            key = f"{pkg.ecosystem.value}|{pkg.name}|{pkg.version}"
            for v in osv_results.get(key, []):
                cves = extract_cves(v)
                in_kev = any(c in kev_set for c in cves)
                top_epss = max((epss_scores.get(c, 0.0) for c in cves), default=0.0)
                cvss = None
                for sev in v.get("severity", []) or []:
                    if str(sev.get("type", "")).startswith("CVSS"):
                        try:
                            if "/" not in str(sev["score"]):
                                cvss = float(sev["score"])
                                break
                        except (TypeError, ValueError):
                            pass
                score = combined_risk_score(cvss, top_epss, in_kev)
                findings.append(
                    Finding(
                        id=f"sureguard.runtime.{v.get('id', 'unknown')}",
                        title=f"{v.get('id')} in deployed {pkg.name}@{pkg.version}",
                        severity=severity_from_score(score),
                        category="vulnerability",
                        message=(v.get("summary") or v.get("details") or "")[:600],
                        location=Location(path=pkg.purl or f"{pkg.name}@{pkg.version}"),
                        cve_ids=cves,
                        risk_score=score,
                        in_kev=in_kev,
                        epss=top_epss or None,
                    )
                )
    finally:
        await osv.aclose()
        await kev.aclose()
        await epss.aclose()

    elapsed = int((time.monotonic() - started) * 1000)
    findings.sort(key=lambda f: -(f.risk_score or 0))
    warnings: list[str] = []
    kev_hits = [f for f in findings if f.in_kev]
    if kev_hits:
        warnings.append(
            f"{len(kev_hits)} CVE(s) in this deployment are in CISA KEV (actively exploited). "
            "Treat as P0 regardless of other context."
        )
    return ScanResult(
        tool="check_runtime_risk",
        findings=findings,
        scanned_files=len(components),
        elapsed_ms=elapsed,
        warnings=warnings,
    )
