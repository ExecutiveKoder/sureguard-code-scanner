"""scan_dependencies tool — SCA across a manifest."""

from __future__ import annotations

import time

from ..manifests import parse_manifest_by_name
from ..models import Finding, Location, ScanResult, Severity
from ..scoring import combined_risk_score, severity_from_score
from ..sources.epss import EPSSClient
from ..sources.kev import KEVCatalog
from ..sources.osv import OSVClient, extract_cves
from ..sources.registries import RegistryClient


def _max_cvss(vuln: dict) -> float | None:
    best: float | None = None
    for sev in vuln.get("severity", []) or []:
        if str(sev.get("type", "")).startswith("CVSS"):
            try:
                if "/" in str(sev["score"]):
                    continue  # vector form, skip — we don't ship a CVSS calculator
                v = float(sev["score"])
                if best is None or v > best:
                    best = v
            except (ValueError, KeyError, TypeError):
                continue
    return best


async def scan_dependencies(
    manifest_filename: str,
    content: str,
    verify_existence: bool = True,
) -> ScanResult:
    started = time.monotonic()
    warnings: list[str] = []
    try:
        packages = parse_manifest_by_name(manifest_filename, content)
    except ValueError as e:
        return ScanResult(tool="scan_dependencies", warnings=[str(e)])

    findings: list[Finding] = []
    osv = OSVClient()
    kev = KEVCatalog()
    epss = EPSSClient()
    reg = RegistryClient()

    try:
        # 1) Existence check — catches hallucinations even before we hit OSV.
        if verify_existence:
            for pkg in packages:
                v = await reg.verify(pkg)
                if v.is_hallucinated:
                    findings.append(
                        Finding(
                            id="sureguard.supply-chain.hallucinated-package",
                            title=f"Package '{pkg.name}' does not exist in {pkg.ecosystem.value}",
                            severity=Severity.CRITICAL,
                            category="hallucinated-package",
                            message=(
                                f"'{pkg.name}' was declared as a dependency but no such package "
                                f"exists in the {pkg.ecosystem.value} registry. This is the classic "
                                "slopsquat target — an attacker can register the name and inherit "
                                "everything that runs `install`."
                            ),
                            location=Location(path=manifest_filename),
                            fix=(
                                "Verify the intended package name. AI agents frequently invent "
                                "plausible-looking names. If you find the correct one, replace it; "
                                "if not, remove the dependency."
                            ),
                        )
                    )
                elif v.is_typosquat_suspect and v.typosquat_candidates:
                    findings.append(
                        Finding(
                            id="sureguard.supply-chain.typosquat-suspect",
                            title=f"'{pkg.name}' is one character away from a popular package",
                            severity=Severity.HIGH,
                            category="hallucinated-package",
                            message=(
                                f"'{pkg.name}' is a 1-edit distance from "
                                f"{', '.join(v.typosquat_candidates)}. Confirm this is intentional."
                            ),
                            location=Location(path=manifest_filename),
                        )
                    )

        # 2) OSV vuln lookup — only for packages that exist.
        resolvable = [p for p in packages if p.version]
        if len(resolvable) < len(packages):
            warnings.append(
                f"{len(packages) - len(resolvable)} package(s) have no pinned version; SCA findings "
                "may be incomplete. Lockfiles produce the most accurate results."
            )
        osv_results = await osv.query_batch(resolvable)

        # 3) Hydrate severity with EPSS + KEV.
        all_cves: list[str] = []
        for vulns in osv_results.values():
            for v in vulns:
                all_cves.extend(extract_cves(v))
        epss_scores = await epss.scores(sorted(set(all_cves)))
        kev_set = await kev.cves()

        for pkg in resolvable:
            key = f"{pkg.ecosystem.value}|{pkg.name}|{pkg.version}"
            for v in osv_results.get(key, []):
                cves = extract_cves(v)
                cvss = _max_cvss(v)
                in_kev = any(c in kev_set for c in cves)
                top_epss = max((epss_scores.get(c, 0.0) for c in cves), default=0.0)
                score = combined_risk_score(cvss, top_epss, in_kev)
                findings.append(
                    Finding(
                        id=f"sureguard.cve.{v.get('id', 'unknown')}",
                        title=f"{v.get('id', 'Advisory')} in {pkg.name}@{pkg.version}",
                        severity=severity_from_score(score),
                        category="vulnerability",
                        message=(v.get("summary") or v.get("details") or "")[:600],
                        location=Location(path=manifest_filename),
                        cve_ids=cves,
                        risk_score=score,
                        in_kev=in_kev,
                        epss=top_epss or None,
                        references=[r.get("url") for r in v.get("references", []) if r.get("url")][
                            :5
                        ],
                        fix=_format_fix(v, pkg),
                    )
                )
    finally:
        await osv.aclose()
        await kev.aclose()
        await epss.aclose()
        await reg.aclose()

    elapsed = int((time.monotonic() - started) * 1000)
    return ScanResult(
        tool="scan_dependencies",
        findings=sorted(findings, key=lambda f: -(f.risk_score or 0)),
        scanned_files=1,
        elapsed_ms=elapsed,
        warnings=warnings,
    )


def _format_fix(vuln: dict, pkg) -> str | None:
    fixed_versions: list[str] = []
    for aff in vuln.get("affected", []) or []:
        for r in aff.get("ranges", []) or []:
            for ev in r.get("events", []) or []:
                if "fixed" in ev:
                    fixed_versions.append(ev["fixed"])
    if fixed_versions:
        return f"Upgrade {pkg.name} to >= {min(fixed_versions)}."
    return None
