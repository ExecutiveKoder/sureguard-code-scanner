"""Risk score combining CVSS, EPSS, and KEV presence.

CVSS alone is too noisy to gate on — half the internet sits at 7.5+ and your
pipeline learns to bypass. EPSS adds exploit probability. KEV adds "actively
exploited in the wild" which is the only signal that should fail a build hard.

The score we return is on 0..10 so it lines up with developer intuition for
CVSS, but the inputs are weighted very differently underneath.
"""

from __future__ import annotations

from .models import Severity


def combined_risk_score(
    cvss: float | None,
    epss: float | None,
    in_kev: bool,
) -> float:
    """Return a 0..10 risk score blending CVSS, EPSS, and KEV presence.

    Weights:
      - CVSS base       : 50%
      - EPSS (0..1)     : 30%, scaled ×10
      - KEV presence    : flat +2.5 bump, capped at 10

    KEV alone with no CVSS still scores ~5.0 — actively exploited beats unknown severity.
    """
    cvss_component = (cvss or 0.0) * 0.5
    epss_component = (epss or 0.0) * 10 * 0.3
    kev_component = 2.5 if in_kev else 0.0
    base = cvss_component + epss_component
    if in_kev and base < 5.0:
        base = 5.0
    return round(min(base + kev_component, 10.0), 2)


def severity_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def severity_from_cvss(cvss: float | None) -> Severity:
    """Plain CVSS → severity, when we don't have EPSS/KEV context."""
    if cvss is None:
        return Severity.INFO
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW
