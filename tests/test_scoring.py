from sureguard_mcp.models import Severity
from sureguard_mcp.scoring import combined_risk_score, severity_from_score


def test_kev_alone_floors_score():
    # No CVSS, no EPSS, but KEV-listed: still scored as urgent.
    s = combined_risk_score(cvss=None, epss=None, in_kev=True)
    assert s >= 5.0
    assert severity_from_score(s) in (Severity.HIGH, Severity.MEDIUM)


def test_kev_bumps_into_critical_when_exploit_signal_is_strong():
    # CVSS 9.0 + EPSS 0.8 + KEV should clear the critical threshold (>= 9.0).
    s = combined_risk_score(cvss=9.0, epss=0.8, in_kev=True)
    assert severity_from_score(s) == Severity.CRITICAL


def test_kev_alone_does_not_overshoot_to_critical():
    # KEV adds urgency but should not silently turn every CVSS=7.0 into a critical.
    s = combined_risk_score(cvss=7.0, epss=0.2, in_kev=True)
    assert severity_from_score(s) == Severity.HIGH


def test_low_epss_low_cvss_is_low():
    s = combined_risk_score(cvss=3.0, epss=0.01, in_kev=False)
    assert severity_from_score(s) in (Severity.LOW, Severity.INFO)


def test_score_capped_at_ten():
    assert combined_risk_score(cvss=10.0, epss=1.0, in_kev=True) == 10.0
