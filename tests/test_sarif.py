from sureguard_mcp.models import Finding, Location, Severity
from sureguard_mcp.sarif import findings_to_sarif


def test_sarif_shape_and_rule_dedup():
    findings = [
        Finding(
            id="sureguard.python.md5-for-security",
            title="MD5 used for security",
            severity=Severity.HIGH,
            category="insecure-pattern",
            message="Replace MD5.",
            location=Location(path="src/a.py", line=10),
        ),
        Finding(
            id="sureguard.python.md5-for-security",
            title="MD5 used for security",
            severity=Severity.HIGH,
            category="insecure-pattern",
            message="Another instance.",
            location=Location(path="src/b.py", line=22),
        ),
    ]
    out = findings_to_sarif(findings)
    assert out["version"] == "2.1.0"
    run = out["runs"][0]
    # Same rule, two results.
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2
    assert run["results"][0]["level"] == "error"
