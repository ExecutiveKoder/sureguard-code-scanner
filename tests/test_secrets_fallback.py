from sureguard_mcp.engines.gitleaks import fallback_scan_text


def test_aws_access_key_detected():
    findings = fallback_scan_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\nother = "noise"\n',
        path="src/config.py",
    )
    ids = [f.id for f in findings]
    assert "sureguard.secret.aws-access-key" in ids


def test_openai_key_detected():
    findings = fallback_scan_text('client = OpenAI(api_key="sk-abc123def456ghi789jkl012")')
    assert any(f.id == "sureguard.secret.openai-key" for f in findings)


def test_anthropic_key_detected():
    findings = fallback_scan_text(
        'client = Anthropic(api_key="sk-ant-api03-AAAAAAAAAAAAAAAAAAAAA")'
    )
    assert any(f.id == "sureguard.secret.anthropic-key" for f in findings)


def test_high_entropy_literal_caught():
    findings = fallback_scan_text(
        'token = "fJ3kLm9PqRsTuVwXyZ12345aBcDeFgHiJkLmNoPqRs"\n'
    )
    assert any(f.id == "sureguard.secret.high-entropy-literal" for f in findings)


def test_no_false_positive_on_short_string():
    findings = fallback_scan_text('label = "hello world"')
    assert findings == []
