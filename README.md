# Sureguard Code Scanner

**AI-aware secure code review as an MCP server.**

Vibe-coded code has a different failure profile than human-written code. Sureguard catches the things AI agents actually get wrong:

- Hallucinated / slopsquatted packages (the LLM-specific failure mode)
- Insecure patterns the model emits (MD5, `verify=False`, JWT `alg=none`, SQL string concat, `NODE_TLS_REJECT_UNAUTHORIZED=0`, …)
- Secrets the model parroted back into code
- Recently disclosed CVEs in declared dependencies, cross-referenced against CISA KEV and EPSS
- Runtime risk against deployed SBOMs

Sureguard is **not** a zero-day detector — by definition, those are unknown. It's a layered control for AI-generated code that catches the things upstream SAST/SCA misses and packages them behind one MCP interface so any agent can call them.

---

## How to use this

Sureguard plugs in at four points along the AI-coding lifecycle. Pick the ones that match your pipeline — most teams want at least two:

| When | What plugs in | What it catches |
| --- | --- | --- |
| **At generation time** (inside the agent) | Claude Code / Cursor / Continue calling Sureguard via MCP | Hallucinated packages, insecure patterns, secrets — *before* code is written to disk |
| **On pre-commit** (local) | `pre-commit` hook | The same checks against the staged diff, as a last guard before commit |
| **On PR open** (CI) | GitHub Action | Full SCA + SAST + secrets scan, gates the PR, posts to GitHub code scanning |
| **Post-deploy** (monitoring) | Scheduled job calling `check_runtime_risk` against your deployed SBOM | New CVE disclosures against shipped versions, prioritized by KEV+EPSS |

The highest-leverage one is the first row: getting Sureguard into the **agent's** tool loop, so the model never even generates the bad pattern. Reactive scanning is fine; never-emitted is better.

### Install

```bash
pip install sureguard-code-scanner
# Or as a one-off (recommended for MCP configs):
uvx sureguard-code-scanner --help
```

Optional but recommended external binaries:

```bash
pip install semgrep      # needed for scan_code / scan_diff
brew install gitleaks    # better recall on scan_secrets; built-in fallback works too
```

### 1. Plug into your AI coding agent (the high-leverage path)

#### Claude Code

```jsonc
// ~/.config/claude-code/mcp.json
{
  "mcpServers": {
    "sureguard": {
      "command": "uvx",
      "args": ["sureguard-code-scanner"]
    }
  }
}
```

Restart Claude Code. Verify with `/mcp` — you should see `sureguard` listed with 7+ tools.

Now ask the agent for something dependency-heavy. Example prompt:

> "Write a Python script that fetches data from an API and parses JSON. Use a popular HTTP library."

Claude will call `verify_package("requests", "pypi")` before suggesting the import, and `scan_code(...)` on the generated script before writing it. If it tries to disable TLS, Sureguard's `scan_code` flags it and the agent self-corrects.

#### Cursor

Settings → MCP → Add new MCP server. Paste:

```json
{
  "mcpServers": {
    "sureguard": {
      "command": "uvx",
      "args": ["sureguard-code-scanner"]
    }
  }
}
```

Same tools, same behaviour. The chat agent has Sureguard available throughout the session.

#### Any other MCP client

Sureguard speaks plain MCP over stdio. Anything that registers an MCP server will work — Continue, Zed, custom agents using `@modelcontextprotocol/sdk`, internal review bots.

### 2. Pre-commit hook (local last-guard)

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/ExecutiveKoder/sureguard-code-scanner
    rev: v0.1.0
    hooks:
      - id: sureguard-diff       # SAST + secrets over the staged diff
      - id: sureguard-deps       # SCA + hallucination check on manifest changes
```

```bash
pre-commit install
```

Every commit now runs Sureguard against its own diff. The hook fails the commit on HIGH or CRITICAL findings.

### 3. GitHub Action (PR gate)

`.github/workflows/security.yml`:

```yaml
name: Security review
on: [pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  sureguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - uses: ExecutiveKoder/sureguard-code-scanner/integrations/github-action@main
        with:
          manifest: requirements.txt
          fail-on: high
```

Findings post to GitHub code scanning (Security tab → Code scanning). `fail-on: high` blocks the PR on HIGH/CRITICAL only. Bump to `medium` once your baseline is clean.

### 4. Post-deploy monitor (audit-grade)

Run a daily job that passes your deployed SBOM (CycloneDX or SPDX) to `check_runtime_risk`. New CVE disclosures against shipped versions surface here — this is the control auditors actually care about because it proves you keep watching after release.

```python
import asyncio, json
from sureguard_code_scanner.tools.check_runtime_risk import check_runtime_risk

sbom = json.loads(open("deploy/sbom.cdx.json").read())
result = asyncio.run(check_runtime_risk(sbom))

for f in result.findings:
    if f.in_kev:
        print(f"P0  {f.title}  (CVE in CISA KEV — actively exploited)")
```

---

## The 7 tools, what they do, when to call them

| Tool | Call when |
| --- | --- |
| `verify_package(name, ecosystem, version?)` | Before *any* package install / import an agent suggested. Returns `is_hallucinated`, `is_typosquat_suspect`, and candidates. |
| `scan_code(content, language)` | After generating code, before writing to disk. Runs Semgrep with Sureguard's AI-aware rule pack. |
| `scan_dependencies(manifest_filename, content)` | On any manifest change. Full SCA against OSV + KEV + EPSS, plus per-package hallucination check. |
| `scan_diff(diff)` | PR review or pre-commit. Scans only the *added* lines from a unified diff. |
| `scan_secrets(content, filename?)` | Anytime you generate config, env, or fixture data. Gitleaks if installed, pattern+entropy fallback otherwise. |
| `check_runtime_risk(sbom)` | Post-deploy, on a schedule. Re-scans deployed components against new disclosures. |
| `policy_for(language, framework?)` | At the *start* of a generation session. Returns the rule pack so the agent can avoid emitting the bad patterns in the first place. |

All return either a `ScanResult` (with `findings: list[Finding]`) or a typed verification object. Findings have a `risk_score` blended from CVSS+EPSS+KEV — gate on that, not raw CVSS.

## A 60-second demo

Save as `bad.py`:

```python
import hashlib, requests, jwt
requests.get("https://example.com", verify=False)
hashlib.md5(password.encode()).hexdigest()
jwt.decode(token, key, algorithms=["none"])
```

```bash
python -c "
import asyncio
from sureguard_code_scanner.tools.scan_code import scan_code
r = asyncio.run(scan_code(open('bad.py').read(), language='python'))
for f in r.findings:
    print(f'{f.severity.value.upper():8} {f.id} — {f.title}')
"
```

Expected output:

```
ERROR    sureguard.python.requests-verify-false — TLS verification disabled
ERROR    sureguard.python.md5-for-security — MD5 used for security
ERROR    sureguard.python.jwt-alg-none — JWT signature verification disabled
```

## Architecture

```
agent / CI / pre-commit hook
            │
            ▼
   ┌────────────────────┐
   │     Sureguard      │
   │    MCP server      │
   └─────────┬──────────┘
             │
   ┌─────────┼─────────────────────────────┐
   ▼         ▼                             ▼
Semgrep   OSV.dev + KEV + EPSS         Gitleaks
(SAST)    (SCA + risk score)           (secrets)
   │         │                             │
   └─────────┴──────────┬──────────────────┘
                        ▼
              SARIF / structured JSON
```

## What Sureguard does *not* do

- It does not detect unknown vulnerabilities — that is by definition impossible. We catch *n-days*, not *zero-days*.
- It does not replace your existing enterprise SAST/SCA at scale. Use it as the AI-generation-aware layer on top.
- It does not guarantee reachability for SCA findings. Treat reachability hints as triage help, not proof.
- It does not phone home. All scanning is local; only the OSV / KEV / EPSS feeds are fetched (and cached).

## Development

```bash
git clone https://github.com/ExecutiveKoder/sureguard-code-scanner
cd sureguard-code-scanner
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
PYTHONPATH=server pytest
```

## Status

`v0.1.0` — alpha. The tool surface is stable. Rule packs and integrations will grow.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
