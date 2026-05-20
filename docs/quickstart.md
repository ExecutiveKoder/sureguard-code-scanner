# Sureguard quickstart

Three ways to plug Sureguard in. Pick whichever matches your pipeline; they all wrap the same MCP server.

---

## 1. As an MCP server for your AI agent (Pattern B — highest leverage)

This is the AI-reviewer integration. Your agent calls Sureguard's tools mid-generation and self-corrects before writing files.

### Claude Code

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

### Cursor

Settings → MCP → Add new MCP server. Paste the contents of [`integrations/cursor/config-sample.json`](../integrations/cursor/config-sample.json).

### Test it

Ask your agent to "write a Python script that fetches data from an API and parses JSON." It should call `verify_package` before suggesting `requests` (and reject anything not in the registry), call `scan_code` on the generated script before writing, and reject `verify=False` if it tried to disable TLS.

---

## 2. As a GitHub Action (Pattern A — deterministic CI gate)

Open a PR, Sureguard scans the diff and the manifest, emits SARIF, posts to GitHub code scanning.

```yaml
# .github/workflows/security.yml
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

`fail-on: high` blocks the PR on HIGH or CRITICAL findings only. Bump to `medium` once your baseline is clean.

---

## 3. As a pre-commit hook (local feedback)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/ExecutiveKoder/sureguard-code-scanner
    rev: v0.1.0
    hooks:
      - id: sureguard-diff
      - id: sureguard-deps
```

```bash
pre-commit install
```

Now every commit scans its own diff and any modified manifest before it lands.

---

## Required external binaries

Sureguard works without these but recall is much better with them installed:

- **semgrep** — needed for `scan_code` / `scan_diff`. `pip install semgrep` or `brew install semgrep`.
- **gitleaks** — recommended for `scan_secrets`. `brew install gitleaks` (we ship a fallback pattern detector if it's missing).

Network access to `api.osv.dev`, `www.cisa.gov`, and `api.first.org` is required for `scan_dependencies` and `check_runtime_risk`. All responses are cached locally (SQLite, default `~/.cache/sureguard/`).

---

## Honest limits

- We catch n-days, not zero-days. "Zero-day" means undisclosed; nothing here or anywhere else can reliably detect those.
- SCA findings are pinned-version-exact. Unpinned manifests get a warning, not a clean report.
- Reachability hints come from Semgrep's basic call-graph analysis. Treat as triage help, not proof.
- Pattern fallback for `scan_secrets` has lower recall than gitleaks. Install it for anything you ship.
