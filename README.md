# Sureguard

**AI-aware secure code review as an MCP server.**

Catches the things AI agents actually get wrong when they write code:

- Hallucinated / slopsquatted packages (the LLM-specific failure mode)
- Insecure patterns the model emits (MD5, `verify=False`, JWT `alg=none`, SQL string concat, `NODE_TLS_REJECT_UNAUTHORIZED=0`, …)
- Secrets the model parroted back into code
- Recently disclosed CVEs in declared dependencies, cross-referenced against CISA KEV and EPSS
- Runtime risk against deployed SBOMs

Sureguard is **not** a zero-day detector — by definition, those are unknown. It's a layered control for AI-generated code that catches the things upstream SAST/SCA misses and packages them behind one MCP interface so any agent can call them.

## Two integration patterns, one server

**Pattern A — CI calls the MCP server.** PR opens, CI spawns Sureguard in stdio mode, calls its tools through a thin client, emits SARIF, posts back via GitHub code scanning. Deterministic gate, no AI in the loop.

**Pattern B — an AI reviewer connects to Sureguard.** Claude Code, Cursor, Continue, or your internal reviewer agent has Sureguard registered as an MCP server. As it reviews a PR or generates code, it calls `verify_package`, `scan_diff`, `scan_dependencies` and reasons over structured findings instead of guessing.

Same server. Same tool surface. Different transport.

## Tools exposed

| Tool | Purpose |
| --- | --- |
| `scan_code` | SAST pass over raw code (Semgrep + bundled AI-aware rule pack) |
| `scan_dependencies` | SCA across `requirements.txt`, `package.json`, `pyproject.toml`, `Gemfile.lock`, `go.sum` via OSV.dev |
| `verify_package` | Single-package existence + reputation check — the slopsquatting catch |
| `scan_diff` | Delta scan for a unified diff (PR / commit context) |
| `scan_secrets` | Entropy + pattern detection via Gitleaks |
| `check_runtime_risk` | Cross-reference an SBOM against CISA KEV |
| `policy_for` | Return the guardrail rule pack for a language/framework so upstream agents can self-correct before generating |

Output is SARIF-compatible for any tool, plus a richer JSON form for agent consumption.

## Quick start

### As an MCP server for Claude Code

```jsonc
// ~/.config/claude-code/mcp.json
{
  "mcpServers": {
    "sureguard": {
      "command": "uvx",
      "args": ["sureguard-mcp"]
    }
  }
}
```

Your next code generation will catch hallucinated packages before they hit your editor.

### As a GitHub Action

```yaml
- uses: sureguard/sureguard-action@v0
  with:
    fail-on: high
```

Posts SARIF to GitHub code scanning and gates the PR.

### As a pre-commit hook

```yaml
repos:
  - repo: https://github.com/sureguard/sureguard
    rev: v0.1.0
    hooks:
      - id: sureguard-diff
```

See `docs/quickstart.md` for the full per-integration walkthrough.

## Architecture

```
agent / CI / pre-commit hook
            │
            ▼
   ┌────────────────────┐
   │   Sureguard MCP    │
   │      server        │
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

## What Sureguard does **not** do

- It does not detect unknown vulnerabilities — that is by definition impossible. We catch *n-days*, not *zero-days*.
- It does not replace your existing SAST/SCA at scale. Use it as the AI-generation gate.
- It does not guarantee reachability for SCA findings. We surface a heuristic reachability hint where Semgrep call-graph data is available; treat it as triage help, not proof.
- It does not phone home. All scanning is local; only the OSV / KEV / EPSS feeds are fetched (and cached).

## Status

`v0.1.0` — alpha. The tool surface is stable. Rule packs and integrations will grow.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
