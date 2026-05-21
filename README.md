# Sureguard Code Scanner

**AI-aware secure code review for AI-generated code.**

Vibe-coded code has a different failure profile than human-written code. Sureguard catches the things AI agents actually get wrong:

- Hallucinated / slopsquatted packages (the LLM-specific failure mode)
- Insecure patterns the model emits (MD5, `verify=False`, JWT `alg=none`, SQL string concat, `NODE_TLS_REJECT_UNAUTHORIZED=0`, …)
- Secrets the model parroted back into code
- Recently disclosed CVEs in declared dependencies, cross-referenced against CISA KEV and EPSS
- Runtime risk against deployed SBOMs

Sureguard is **not** a zero-day detector — by definition, those are unknown. It's a layered control for AI-generated code that catches the things upstream SAST/SCA misses and packages them behind one MCP interface so any agent can call them.

---

## Install

```bash
git clone https://github.com/ExecutiveKoder/sureguard-code-scanner
cd sureguard-code-scanner
python -m venv .venv && source .venv/bin/activate
pip install -e .
pip install semgrep      # optional, recommended — enables SAST
```

> **You do NOT need to install gitleaks.** Sureguard fetches a verified gitleaks binary on first run and caches it at `~/.cache/sureguard/bin/`. To opt out, set `SUREGUARD_NO_AUTO_INSTALL=1`.

---

## Quick start

### Scan anything

```bash
# A local directory
sureguard scan ./my-project
sureguard scan /Users/me/Code/myapp

# A GitHub URL (clones it shallowly to a temp dir, scans, cleans up)
sureguard scan https://github.com/owner/repo

# Any other git URL — GitLab, Bitbucket, SSH — also works
sureguard scan git@github.com:org/private-repo.git
```

**For the cleanest output**, add `--actions-only`:

```bash
sureguard scan ./my-project --actions-only
```

### What you'll see

```
Sureguard scan  /path/to/your/project
────────────────────────────────────────────────────────────────────────
  Sureguard Score: 86 / 100  (B)
  1 high   17 low   121 info

  By category:
     138  Dependency CVEs
       1  Insecure code patterns

  Next actions  (fix these in order)
  ──────────────────────────────────────────────────────────────────────
   1. CODE     [high] Fix insecure pattern in src/cache.py:96
       Replace hashlib.md5(...) with hashlib.sha256(...)
   2. UPGRADE  [low]  Upgrade next → 15.5.16
       clears 46 CVE(s)
   3. UPGRADE  [low]  Upgrade axios → 1.15.2
       clears 35 CVE(s)
   …

  Copy-paste install commands
    pip install -U "aiohttp>=3.13.4" "requests>=2.33.0" …
    npm install next@^15.5.16 axios@^1.15.2 …
```

---

## Understanding your score

| Score | Grade | Means |
| --- | --- | --- |
| 90-100 | **A** | Clean. Anything left is informational. |
| 80-89  | **B** | Healthy. A small backlog of patches. |
| 70-79  | **C** | Real items to fix, none on fire. |
| 60-69  | **D** | Backlog has been ignored too long. |
| <60    | **F** | Several HIGH findings or a CRITICAL. |

The score starts at 100 and deducts based on severity:

| Severity | Deducts | When you'd see it |
| --- | --- | --- |
| CRITICAL | -15 each | Hallucinated package, KEV-listed CVE |
| HIGH     | -3 each  | MD5 in your code, JWT alg=none, hardcoded API key |
| MEDIUM   | -1 each  | Weak PRNG for secrets, deprecated TLS |
| LOW      | -0.3 each| Known CVE in a dep, fixable by upgrade |
| INFO     | -0.05 each | Disclosed CVE without a strong exploit signal |

### How to improve a low score

Look at the **Next actions** section, not the raw findings list. One package upgrade can clear dozens of findings.

The single highest-leverage move is almost always either:
1. Fix the one or two HIGHs in your own code, or
2. Run the two copy-paste install commands at the bottom — they almost always clear the bulk of dep CVEs.

Then re-run `sureguard scan ./` and watch the score move.

---

## When secrets are "everywhere"

Gitleaks is aggressive on file types where example/placeholder tokens are common. By default, Sureguard **filters secret findings in low-signal locations**:

| Filtered by default | Why | Override flag |
| --- | --- | --- |
| `.env`, `.env.local`, `.env.bak`, … | Local-only config; their presence isn't a leak | `--include-env-secrets` |
| `.md`, `.mdx`, `.rst`, `.adoc`, `.txt` | Docs almost always contain example tokens | `--include-doc-secrets` |
| `test_*.py`, `*_test.go`, `tests/`, `fixtures/`, `__tests__/` | Test fixtures use throwaway tokens | `--include-test-secrets` |
| `.claude/`, `.vscode/`, `.idea/`, `.cursor/` | IDE config, never deployed | `--include-ide-secrets` |

For audit / leak-hunt mode, use:

```bash
sureguard scan ./ --strict-secrets
```

That includes everything regardless of file type.

If `sureguard` flags a real-looking key inside a `.md` or test file and you're not sure if it's a placeholder, **treat it as compromised and rotate** — the cost of rotation is low; the cost of guessing wrong is high.

---

## All the flags

```bash
sureguard scan <path-or-url>           # the only required argument
  --fail-on {info,low,medium,high,critical}   # exit nonzero on this or worse (default: high)
  --no-sast                            # skip Semgrep
  --no-secrets                         # skip gitleaks entirely
  --no-deps                            # skip manifest / SCA scan
  --json                               # raw findings JSON (for piping into other tools)
  --sarif PATH                         # also write SARIF for GitHub code scanning
  --top N                              # show top N findings in detail (default: 20)
  --all                                # show every finding (overrides --top)
  --actions-only                       # just the action plan, no detail list
  --include-env-secrets                # include .env* in secret scan
  --include-doc-secrets                # include .md / .rst / .txt
  --include-test-secrets               # include test fixtures
  --include-ide-secrets                # include .claude/, .vscode/, etc.
  --strict-secrets                     # include ALL of the above
  -v / -vv                             # status lines / per-HTTP-request logs
  -q                                   # suppress status lines
```

---

## Plug it in elsewhere

Sureguard isn't just a CLI. The same scanner backs four integration points:

| When | What plugs in | Path |
| --- | --- | --- |
| **At generation time** (inside the agent) | Claude Code / Cursor / Continue calling Sureguard via MCP | [`integrations/claude-code/config-sample.json`](integrations/claude-code/config-sample.json), [`integrations/cursor/config-sample.json`](integrations/cursor/config-sample.json) |
| **One-off demo** (paste a URL) | The hosted web UI | [`web/`](web/) |
| **On pre-commit** (local) | `pre-commit` hook | [`integrations/pre-commit/.pre-commit-hooks.yaml`](integrations/pre-commit/.pre-commit-hooks.yaml) |
| **On PR open** (CI) | GitHub Action | [`integrations/github-action/action.yml`](integrations/github-action/action.yml) |

See [`docs/quickstart.md`](docs/quickstart.md) for full per-integration walkthroughs.

---

## Plug into your AI coding agent

This is the highest-leverage integration — the agent calls Sureguard's tools mid-generation and self-corrects before writing files.

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

Restart Claude Code. Verify with `/mcp` — `sureguard` should appear with 7+ tools. Now ask the agent for dependency-heavy code and watch it call `verify_package` before suggesting any import.

### Cursor

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

### Any other MCP client

Sureguard speaks plain MCP over stdio. Continue, Zed, custom agents using `@modelcontextprotocol/sdk` all work.

---

## A 60-second demo

Save as `bad.py`:

```python
import hashlib, requests, jwt
requests.get("https://example.com", verify=False)
hashlib.md5(password.encode()).hexdigest()
jwt.decode(token, key, algorithms=["none"])
```

```bash
sureguard scan .
```

Expected: 3 HIGH findings (TLS disabled, MD5 for security, JWT alg=none).

---

## Architecture

```
agent / CI / pre-commit hook / web UI
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
                Action plan + SARIF
```

---

## What Sureguard does **not** do

- It does not detect unknown vulnerabilities — that is by definition impossible. We catch *n-days*, not *zero-days*.
- It does not replace your existing enterprise SAST/SCA at scale. Use it as the AI-generation-aware layer on top.
- It does not guarantee reachability for SCA findings. Treat reachability hints as triage help, not proof.
- It does not phone home. All scanning is local; only OSV / KEV / EPSS / package-registry feeds are fetched (and cached at `~/.cache/sureguard/`).

---

## Development

```bash
git clone https://github.com/ExecutiveKoder/sureguard-code-scanner
cd sureguard-code-scanner
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,web]"
PYTHONPATH=server pytest
```

---

## Status

`v0.1.0` — alpha. Tool surface is stable. Rule packs and integrations grow.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
