# Sureguard hosted UI

Paste a public GitHub URL, get a security report. Same scanner the CLI uses, rendered as HTML.

## Run locally

```bash
# From the repo root
python -m venv .venv && source .venv/bin/activate
pip install -e ".[web]"
pip install semgrep                       # optional, recommended for SAST
brew install gitleaks 2>/dev/null || true # optional, recommended for secrets

uvicorn web.main:app --reload
```

Open <http://127.0.0.1:8000/>.

## What runs

- `GET /` — the paste-a-URL form.
- `POST /scan` — clones the URL shallow (`--depth=1 --no-tags`), runs Semgrep + Gitleaks + manifest SCA, renders the action plan.
- `GET /healthz` — liveness probe.

The same `build_action_plan` and `project_score` functions the CLI uses run here. There's no separate scoring logic to drift.

## Safety caps

These live in [`scanner.py`](scanner.py) and are tuned for a 1-vCPU container:

| Cap | Value | Why |
| --- | --- | --- |
| Repo size | 200 MB cloned | Refuse before scanning; cheap DoS prevention. |
| Wall-clock | 120 s per scan | A runaway Semgrep or stuck OSV request can't tie up the worker. |
| Concurrency | 2 scans | Semaphore in `main.py`. Bump if you give the box more CPU. |
| URL host | `github.com` only | Regex-enforced; no other hosts, no embedded tokens. |
| `GIT_TERMINAL_PROMPT` | `0` | `git clone` never prompts for creds. |

The cloned repo lives in a temp dir and is **always** deleted in the `finally` block.

## Deploy

### Fly.io (simplest)

```bash
fly launch --dockerfile web/Dockerfile --no-deploy
fly deploy
```

### Render / Railway / GHCR + any container host

The Dockerfile is the only build artifact you need. It's multi-stage, ~250 MB, and runs as a non-root user. The image preinstalls `git`, `semgrep`, and `gitleaks` so a cold start is fast.

```bash
docker build -t sureguard-web -f web/Dockerfile .
docker run --rm -p 8000:8000 sureguard-web
```

## Architecture

```
   browser
      │ POST /scan { url }
      ▼
┌─────────────────────────┐
│  FastAPI route handler  │  semaphore (max 2 concurrent)
│                         │
│  1. validate URL        │  → only github.com, no tokens
│  2. shallow clone       │  → /tmp/sureguard-…
│  3. size + time caps    │
│  4. run pipeline:       │
│     • Semgrep (SAST)    │  → bundled AI-aware rule pack
│     • Gitleaks (secrets)│  → fallback if not installed
│     • scan_dependencies │  → OSV + KEV + EPSS
│  5. build_action_plan   │  → group findings → upgrades
│  6. render report.html  │
│  7. delete clone        │
└─────────────────────────┘
```

## What's intentionally not here yet

- **Authentication for private repos.** Use the GitHub Action or local CLI for that — see the root README. Asking users to paste a token into a stranger's website is a non-starter.
- **Background jobs / queue.** Scans are sync. Anything that goes near the 120s cap should run via CI, not here.
- **Persistent storage.** No DB. Every scan starts cold (modulo the on-disk OSV/KEV/EPSS cache the scanner module manages locally).
- **Rate limiting per IP.** The semaphore protects the *box*; if you need anti-abuse for a public deploy, put Cloudflare in front.
