"""Sureguard hosted UI — FastAPI app.

Two routes:
  GET  /         the URL-paste form
  POST /scan     clone + scan + render report

The form submission is synchronous (the scan typically runs in 5-30s on small
public repos with a warm cache). For longer-running jobs you'd want a queue;
keeping it sync for v0 dramatically simplifies the deploy and the demo.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .scanner import ScanError, scan_github_url

BASE_DIR = Path(__file__).resolve().parent

# We build the Jinja environment explicitly and disable the template cache
# (cache_size=0) because Jinja2's cache trips a TypeError on Python 3.14 where
# its cache-key tuple ends up containing an unhashable dict. Once Jinja2 ships
# a 3.14-compatible fix we can drop the manual env.
_jinja_env = Environment(
    loader=FileSystemLoader(str(BASE_DIR / "templates")),
    autoescape=select_autoescape(["html"]),
    cache_size=0,
)
templates = Jinja2Templates(env=_jinja_env)

app = FastAPI(title="Sureguard")

# Static dir is optional — if it doesn't exist (no custom CSS yet) we just skip.
_static_dir = BASE_DIR / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


# A small in-process semaphore so we don't run too many scans concurrently on a
# small box. Tune via the concurrency env var when deploying.
_CONCURRENCY = 2
_scan_semaphore = asyncio.Semaphore(_CONCURRENCY)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html")


@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, url: str = Form(...)) -> HTMLResponse:
    async with _scan_semaphore:
        try:
            report = await scan_github_url(url)
        except ScanError as e:
            return templates.TemplateResponse(
                request,
                "index.html",
                {"error": str(e), "submitted_url": url},
                status_code=400,
            )
    return templates.TemplateResponse(request, "report.html", {"report": report})


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True}
