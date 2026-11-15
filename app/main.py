"""LINKBREAK — FastAPI application.

Routes
------
GET  /                  the web UI (static/index.html)
GET  /api/health        {"status": "ok"}
POST /api/resolve       resolve one URL
POST /api/batch-resolve resolve up to 20 URLs
GET  /api/history       latest 50 stored resolutions
DELETE /api/history     clear stored history

Safety notes
------------
* Per-IP rate limit: 30 resolve calls per minute (in-memory).
* URL max 2048 chars; batch max 20 URLs (enforced by Pydantic).
* Error responses never include server internals or credentials.
* Resolution history is stored locally in SQLite only.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import db as history_db
from .resolver import resolve_url

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
DB_PATH = os.environ.get("LINKBREAK_DB", str(BASE_DIR / "data" / "linkbreak.db"))

RATE_LIMIT_PER_MINUTE = 30
RATE_WINDOW_SECONDS = 60
MAX_BATCH_URLS = 20
BATCH_CONCURRENCY = 5

_hits: dict[str, deque] = defaultdict(deque)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    history_db.init_db(DB_PATH)
    yield


app = FastAPI(
    title="LINKBREAK",
    description="Universal Shortlink Resolver — discover where a short link really goes.",
    version="1.0.0",
    lifespan=lifespan,
)


def _rate_limit(request: Request) -> None:
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    queue = _hits[ip]
    while queue and queue[0] <= now - RATE_WINDOW_SECONDS:
        queue.popleft()
    if len(queue) >= RATE_LIMIT_PER_MINUTE:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded: 30 resolve requests per minute.",
        )
    queue.append(now)


class Hop(BaseModel):
    url: str
    status: int
    method: str = "HEAD"
    note: str | None = None
    elapsed_ms: int = 0


class ResolveRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)


class BatchRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=MAX_BATCH_URLS)


class ResolveResponse(BaseModel):
    original_url: str
    detected_provider: str
    final_url: str | None = None
    redirect_chain: list[Hop] = []
    http_status: int | None = None
    resolution_status: str
    error_message: str | None = None
    elapsed_ms: int
    canonical_url: str | None = None
    canonical_source: str | None = None
    original_domain: str | None = None
    final_domain: str | None = None
    domain_changed: bool = False
    brand_mismatch: bool = False
    safety_notes: list[str] = []


class HistoryEntry(BaseModel):
    id: int
    original_url: str
    detected_provider: str | None = None
    final_url: str | None = None
    http_status: int | None = None
    resolution_status: str | None = None
    error_message: str | None = None
    elapsed_ms: int | None = None
    created_at: float


def _validate_absolute_url(raw: str) -> str:
    """Reject strings that are not absolute URLs at all (HTTP 400).

    Well-formed URLs with a disallowed scheme or a blocked host are
    handled by the resolver instead, which reports them as ``Blocked``.
    """
    url = (raw or "").strip()
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise HTTPException(
            status_code=400,
            detail="url must be an absolute URL, e.g. https://bit.ly/abc123",
        )
    return url


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/resolve", response_model=ResolveResponse)
async def resolve_one(body: ResolveRequest, request: Request) -> dict:
    _rate_limit(request)
    url = _validate_absolute_url(body.url)
    result = await resolve_url(url)
    history_db.save_result(DB_PATH, result)
    return result


@app.post("/api/batch-resolve", response_model=list[ResolveResponse])
async def resolve_batch(body: BatchRequest, request: Request) -> list[dict]:
    _rate_limit(request)
    urls = [_validate_absolute_url(u) for u in body.urls]
    semaphore = asyncio.Semaphore(BATCH_CONCURRENCY)

    async def _one(url: str) -> dict:
        async with semaphore:
            return await resolve_url(url)

    results = await asyncio.gather(*(_one(u) for u in urls))
    for result in results:
        history_db.save_result(DB_PATH, result)
    return results


@app.get("/api/history", response_model=list[HistoryEntry])
def get_history() -> list[dict]:
    return history_db.list_history(DB_PATH, limit=50)


@app.delete("/api/history")
def delete_history() -> dict:
    deleted = history_db.clear_history(DB_PATH)
    return {"deleted": deleted}


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
