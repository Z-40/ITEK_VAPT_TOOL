#!/usr/bin/env python3
"""
har_pipeline.py
═══════════════
Production-grade HAR Benchmarking Pipeline

Automates HTTP Archive (HAR) file generation and raw HTTP/1.1 request
extraction from a JSON endpoint schema using Playwright's async API with
semaphore-bounded concurrency.

╔══════════════════════════════════════════════════════════════════╗
║  PHASES                                                          ║
║  Phase 0 — Input parsing   (multi-schema JSON → EndpointEntry)  ║
║  Phase 1 — HAR capture     (async Playwright, bounded by sem.)   ║
║  Phase 2 — HAR extraction  (log.entries → HTTP/1.1 text blocks)  ║
╚══════════════════════════════════════════════════════════════════╝

Usage
─────
    python har_pipeline.py [OPTIONS]

    --input       Path to JSON schema file         (default: input_data.json)
    --har-dir     Directory for .har outputs       (default: har_output/)
    --report-dir  Directory for .txt reports       (default: reports/)
    --workers     Max concurrent contexts [sem.]   (default: 3)
    --timeout     Per-page timeout, seconds        (default: 30)
    --browser     chromium | firefox | webkit      (default: chromium)
    --headed      Show browser window (flag)
    --har-content omit | embed                     (default: omit)
    --log-level   DEBUG | INFO | WARNING | ERROR   (default: INFO)

Requirements
────────────
    pip install playwright
    playwright install chromium      # swap for firefox / webkit as needed
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    async_playwright,
    TimeoutError as PlaywrightTimeoutError,
)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 0 ─ Configuration & Logging
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PipelineConfig:
    """
    Central configuration object passed through every pipeline stage.
    All fields have safe defaults; the CLI parser overrides them at startup.
    """
    input_file:      Path  = field(default_factory=lambda: Path("input_data.json"))
    har_output_dir:  Path  = field(default_factory=lambda: Path("har_output"))
    report_dir:      Path  = field(default_factory=lambda: Path("reports"))
    max_workers:     int   = 3          # asyncio.Semaphore ceiling
    page_timeout_ms: int   = 30_000     # 30 seconds in milliseconds
    browser_type:    str   = "chromium" # chromium | firefox | webkit
    headless:        bool  = True
    log_level:       str   = "INFO"
    # "omit"  → skip response bodies (smaller .har, faster)
    # "embed" → record full response bodies (larger but richer for analysis)
    har_content:     str   = "omit"


_LOG_FMT = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s"


def _build_logger(level: str = "INFO") -> logging.Logger:
    """
    Builds (or retrieves) the package-level logger.
    Attaches a stdout StreamHandler and a rotating FileHandler on first call.
    Subsequent calls only update the log level to avoid duplicate handlers.
    """
    numeric = getattr(logging, level.upper(), logging.INFO)
    logger  = logging.getLogger("har_pipeline")
    logger.setLevel(numeric)

    if not logger.handlers:
        formatter = logging.Formatter(_LOG_FMT)

        stream_h = logging.StreamHandler(sys.stdout)
        stream_h.setFormatter(formatter)
        logger.addHandler(stream_h)

        file_h = logging.FileHandler("pipeline.log", encoding="utf-8", mode="a")
        file_h.setFormatter(formatter)
        logger.addHandler(file_h)
    else:
        # Update existing handlers if level changed at runtime
        logger.setLevel(numeric)

    return logger


# Module-level logger — re-assigned in main() after arg parsing
log = _build_logger()


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 ─ Data Models
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class EndpointEntry:
    """
    Represents a single URL target extracted from the input schema.
    Carries optional metadata (label, HTTP method, query params) sourced
    from richer schema shapes such as 'endpoints_with_params'.
    """
    url:    str
    label:  str              = ""
    method: str              = "GET"
    params: dict[str, Any]   = field(default_factory=dict)


@dataclass
class CaptureResult:
    """
    Records the outcome of a single :func:`capture_har` attempt.
    Fields are populated inside the coroutine and read post-gather.
    """
    entry:      EndpointEntry
    har_path:   Path | None  = None
    success:    bool         = False
    error:      str          = ""
    duration_s: float        = 0.0


@dataclass
class HARRequestEntry:
    """
    Structured representation of one HTTP exchange extracted from a HAR
    ``log.entries`` item.  Used as the source-of-truth for report rendering.
    """
    method:        str
    url:           str
    path:          str              # includes query string and fragment
    host:          str
    http_version:  str
    headers:       dict[str, str]   # insertion-ordered
    post_data:     str | None       # None when no request body was recorded
    status_code:   int
    response_mime: str


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 ─ Input Parsing  (Phase 0)
# ═══════════════════════════════════════════════════════════════════════════════

def load_endpoints(config: PipelineConfig) -> list[EndpointEntry]:
    """
    Reads ``config.input_file`` and extracts unique, valid HTTP(S) endpoints.

    Supported schema shapes
    ───────────────────────
    Shape A — top-level list of URL strings::

        ["https://example.com", "https://example.com/about"]

    Shape B — top-level list of objects::

        [{"url": "...", "label": "...", "method": "GET"}]

    Shape C — dict with a ``"pages"`` key::

        {"pages": [{"url": "...", "title": "..."}]}

    Shape D — dict with an ``"endpoints_with_params"`` key (expands params)::

        {"endpoints_with_params": [
            {"url": "https://api.example.com/search",
             "method": "GET",
             "params": [{"q": "foo"}, {"q": "bar"}]}
        ]}

    Shape E — dict with a generic ``"urls"`` list::

        {"urls": ["https://example.com", ...]}

    Any combination of C, D, and E may co-exist inside the same dict.
    All shapes are deduplicated by final URL string before returning.

    Returns
    ───────
    list[EndpointEntry]
        Unique, validated endpoint objects ready for :func:`capture_har`.

    Raises
    ──────
    FileNotFoundError
        If ``config.input_file`` does not exist.
    ValueError
        If the parsed JSON yields zero valid HTTP(S) URLs.
    """
    if not config.input_file.exists():
        raise FileNotFoundError(
            f"Input schema not found: {config.input_file.resolve()}"
        )

    with config.input_file.open(encoding="utf-8") as fh:
        raw: Any = json.load(fh)

    entries: list[EndpointEntry] = []
    seen:    set[str]            = set()

    def push(
        url:    str,
        label:  str             = "",
        method: str             = "GET",
        params: dict | None     = None,
    ) -> None:
        """Deduplicates and validates before appending to the entry list."""
        url = url.strip()
        if not url or url in seen:
            return
        if not url.startswith(("http://", "https://")):
            log.debug("Skipping non-HTTP URL: %s", url)
            return
        seen.add(url)
        entries.append(
            EndpointEntry(
                url    = url,
                label  = label,
                method = method.upper(),
                params = params or {},
            )
        )

    # ── Shape A & B: top-level list ───────────────────────────────────────────
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                push(item)
            elif isinstance(item, dict):
                push(
                    url    = item.get("url", ""),
                    label  = item.get("label", item.get("name", item.get("title", ""))),
                    method = item.get("method", "GET"),
                )
        log.info("Loaded %d endpoint(s) from top-level list.", len(entries))
        return entries

    # ── Shape C, D, E: dict with well-known keys ──────────────────────────────
    if isinstance(raw, dict):

        # Shape C — "pages"
        for page in raw.get("pages", []):
            if isinstance(page, str):
                push(page)
            elif isinstance(page, dict):
                push(
                    url    = page.get("url", ""),
                    label  = page.get("title", page.get("label", "")),
                    method = page.get("method", "GET"),
                )

        # Shape D — "endpoints_with_params" (one entry per param-set)
        for ep in raw.get("endpoints_with_params", []):
            base_url:  str        = ep.get("url", ep.get("base_url", ""))
            method:    str        = ep.get("method", "GET").upper()
            label:     str        = ep.get("label", ep.get("name", ""))
            param_sets: list[dict] = ep.get("params", [{}]) or [{}]

            for param_set in param_sets:
                if method == "GET" and param_set:
                    full_url = f"{base_url}?{urlencode(param_set)}"
                else:
                    # POST/PUT/PATCH — params go in the body; URL stays clean
                    full_url = base_url
                push(url=full_url, label=label, method=method, params=param_set)

        # Shape E — generic "urls" list
        for u in raw.get("urls", []):
            if isinstance(u, str):
                push(u)
            elif isinstance(u, dict):
                push(
                    url    = u.get("url", ""),
                    label  = u.get("label", ""),
                    method = u.get("method", "GET"),
                )

    if not entries:
        raise ValueError(
            "No valid HTTP/HTTPS URLs found in the input file. "
            "Check that the JSON schema matches one of the supported shapes "
            "documented in the module docstring."
        )

    log.info(
        "Loaded %d unique endpoint(s) from '%s'.",
        len(entries), config.input_file,
    )
    return entries


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 ─ HAR Capture  (Phase 1)
# ═══════════════════════════════════════════════════════════════════════════════

async def capture_har(
    entry:     EndpointEntry,
    browser:   Browser,
    config:    PipelineConfig,
    semaphore: asyncio.Semaphore,
) -> CaptureResult:
    """
    Semaphore-guarded coroutine that captures a HAR file for a single URL.

    Isolation model
    ───────────────
    Each URL gets its own :class:`BrowserContext` so cookies, cache, and
    localStorage never bleed between targets.  The context is torn down
    after the navigation regardless of success or failure, which guarantees:

    * The HAR buffer is flushed and the ``.har`` file is written to disk.
    * Memory occupied by the tab is reclaimed before the next task starts.

    Timeout strategy  (two-layer defence)
    ──────────────────────────────────────
    1. ``page.goto(timeout=…)`` — Playwright's own timeout raises
       :class:`PlaywrightTimeoutError` at the protocol level and triggers
       graceful teardown through the normal ``finally`` path.

    2. ``asyncio.wait_for(…, timeout=…)`` — a Python-level hard ceiling
       that fires :class:`asyncio.TimeoutError` even if the Playwright event
       loop itself is wedged (rare but possible with some OS/network combos).
       The outer timeout is set 5 seconds *longer* than the Playwright one so
       that Playwright's own error (which carries useful diagnostics) takes
       precedence in the common case.

    Parameters
    ──────────
    entry     : Target URL + metadata.
    browser   : Shared Playwright browser instance (single process, many ctxs).
    config    : Pipeline configuration.
    semaphore : Bounds concurrent contexts to ``config.max_workers`` slots.

    Returns
    ───────
    CaptureResult
        Populated with success/failure status, error message (if any),
        path to the written .har file, and wall-clock duration.
    """
    async with semaphore:
        slug      = _url_to_slug(entry.url)
        har_path  = config.har_output_dir / f"{slug}.har"
        result    = CaptureResult(entry=entry, har_path=har_path)
        t0        = time.perf_counter()

        context: BrowserContext | None = None
        page:    Page | None           = None

        try:
            log.info("[CAPTURE ▶] %-6s  %s", entry.method, entry.url)

            # ── Open isolated context with HAR recording ───────────────────────
            context = await browser.new_context(
                record_har_path    = str(har_path),
                record_har_content = config.har_content,
                ignore_https_errors= True,
                java_script_enabled= True,
                user_agent         = (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 "
                    "HAR-Pipeline/1.0"
                ),
            )

            page = await context.new_page()

            # ── Navigate with two-layer timeout ──────────────────────────────
            async def _navigate() -> None:
                await page.goto(
                    entry.url,
                    wait_until = "networkidle",
                    timeout    = config.page_timeout_ms,   # layer 1: Playwright
                )

            await asyncio.wait_for(
                _navigate(),
                timeout = config.page_timeout_ms / 1_000 + 5,  # layer 2: Python (+5 s grace)
            )

            result.success = True
            log.info("[CAPTURE ✓] %s  (%.2fs)", slug, time.perf_counter() - t0)

        except asyncio.TimeoutError:
            # Python hard-stop (should rarely fire before Playwright's own)
            result.error = (
                f"asyncio hard-stop after "
                f"{config.page_timeout_ms / 1_000 + 5:.0f}s"
            )
            log.warning("[CAPTURE ⏱] TIMEOUT (asyncio)  %s — %s", slug, result.error)

        except PlaywrightTimeoutError as exc:
            # Playwright graceful abort — includes URL and phase in the message
            result.error = f"Navigation timeout after {config.page_timeout_ms / 1_000:.0f}s"
            log.warning(
                "[CAPTURE ⏱] TIMEOUT (playwright)  %s\n             %s",
                slug, exc,
            )

        except Exception as exc:                           # noqa: BLE001
            result.error = repr(exc)
            log.error("[CAPTURE ✗] %s — %s", slug, exc, exc_info=True)

        finally:
            # ── Guaranteed teardown — order matters ────────────────────────────
            # Closing the page first ensures all in-flight XHR / fetch calls are
            # cancelled cleanly.  Closing the *context* is the critical step that
            # flushes Playwright's internal HAR buffer and writes the .har file.
            for obj, label in ((page, "page"), (context, "context")):
                if obj is not None:
                    try:
                        await obj.close()
                    except Exception as _e:
                        log.debug("Teardown error closing %s: %s", label, _e)

        result.duration_s = time.perf_counter() - t0
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 ─ HAR Parsing & HTTP Reconstruction  (Phase 2)
# ═══════════════════════════════════════════════════════════════════════════════

def parse_har_file(har_path: Path) -> list[HARRequestEntry]:
    """
    Opens *har_path* and iterates ``log.entries`` to produce structured
    :class:`HARRequestEntry` objects — one per captured HTTP exchange.

    HAR format reference
    ─────────────────────
    Each ``log.entries[n]`` is a dict with at minimum::

        {
          "request": {
            "method":      "GET",
            "url":         "https://...",
            "httpVersion": "HTTP/1.1",
            "headers":     [{"name": "...", "value": "..."}],
            "postData":    {"text": "...", "mimeType": "..."}   # optional
          },
          "response": {
            "status":  200,
            "content": {"mimeType": "text/html; charset=utf-8"}
          }
        }

    Resilience
    ──────────
    * Returns ``[]`` for missing, empty, or non-JSON files (logged as warnings).
    * Skips individual entries missing the ``request.url`` field.
    * Duplicate header names: last-write-wins (matches browser behaviour).

    Parameters
    ──────────
    har_path : Path to the .har file written by :func:`capture_har`.

    Returns
    ───────
    list[HARRequestEntry]
        Ordered list matching the ``log.entries`` insertion order.
    """
    if not har_path.exists():
        log.warning("[PARSE ⚠] File not found: %s", har_path)
        return []

    if har_path.stat().st_size == 0:
        log.warning("[PARSE ⚠] Empty HAR file: %s", har_path)
        return []

    try:
        with har_path.open(encoding="utf-8") as fh:
            doc: dict = json.load(fh)
    except json.JSONDecodeError as exc:
        log.error("[PARSE ✗] Malformed HAR JSON in %s: %s", har_path, exc)
        return []

    raw_entries: list[dict] = doc.get("log", {}).get("entries", [])
    results: list[HARRequestEntry] = []

    for idx, raw in enumerate(raw_entries):
        req  = raw.get("request",  {})
        resp = raw.get("response", {})

        url_str = req.get("url", "").strip()
        if not url_str:
            log.debug("[PARSE] Entry #%d missing URL — skipping.", idx)
            continue

        parsed_url   = urlparse(url_str)
        method       = req.get("method", "GET").upper()
        http_version = req.get("httpVersion", "HTTP/1.1")

        # ── Reconstruct full path (path + query + fragment) ───────────────────
        path = parsed_url.path or "/"
        if parsed_url.query:
            path = f"{path}?{parsed_url.query}"
        if parsed_url.fragment:
            path = f"{path}#{parsed_url.fragment}"

        host = parsed_url.netloc or parsed_url.hostname or ""

        # ── Flatten header list → insertion-ordered dict ──────────────────────
        # HAR stores headers as [{"name": "...", "value": "..."}, ...]
        raw_headers: list[dict] = req.get("headers", [])
        headers: dict[str, str] = {
            h["name"]: h["value"]
            for h in raw_headers
            if "name" in h and "value" in h
        }

        # ── Extract request body (postData) ───────────────────────────────────
        post_data: str | None = None
        if "postData" in req:
            pd_block  = req["postData"]
            post_data = pd_block.get("text") or pd_block.get("mimeType") or None

        results.append(
            HARRequestEntry(
                method         = method,
                url            = url_str,
                path           = path,
                host           = host,
                http_version   = http_version,
                headers        = headers,
                post_data      = post_data,
                status_code    = resp.get("status", 0),
                response_mime  = resp.get("content", {}).get("mimeType", ""),
            )
        )

    log.info(
        "[PARSE ✓] %d request(s) extracted from %s",
        len(results), har_path.name,
    )
    return results


def format_http_block(entry: HARRequestEntry, index: int = 1) -> str:
    """
    Reconstructs a :class:`HARRequestEntry` into a human-readable HTTP/1.1
    flat text block, matching the canonical wire format:

    ::

        GET /path?query HTTP/1.1
        Host: example.com
        Accept: text/html
        Accept-Encoding: gzip, deflate, br
        Connection: keep-alive

        (body for POST/PUT/PATCH — omitted when absent)

    Header ordering
    ───────────────
    ``Host`` is always placed immediately after the request line (RFC 7230 §5.4).
    All other headers follow in their original HAR insertion order.
    The ``Host`` header is suppressed from the remainder of the list to prevent
    duplication.

    Parameters
    ──────────
    entry : Structured request entry from :func:`parse_har_file`.
    index : 1-based request number (unused in formatting, present for callers).

    Returns
    ───────
    str
        Multi-line HTTP/1.1 text block, UNIX line endings.
    """
    lines: list[str] = []

    # ── Line 1: Request line ──────────────────────────────────────────────────
    lines.append(f"{entry.method} {entry.path} {entry.http_version}")

    # ── Line 2: Host (always explicit, per RFC 7230) ──────────────────────────
    lines.append(f"Host: {entry.host}")

    # ── Lines 3+: Remaining headers (skip 'host' — already emitted above) ─────
    _skip = frozenset({"host"})
    for name, value in entry.headers.items():
        if name.lower() not in _skip:
            lines.append(f"{name}: {value}")

    # ── CRLF blank-line separator ─────────────────────────────────────────────
    lines.append("")

    # ── Optional payload body ─────────────────────────────────────────────────
    if entry.post_data:
        lines.append(entry.post_data.strip())
        lines.append("")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 ─ Report Writer
# ═══════════════════════════════════════════════════════════════════════════════

def write_per_url_report(
    result:      CaptureResult,
    har_entries: list[HARRequestEntry],
    output_dir:  Path,
) -> Path:
    """
    Writes a human-readable plain-text report for a single URL capture to
    ``output_dir/<slug>.txt``.

    Report layout
    ─────────────
    * Header block: target URL, label, HAR path, timestamp, duration, status.
    * For each ``HARRequestEntry``: a separator line + formatted HTTP block.
    * On capture failure: a single "CAPTURE FAILED" notice in lieu of blocks.

    Parameters
    ──────────
    result      : Outcome of the :func:`capture_har` call.
    har_entries : Parsed entries from :func:`parse_har_file` (may be empty).
    output_dir  : Directory to write the report file into.

    Returns
    ───────
    Path
        Absolute path of the written report file.
    """
    slug        = _url_to_slug(result.entry.url)
    report_path = output_dir / f"{slug}.txt"
    now_iso     = datetime.now(tz=timezone.utc).isoformat()

    with report_path.open("w", encoding="utf-8") as fh:
        border = "═" * 80

        fh.write(f"{border}\n")
        fh.write(f"  HAR REQUEST REPORT\n")
        fh.write(f"  Target   : {result.entry.url}\n")
        fh.write(f"  Label    : {result.entry.label or '—'}\n")
        fh.write(f"  HAR File : {result.har_path}\n")
        fh.write(f"  Captured : {now_iso}\n")
        fh.write(f"  Duration : {result.duration_s:.3f}s\n")
        status_str = "SUCCESS ✓" if result.success else f"FAILED ✗  ({result.error})"
        fh.write(f"  Status   : {status_str}\n")
        fh.write(f"{border}\n\n")

        if not result.success or not har_entries:
            fh.write("(No request entries — capture failed or returned no data.)\n")
            return report_path

        for i, har_req in enumerate(har_entries, start=1):
            direction = "↑" if har_req.method in {"POST", "PUT", "PATCH"} else "↓"
            sep = (
                f"─── Request #{i:04d}  "
                f"[{direction} {har_req.status_code}  {har_req.response_mime}]  "
                f"{'─' * 40}"
            )
            fh.write(f"{sep}\n")
            fh.write(format_http_block(har_req, index=i))
            fh.write("\n\n")

    log.info(
        "[REPORT ✓] %s  (%d requests logged)",
        report_path.name, len(har_entries),
    )
    return report_path


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 ─ Pipeline Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

async def run_pipeline(config: PipelineConfig) -> dict[str, Any]:
    """
    Top-level async orchestrator that coordinates all three pipeline phases.

    Execution model
    ───────────────
    Phase 0 — Input parsing (synchronous):
        ``load_endpoints`` reads and validates the JSON schema, returning a
        flat list of :class:`EndpointEntry` objects.

    Phase 1 — Concurrent HAR capture:
        A single Playwright browser process is launched.  All capture tasks
        are submitted to :func:`asyncio.gather` simultaneously; an
        :class:`asyncio.Semaphore` ensures no more than ``config.max_workers``
        contexts are open at any moment.  After all tasks settle the browser
        is closed.

    Phase 2 — Serial post-processing:
        HAR files are parsed and per-URL reports are written sequentially.
        This is intentionally serial: disk I/O here is fast (< 1 ms per file),
        and serial execution avoids lock contention on the filesystem without
        adding complexity.

    The final pipeline summary manifest is written to
    ``config.report_dir/pipeline_summary.json`` and returned as a dict.

    Parameters
    ──────────
    config : Fully-populated :class:`PipelineConfig` instance.

    Returns
    ───────
    dict
        Pipeline summary (counts, timing, per-URL results) as a Python dict.
        Also serialised to ``pipeline_summary.json`` on disk.
    """
    # ── Prepare output directories ─────────────────────────────────────────────
    config.har_output_dir.mkdir(parents=True, exist_ok=True)
    config.report_dir.mkdir(parents=True, exist_ok=True)

    # ── Phase 0: Load endpoints ────────────────────────────────────────────────
    endpoints = load_endpoints(config)
    semaphore = asyncio.Semaphore(config.max_workers)

    summary: dict[str, Any] = {
        "pipeline_version": "1.0.0",
        "start_time":       datetime.now(tz=timezone.utc).isoformat(),
        "config": {
            "input_file":  str(config.input_file),
            "browser":     config.browser_type,
            "max_workers": config.max_workers,
            "timeout_s":   config.page_timeout_ms / 1_000,
            "har_content": config.har_content,
        },
        "total":            len(endpoints),
        "success":          0,
        "failed":           0,
        "skipped":          0,
        "total_requests":   0,
        "results":          [],
    }

    # ── Phase 1: Concurrent HAR capture ───────────────────────────────────────
    async with async_playwright() as pw:
        launcher = getattr(pw, config.browser_type)
        browser  = await launcher.launch(
            headless = config.headless,
            args     = [
                "--disable-dev-shm-usage",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-background-networking",  # suppress telemetry noise
            ],
        )

        log.info(
            "Browser: %s (headless=%s) | Workers: %d | Endpoints: %d",
            config.browser_type, config.headless,
            config.max_workers, len(endpoints),
        )

        # Dispatch every coroutine at once; semaphore manages concurrency
        capture_coros = [
            capture_har(ep, browser, config, semaphore)
            for ep in endpoints
        ]
        results: list[CaptureResult] = await asyncio.gather(*capture_coros)

        await browser.close()
        log.info("Browser closed — post-processing %d result(s) …", len(results))

    # ── Phase 2: Serial post-processing ───────────────────────────────────────
    for result in results:
        record: dict[str, Any] = {
            "url":           result.entry.url,
            "label":         result.entry.label,
            "success":       result.success,
            "duration_s":    round(result.duration_s, 3),
            "error":         result.error,
            "har_path":      str(result.har_path),
            "report_path":   None,
            "request_count": 0,
        }

        if not result.success:
            # Write a failure stub report so the reports/ dir is complete
            write_per_url_report(result, [], config.report_dir)
            summary["failed"] += 1
            summary["results"].append(record)
            continue

        if not result.har_path or not result.har_path.exists():
            log.warning(
                "[PIPELINE ⚠] HAR file absent for %s — skipping parse.",
                result.entry.url,
            )
            summary["skipped"] += 1
            summary["results"].append(record)
            continue

        har_entries        = parse_har_file(result.har_path)
        report_path        = write_per_url_report(result, har_entries, config.report_dir)

        record["report_path"]   = str(report_path)
        record["request_count"] = len(har_entries)
        summary["success"]     += 1
        summary["results"].append(record)

    # ── Write manifest ─────────────────────────────────────────────────────────
    summary["end_time"]       = datetime.now(tz=timezone.utc).isoformat()
    summary["total_requests"] = sum(r.get("request_count", 0) for r in summary["results"])

    manifest_path = config.report_dir / "pipeline_summary.json"
    with manifest_path.open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    _print_summary_banner(summary)
    return summary


def _print_summary_banner(summary: dict[str, Any]) -> None:
    """Emits a compact ASCII summary to the log at INFO level."""
    bar = "═" * 62
    log.info(
        "\n%s\n"
        "  PIPELINE COMPLETE\n"
        "  Total endpoints  : %d\n"
        "  ✓ Success        : %d\n"
        "  ✗ Failed         : %d\n"
        "  ⚠ Skipped        : %d\n"
        "  Total requests   : %d\n"
        "%s",
        bar,
        summary["total"],
        summary["success"],
        summary["failed"],
        summary["skipped"],
        summary.get("total_requests", 0),
        bar,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 ─ Utilities
# ═══════════════════════════════════════════════════════════════════════════════

def _url_to_slug(url: str, max_label_len: int = 60) -> str:
    """
    Converts a URL into a deterministic, collision-resistant, filesystem-safe
    slug suitable for use as a filename stem.

    Algorithm
    ─────────
    1. Extract ``netloc + path`` from the parsed URL.
    2. Replace ``/`` with ``__`` and ``.`` with ``-``.
    3. Strip all characters that are not alphanumeric, ``-``, or ``_``.
    4. Truncate to *max_label_len* characters.
    5. Append the first 8 hex characters of the URL's MD5 digest to
       guarantee uniqueness even when two URLs share the same label prefix.

    Example::

        "https://api.example.com/v1/users?id=42"
        →  "api-example-com__v1__users_a3f2c9d1"

    The MD5 is used for hashing only (not cryptographic security); the
    ``usedforsecurity=False`` flag silences FIPS-mode warnings.

    Parameters
    ──────────
    url          : Fully-qualified URL string.
    max_label_len: Maximum characters from the human-readable label prefix.

    Returns
    ───────
    str
        Filename-safe slug (no extension).
    """
    parsed  = urlparse(url)
    raw     = f"{parsed.netloc}{parsed.path}".strip("/")
    label   = raw.replace("/", "__").replace(".", "-")
    safe    = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)
    digest  = hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()[:8]
    slug    = safe[:max_label_len] or "unknown"
    return f"{slug}_{digest}"


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8 ─ CLI Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog             = "har_pipeline",
        description      = (
            "HAR Benchmarking Pipeline — captures HTTP Archive files from a "
            "JSON endpoint schema and reconstructs raw HTTP/1.1 request blocks."
        ),
        formatter_class  = argparse.ArgumentDefaultsHelpFormatter,
        epilog           = (
            "Supported input schema shapes:\n"
            "  A) [\"https://...\", ...]                        (URL list)\n"
            "  B) [{\"url\": \"...\", \"method\": \"GET\"}, ...]    (object list)\n"
            "  C) {\"pages\": [{\"url\": \"...\", \"title\": \"...\"}]}\n"
            "  D) {\"endpoints_with_params\": [{\"url\": ..., \"params\": [...]}]}\n"
            "  E) {\"urls\": [\"...\", ...]}\n"
            "  Mix of C/D/E is supported."
        ),
    )
    parser.add_argument(
        "--input",
        default  = "input_data.json",
        metavar  = "FILE",
        help     = "Path to the JSON endpoint schema file.",
    )
    parser.add_argument(
        "--har-dir",
        default  = "har_output",
        metavar  = "DIR",
        help     = "Output directory for generated .har files.",
    )
    parser.add_argument(
        "--report-dir",
        default  = "reports",
        metavar  = "DIR",
        help     = "Output directory for plain-text HTTP request reports.",
    )
    parser.add_argument(
        "--workers",
        type     = int,
        default  = 3,
        metavar  = "N",
        help     = "Maximum concurrent browser contexts (semaphore ceiling).",
    )
    parser.add_argument(
        "--timeout",
        type     = int,
        default  = 30,
        metavar  = "SEC",
        help     = "Per-page navigation timeout in seconds.",
    )
    parser.add_argument(
        "--browser",
        choices  = ["chromium", "firefox", "webkit"],
        default  = "chromium",
        help     = "Playwright browser engine to use.",
    )
    parser.add_argument(
        "--headed",
        action   = "store_true",
        help     = "Launch browser in headed (visible) mode for debugging.",
    )
    parser.add_argument(
        "--har-content",
        choices  = ["omit", "embed"],
        default  = "omit",
        dest     = "har_content",
        help     = (
            "'omit' skips response bodies (smaller .har files, faster). "
            "'embed' records full bodies (larger but richer for analysis)."
        ),
    )
    parser.add_argument(
        "--log-level",
        choices  = ["DEBUG", "INFO", "WARNING", "ERROR"],
        default  = "INFO",
        dest     = "log_level",
        help     = "Logging verbosity.",
    )
    return parser


def main() -> None:
    """
    CLI entry point.

    Parses arguments, builds a :class:`PipelineConfig`, then delegates to
    :func:`run_pipeline` via :func:`asyncio.run`.

    Exit codes
    ──────────
    0   — All captures succeeded (or partial failures were recorded gracefully).
    1   — Input file not found.
    2   — Input file contains no valid URLs.
    130 — Interrupted by SIGINT / Ctrl-C.
    """
    args   = _build_arg_parser().parse_args()

    # Re-initialise the module-level logger at the requested verbosity
    global log
    log = _build_logger(args.log_level)

    config = PipelineConfig(
        input_file      = Path(args.input),
        har_output_dir  = Path(args.har_dir),
        report_dir      = Path(args.report_dir),
        max_workers     = args.workers,
        page_timeout_ms = args.timeout * 1_000,
        browser_type    = args.browser,
        headless        = not args.headed,
        log_level       = args.log_level,
        har_content     = args.har_content,
    )

    try:
        asyncio.run(run_pipeline(config))
    except FileNotFoundError as exc:
        log.critical("Startup failure — %s", exc)
        sys.exit(1)
    except ValueError as exc:
        log.critical("Input schema error — %s", exc)
        sys.exit(2)
    except KeyboardInterrupt:
        log.warning(
            "Interrupted by user (SIGINT). "
            "Partial results may exist in the output directories."
        )
        sys.exit(130)


if __name__ == "__main__":
    main()