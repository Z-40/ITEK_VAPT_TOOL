#!/usr/bin/env python3
"""
har_pipeline.py
═══════════════
Production-grade HAR Benchmarking Pipeline — v2.0

Automates HTTP Archive (HAR) file generation and raw HTTP/1.1 request
extraction from a JSON endpoint schema using Playwright's async API with
semaphore-bounded concurrency.

Changes from v1.0
─────────────────
• [REQ 1] Dynamic request capture — page.on("request"), page.on("response"),
  and page.on("requestfailed") listeners are registered before navigation so
  that every XHR, fetch, or other client-side network exchange is captured
  alongside the initial page load, and any in-flight requests still pending
  after networkidle are drained before the context is closed.

• [REQ 2] wpath.json parameter flattening — _flatten_params() recursively
  extracts the first scalar value from each parameter array.  _encode_url()
  always strips any pre-existing query string from the base URL before
  re-encoding, preventing HTML-entity artefacts (e.g. "&amp;") from leaking
  through when the scraper has already embedded params in the URL string.

• [REQ 3] Single-request output files — split_har_into_individual_files()
  decomposes each composite HAR into one <slug>_rNNNN.har per entry, and
  write_single_request_report() produces one <slug>_rNNNN.txt per entry.
  A page that fires N requests therefore yields exactly N .har files and
  N .txt reports.

Usage
─────
    python endpoint_requests.py --input wpath.json

Requirements
────────────
    pip install playwright
    playwright install chromium
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
from urllib.parse import urlencode, urlparse, urlunparse

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
    input_file:      Path  = field(default_factory=lambda: Path("input_data.json"))
    har_output_dir:  Path  = field(default_factory=lambda: Path("har_output"))
    report_dir:      Path  = field(default_factory=lambda: Path("reports"))
    max_workers:     int   = 3
    page_timeout_ms: int   = 30_000
    browser_type:    str   = "chromium"
    headless:        bool  = True
    log_level:       str   = "INFO"
    har_content:     str   = "omit"

_LOG_FMT = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s"


def _build_logger(level: str = "INFO") -> logging.Logger:
    numeric = getattr(logging, level.upper(), logging.INFO)
    logger  = logging.getLogger("har_pipeline")
    logger.setLevel(numeric)

    if not logger.handlers:
        formatter = logging.Formatter(_LOG_FMT)
        stream_h  = logging.StreamHandler(sys.stdout)
        stream_h.setFormatter(formatter)
        logger.addHandler(stream_h)

        file_h = logging.FileHandler("pipeline.log", encoding="utf-8", mode="a")
        file_h.setFormatter(formatter)
        logger.addHandler(file_h)
    else:
        logger.setLevel(numeric)
    return logger


log = _build_logger()

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 ─ Data Models
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class EndpointEntry:
    url:    str
    label:  str            = ""
    method: str            = "GET"
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class CaptureResult:
    entry:              EndpointEntry
    har_path:           Path | None   = None        # Composite HAR (all requests, written by Playwright)
    individual_hars:    list[Path]    = field(default_factory=list)   # Per-request split HAR files
    success:            bool          = False
    error:              str           = ""
    duration_s:         float         = 0.0
    captured_exchanges: list[dict]    = field(default_factory=list)   # Raw data from listeners


@dataclass
class HARRequestEntry:
    method:        str
    url:           str
    path:          str
    host:          str
    http_version:  str
    headers:       dict[str, str]
    post_data:     str | None
    status_code:   int
    response_mime: str

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 ─ Input Parsing  (Phase 0 — wpath.json Compatible)
# ═══════════════════════════════════════════════════════════════════════════════

# ── [REQ 2] Parameter flattening helpers ──────────────────────────────────────

def _flatten_param_value(v: Any) -> str:
    """
    Recursively extract the first scalar value from a wpath.json parameter
    array or nested dict.

    Examples
    ────────
    ["126"]                       → "126"
    ["Cabin:ital,wght@0,400..700"] → "Cabin:ital,wght@0,400..700"
    {"nested": ["val"]}           → "val"
    "plain"                       → "plain"
    ""                            → ""
    """
    if isinstance(v, list):
        return str(v[0]) if v else ""
    if isinstance(v, dict):
        first = next(iter(v.values()), "")
        return _flatten_param_value(first)
    return str(v) if v is not None else ""


def _flatten_params(raw_params: dict) -> dict[str, str]:
    """
    Convert a wpath.json 'parameters' block — where every value is an array —
    into a plain {str: str} dict by calling _flatten_param_value on each entry.
    """
    return {k: _flatten_param_value(v) for k, v in raw_params.items()}


def _encode_url(base_url: str, method: str, param_set: dict[str, str]) -> str:
    """
    Build a correctly percent-encoded URL.

    Always strips any pre-existing query string from *base_url* before
    re-encoding from *param_set*.  This prevents two classes of bug present
    in the v1.0 code:

    1. When the base URL already contained '?' but did NOT end with '?' or '&',
       the old branch silently returned the raw base URL without appending the
       decoded params at all.

    2. When the crawler has already embedded params as HTML entities
       (e.g. 'index.aspx?idp=126&amp;foo=bar'), stripping and re-encoding
       from the structured params dict produces a clean, valid URL.
    """
    if method == "GET" and param_set:
        parsed   = urlparse(base_url)
        clean    = urlunparse(parsed._replace(query="", fragment=""))
        return f"{clean}?{urlencode(param_set)}"
    return base_url


# ─────────────────────────────────────────────────────────────────────────────

def load_endpoints(config: PipelineConfig) -> list[EndpointEntry]:
    if not config.input_file.exists():
        raise FileNotFoundError(f"Input schema not found: {config.input_file.resolve()}")

    with config.input_file.open(encoding="utf-8") as fh:
        raw: Any = json.load(fh)

    entries: list[EndpointEntry] = []
    seen:    set[str]            = set()

    def push(url: str, label: str = "", method: str = "GET", params: dict | None = None) -> None:
        url = url.strip()
        if not url or url in seen:
            return
        if not url.startswith(("http://", "https://")):
            return
        seen.add(url)
        entries.append(EndpointEntry(url=url, label=label, method=method.upper(), params=params or {}))

    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                push(item)
            elif isinstance(item, dict):
                push(url=item.get("url", ""), label=item.get("label", ""), method=item.get("method", "GET"))
        return entries

    if isinstance(raw, dict):
        # Flatten the wpath.json 'results' array; fall back to treating root as the
        # single target if 'results' is absent.
        targets = raw.get("results", [raw]) if "results" in raw else [raw]

        for target in targets:
            if not isinstance(target, dict):
                continue

            # ── Plain page URLs ──────────────────────────────────────────────
            for page in target.get("pages", []):
                if isinstance(page, str):
                    push(page)
                elif isinstance(page, dict):
                    push(url=page.get("url", ""), label=page.get("title", ""), method=page.get("method", "GET"))

            # ── Parameterised endpoints ──────────────────────────────────────
            for ep in target.get("endpoints_with_params", []):
                base_url: str = ep.get("url", ep.get("base_url", ""))
                method:   str = ep.get("method", "GET").upper()
                label:    str = ep.get("label", "")

                if "parameters" in ep and isinstance(ep["parameters"], dict):
                    # [REQ 2] wpath.json style — flatten array values to scalars
                    param_set  = _flatten_params(ep["parameters"])
                    param_sets = [param_set]
                else:
                    param_sets = ep.get("params", [{}]) or [{}]

                for param_set in param_sets:
                    # [REQ 2] Always re-encode via _encode_url to avoid the
                    # "&amp;" / missing-params bugs from v1.0.
                    full_url = _encode_url(base_url, method, param_set)
                    push(url=full_url, label=label, method=method, params=param_set)

            # ── Bare URL lists ───────────────────────────────────────────────
            for u in target.get("urls", []):
                if isinstance(u, str):
                    push(u)
                elif isinstance(u, dict):
                    push(url=u.get("url", ""), label=u.get("label", ""), method=u.get("method", "GET"))

    if not entries:
        raise ValueError("No valid HTTP/HTTPS URLs found in the input file.")

    log.info("Loaded %d unique endpoint(s) from '%s'.", len(entries), config.input_file)
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
    async with semaphore:
        slug     = _url_to_slug(entry.url)
        har_path = config.har_output_dir / f"{slug}.har"
        result   = CaptureResult(entry=entry, har_path=har_path)
        t0       = time.perf_counter()

        context: BrowserContext | None = None
        page:    Page | None           = None

        try:
            log.info("[CAPTURE ▶] %-6s  %s", entry.method, entry.url)

            context = await browser.new_context(
                record_har_path     = str(har_path),
                record_har_content  = config.har_content,
                ignore_https_errors = True,
                java_script_enabled = True,
                user_agent = (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36 HAR-Pipeline/2.0"
                ),
            )

            page = await context.new_page()

            # ── [REQ 1] Register request / response listeners ─────────────────
            #
            # These three handlers are installed BEFORE page.goto() so that the
            # very first request (the navigation itself) is captured.  Because
            # they are sync callbacks (no await inside), asyncio never yields
            # between _on_request and _on_response for the same request, making
            # the in_flight dict safe from race conditions in a single-threaded
            # event loop.
            #
            # The in_flight dict holds a reference to the raw request metadata
            # keyed by id(request).  Storing that dict entry also keeps a '_req'
            # back-reference to the Playwright Request object so CPython cannot
            # reuse its memory address while a response is still outstanding.
            #
            # Together the three hooks cover every network exchange a page can
            # produce: initial navigation, background XHR/fetch calls, dynamically
            # injected script/style loads, and pre-flight OPTIONS requests.
            # ─────────────────────────────────────────────────────────────────

            exchanges: list[dict]      = []  # Completed request/response pairs
            in_flight: dict[int, dict] = {}  # id(request) → metadata while pending

            def _on_request(request: Any) -> None:
                key  = id(request)
                meta: dict[str, Any] = {
                    "_req":          request,           # hold ref; prevents ID reuse
                    "method":        request.method,
                    "url":           request.url,
                    "resource_type": request.resource_type,
                    "headers":       dict(request.headers),
                    "post_data":     request.post_data,
                    "ts_start":      time.perf_counter(),
                    # Response fields are filled in by _on_response / _on_request_failed
                    "status":        0,
                    "response_headers": {},
                    "mime_type":     "",
                    "duration_ms":   0.0,
                    "failed":        False,
                }
                in_flight[key] = meta
                log.debug(
                    "[REQ  ▶] %-6s  %s  (%s)",
                    meta["method"], meta["url"], meta["resource_type"],
                )

            def _on_response(response: Any) -> None:
                key  = id(response.request)
                meta = in_flight.pop(key, None)
                if meta is None:
                    # Response arrived for a request whose _on_request we missed
                    # (can happen for requests already in-flight when the listener
                    # was attached).  Build a minimal record from what we have.
                    req  = response.request
                    meta = {
                        "method":        req.method,
                        "url":           req.url,
                        "resource_type": req.resource_type,
                        "headers":       dict(req.headers),
                        "post_data":     req.post_data,
                        "ts_start":      time.perf_counter(),
                        "failed":        False,
                    }
                meta.pop("_req", None)          # release back-reference
                meta["status"]           = response.status
                meta["response_headers"] = dict(response.headers)
                meta["mime_type"]        = response.headers.get("content-type", "")
                meta["duration_ms"]      = (time.perf_counter() - meta["ts_start"]) * 1_000
                exchanges.append(meta)
                log.debug("[RESP ✓] %d  %s", response.status, meta["url"])

            def _on_request_failed(request: Any) -> None:
                key  = id(request)
                meta = in_flight.pop(key, None)
                if meta is None:
                    return
                meta.pop("_req", None)
                meta["failed"]      = True
                meta["status"]      = 0
                meta["duration_ms"] = (time.perf_counter() - meta["ts_start"]) * 1_000
                exchanges.append(meta)
                log.debug("[REQ  ✗] %s", request.url)

            page.on("request",       _on_request)
            page.on("response",      _on_response)
            page.on("requestfailed", _on_request_failed)
            # ─────────────────────────────────────────────────────────────────

            async def _navigate() -> None:
                await page.goto(
                    entry.url,
                    wait_until = "networkidle",
                    timeout    = config.page_timeout_ms,
                )

            await asyncio.wait_for(
                _navigate(),
                timeout = config.page_timeout_ms / 1_000 + 5,
            )

            # Drain requests that fired after networkidle but before context close.
            # (E.g. analytics beacons, lazy-loaded assets, long-polling XHR.)
            if in_flight:
                log.debug(
                    "[DRAIN] %d in-flight request(s) pending — waiting 1 s.",
                    len(in_flight),
                )
                await asyncio.sleep(1.0)
                # Anything still pending after the drain window is treated as
                # failed so we never silently lose a request record.
                for meta in in_flight.values():
                    meta.pop("_req", None)
                    meta["failed"]      = True
                    meta["status"]      = 0
                    meta["duration_ms"] = (time.perf_counter() - meta["ts_start"]) * 1_000
                    exchanges.append(meta)
                in_flight.clear()

            result.success            = True
            result.captured_exchanges = exchanges
            log.info(
                "[CAPTURE ✓] %s  exchanges=%d  (%.2fs)",
                slug, len(exchanges), time.perf_counter() - t0,
            )

        except asyncio.TimeoutError:
            result.error = f"asyncio hard-stop after {config.page_timeout_ms / 1_000 + 5:.0f}s"
            log.warning("[CAPTURE ⏱] TIMEOUT (asyncio)  %s — %s", slug, result.error)
        except PlaywrightTimeoutError:
            result.error = f"Navigation timeout after {config.page_timeout_ms / 1_000:.0f}s"
            log.warning("[CAPTURE ⏱] TIMEOUT (playwright)  %s", slug)
        except Exception as exc:
            result.error = repr(exc)
            log.error("[CAPTURE ✗] %s — %s", slug, exc)
        finally:
            # Closing context last is intentional: Playwright flushes the
            # record_har_path file when the context (not the page) is closed.
            for obj in (page, context):
                if obj is not None:
                    try:
                        await obj.close()
                    except Exception:
                        pass

        result.duration_s = time.perf_counter() - t0
        return result

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 ─ HAR Parsing, Splitting & HTTP Reconstruction  (Phase 2)
# ═══════════════════════════════════════════════════════════════════════════════

def parse_har_file(har_path: Path) -> list[HARRequestEntry]:
    """Parse a HAR file and return one HARRequestEntry per log entry."""
    if not har_path.exists() or har_path.stat().st_size == 0:
        return []

    try:
        with har_path.open(encoding="utf-8") as fh:
            doc: dict = json.load(fh)
    except json.JSONDecodeError:
        return []

    raw_entries: list[dict] = doc.get("log", {}).get("entries", [])
    results: list[HARRequestEntry] = []

    for raw in raw_entries:
        req     = raw.get("request",  {})
        resp    = raw.get("response", {})
        url_str = req.get("url", "").strip()
        if not url_str:
            continue

        parsed_url   = urlparse(url_str)
        method       = req.get("method", "GET").upper()
        http_version = req.get("httpVersion", "HTTP/1.1")

        path = parsed_url.path or "/"
        if parsed_url.query:    path = f"{path}?{parsed_url.query}"
        if parsed_url.fragment: path = f"{path}#{parsed_url.fragment}"

        host = parsed_url.netloc or parsed_url.hostname or ""

        raw_headers: list[dict] = req.get("headers", [])
        headers: dict[str, str] = {
            h["name"]: h["value"]
            for h in raw_headers
            if "name" in h and "value" in h
        }

        post_data: str | None = None
        if "postData" in req:
            pd_block  = req["postData"]
            post_data = pd_block.get("text") or pd_block.get("mimeType") or None

        results.append(HARRequestEntry(
            method        = method,
            url           = url_str,
            path          = path,
            host          = host,
            http_version  = http_version,
            headers       = headers,
            post_data     = post_data,
            status_code   = resp.get("status", 0),
            response_mime = resp.get("content", {}).get("mimeType", ""),
        ))
    return results


# ── [REQ 3] HAR splitting ─────────────────────────────────────────────────────

def split_har_into_individual_files(
    har_path:       Path,
    base_slug:      str,
    har_output_dir: Path,
) -> list[Path]:
    """
    Decompose a composite HAR (N log entries) into N individual HAR files,
    each containing exactly one entry.

    Output filenames follow the pattern:
        <har_output_dir>/<base_slug>_r<NNNN>.har

    Returns the list of written paths in entry order.  An empty list is
    returned (and a warning logged) if the HAR cannot be parsed.
    """
    if not har_path.exists() or har_path.stat().st_size == 0:
        return []

    try:
        with har_path.open(encoding="utf-8") as fh:
            doc: dict = json.load(fh)
    except json.JSONDecodeError:
        log.warning("[SPLIT] Cannot parse HAR at %s — file may be incomplete.", har_path)
        return []

    raw_entries: list[dict] = doc.get("log", {}).get("entries", [])
    # Preserve all HAR metadata fields (creator, browser, pages …) except
    # 'entries', which we replace with a single element per output file.
    log_meta: dict = {k: v for k, v in doc.get("log", {}).items() if k != "entries"}

    individual_paths: list[Path] = []
    for i, entry in enumerate(raw_entries, start=1):
        single_har = {"log": {**log_meta, "entries": [entry]}}
        entry_path = har_output_dir / f"{base_slug}_r{i:04d}.har"
        with entry_path.open("w", encoding="utf-8") as fh:
            json.dump(single_har, fh, indent=2)
        individual_paths.append(entry_path)
        log.debug("[SPLIT] Wrote %s", entry_path.name)

    log.info(
        "[SPLIT] %d → %d individual HAR file(s)  (slug: %s)",
        len(raw_entries), len(individual_paths), base_slug,
    )
    return individual_paths


# ─────────────────────────────────────────────────────────────────────────────

def format_http_block(entry: HARRequestEntry, index: int = 1) -> str:
    lines: list[str] = [
        f"{entry.method} {entry.path} {entry.http_version}",
        f"Host: {entry.host}",
    ]
    _skip = frozenset({"host"})
    for name, value in entry.headers.items():
        if name.lower() not in _skip:
            lines.append(f"{name}: {value}")
    lines.append("")
    if entry.post_data:
        lines.append(entry.post_data.strip())
        lines.append("")
    return "\n".join(lines)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 ─ Report Writers
# ═══════════════════════════════════════════════════════════════════════════════

# ── [REQ 3] One report file per request ──────────────────────────────────────

def write_single_request_report(
    result:        CaptureResult,
    har_entry:     HARRequestEntry,
    request_index: int,
    base_slug:     str,
    output_dir:    Path,
) -> Path:
    """
    Write a plain-text HTTP request report for exactly ONE HAR entry.

    Output filename: <output_dir>/<base_slug>_r<NNNN>.txt

    If a page fires N requests, this function is called N times, producing N
    independent report files — one per network exchange.
    """
    report_path = output_dir / f"{base_slug}_r{request_index:04d}.txt"
    now_iso     = datetime.now(tz=timezone.utc).isoformat()
    border      = "═" * 80
    direction   = "↑" if har_entry.method in {"POST", "PUT", "PATCH"} else "↓"
    sep_line    = (
        f"─── Request #{request_index:04d}"
        f"  [{direction} {har_entry.status_code}  {har_entry.response_mime}]"
        f"  {'─' * 40}"
    )

    with report_path.open("w", encoding="utf-8") as fh:
        fh.write(
            f"{border}\n"
            f"  HAR REQUEST REPORT — Entry #{request_index:04d}\n"
            f"  Target   : {result.entry.url}\n"
            f"  Label    : {result.entry.label or '—'}\n"
            f"  HAR File : {result.har_path}\n"
            f"  Captured : {now_iso}\n"
            f"  Duration : {result.duration_s:.3f}s\n"
            f"  Status   : {'SUCCESS ✓' if result.success else f'FAILED ✗  ({result.error})'}\n"
            f"{border}\n\n"
            f"{sep_line}\n"
            f"{format_http_block(har_entry, index=request_index)}\n\n"
        )
    return report_path


def write_failed_report(result: CaptureResult, base_slug: str, output_dir: Path) -> Path:
    """Write a single failure report for an endpoint whose capture did not succeed."""
    report_path = output_dir / f"{base_slug}_FAILED.txt"
    now_iso     = datetime.now(tz=timezone.utc).isoformat()
    border      = "═" * 80

    with report_path.open("w", encoding="utf-8") as fh:
        fh.write(
            f"{border}\n"
            f"  HAR REQUEST REPORT — CAPTURE FAILED\n"
            f"  Target   : {result.entry.url}\n"
            f"  Label    : {result.entry.label or '—'}\n"
            f"  HAR File : {result.har_path}\n"
            f"  Captured : {now_iso}\n"
            f"  Duration : {result.duration_s:.3f}s\n"
            f"  Status   : FAILED ✗  ({result.error})\n"
            f"{border}\n\n"
            f"(No request entries — capture failed or returned no data.)\n"
        )
    return report_path

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 ─ Pipeline Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

async def run_pipeline(config: PipelineConfig) -> dict[str, Any]:
    config.har_output_dir.mkdir(parents=True, exist_ok=True)
    config.report_dir.mkdir(parents=True, exist_ok=True)

    endpoints = load_endpoints(config)
    semaphore = asyncio.Semaphore(config.max_workers)

    summary: dict[str, Any] = {
        "pipeline_version": "2.0.0",
        "start_time":       datetime.now(tz=timezone.utc).isoformat(),
        "total":            len(endpoints),
        "success":          0,
        "failed":           0,
        "skipped":          0,
        "total_requests":   0,
        "results":          [],
    }

    async with async_playwright() as pw:
        launcher = getattr(pw, config.browser_type)
        browser  = await launcher.launch(
            headless = config.headless,
            args     = [
                "--disable-dev-shm-usage",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-background-networking",
            ],
        )
        log.info(
            "Browser: %s | Workers: %d | Endpoints: %d",
            config.browser_type, config.max_workers, len(endpoints),
        )

        capture_coros = [capture_har(ep, browser, config, semaphore) for ep in endpoints]
        results: list[CaptureResult] = await asyncio.gather(*capture_coros)
        await browser.close()

    # ── [REQ 3] Post-processing: split composite HAR → per-request files ──────
    for result in results:
        slug   = _url_to_slug(result.entry.url)
        record: dict[str, Any] = {
            "url":           result.entry.url,
            "success":       result.success,
            "duration_s":    round(result.duration_s, 3),
            "error":         result.error,
            "har_path":      str(result.har_path),
            "request_count": 0,
            "har_paths":     [],     # individual per-request .har files
            "report_paths":  [],     # individual per-request .txt reports
        }

        if not result.success:
            fail_rpt = write_failed_report(result, slug, config.report_dir)
            record["report_paths"] = [str(fail_rpt)]
            summary["failed"] += 1

        elif not result.har_path or not result.har_path.exists():
            summary["skipped"] += 1

        else:
            # Parse the composite HAR into individual request entries
            har_entries = parse_har_file(result.har_path)

            if not har_entries:
                summary["skipped"] += 1
            else:
                # Step A — split composite HAR → N individual .har files
                individual_hars = split_har_into_individual_files(
                    result.har_path, slug, config.har_output_dir
                )
                result.individual_hars = individual_hars
                record["har_paths"] = [str(p) for p in individual_hars]

                # Step B — write one .txt report per HAR entry
                # (decoupled from Step A so reports are produced even if a
                # split file fails to write)
                report_paths: list[str] = []
                for idx, har_entry in enumerate(har_entries, start=1):
                    rpt = write_single_request_report(
                        result        = result,
                        har_entry     = har_entry,
                        request_index = idx,
                        base_slug     = slug,
                        output_dir    = config.report_dir,
                    )
                    report_paths.append(str(rpt))

                record["request_count"] = len(har_entries)
                record["report_paths"]  = report_paths
                summary["success"] += 1

        summary["results"].append(record)

    summary["end_time"]       = datetime.now(tz=timezone.utc).isoformat()
    summary["total_requests"] = sum(r.get("request_count", 0) for r in summary["results"])

    with (config.report_dir / "pipeline_summary.json").open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    bar = "═" * 62
    log.info(
        "\n%s\n  PIPELINE COMPLETE\n"
        "  Total endpoints  : %d\n"
        "  ✓ Success        : %d\n"
        "  ✗ Failed         : %d\n"
        "  Total requests   : %d\n%s",
        bar, summary["total"], summary["success"],
        summary["failed"], summary["total_requests"], bar,
    )
    return summary

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 ─ Utilities & CLI
# ═══════════════════════════════════════════════════════════════════════════════

def _url_to_slug(url: str, max_label_len: int = 60) -> str:
    parsed = urlparse(url)
    raw    = f"{parsed.netloc}{parsed.path}".strip("/")
    label  = raw.replace("/", "__").replace(".", "-")
    safe   = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)
    digest = hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()[:8]
    return f"{safe[:max_label_len] or 'unknown'}_{digest}"


def main() -> None:
    parser = argparse.ArgumentParser(description="HAR Benchmarking Pipeline v2.0")
    parser.add_argument("--input",       default="wpath.json",  help="Path to the JSON endpoint schema file.")
    parser.add_argument("--har-dir",     default="har_output",  help="Output directory for generated .har files.")
    parser.add_argument("--report-dir",  default="reports",     help="Output directory for plain-text HTTP request reports.")
    parser.add_argument("--workers",     type=int, default=3,   help="Maximum concurrent browser contexts.")
    parser.add_argument("--timeout",     type=int, default=30,  help="Per-page navigation timeout in seconds.")
    parser.add_argument("--browser",     choices=["chromium", "firefox", "webkit"], default="chromium")
    parser.add_argument("--headed",      action="store_true",   help="Launch browser in headed (visible) mode.")
    parser.add_argument("--har-content", choices=["omit", "embed"], default="omit")
    parser.add_argument("--log-level",   choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")

    args = parser.parse_args()
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
        sys.exit(130)


if __name__ == "__main__":
    main()