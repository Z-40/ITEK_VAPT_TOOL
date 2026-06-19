#!/usr/bin/env python3
"""
har_pipeline.py
═══════════════
Production-grade HAR Benchmarking Pipeline

Automates HTTP Archive (HAR) file generation and raw HTTP/1.1 request
extraction from a JSON endpoint schema using Playwright's async API with
semaphore-bounded concurrency.

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
        stream_h = logging.StreamHandler(sys.stdout)
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
    label:  str              = ""
    method: str              = "GET"
    params: dict[str, Any]   = field(default_factory=dict)

@dataclass
class CaptureResult:
    entry:      EndpointEntry
    har_path:   Path | None  = None
    success:    bool         = False
    error:      str          = ""
    duration_s: float        = 0.0

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
# SECTION 2 ─ Input Parsing  (Phase 0 - WPATH.JSON COMPATIBLE)
# ═══════════════════════════════════════════════════════════════════════════════

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
            if isinstance(item, str): push(item)
            elif isinstance(item, dict): push(url=item.get("url", ""), label=item.get("label", ""), method=item.get("method", "GET"))
        return entries

    if isinstance(raw, dict):
        # Flatten wpath.json 'results' array if it exists, otherwise treat root as target
        targets = raw.get("results", [raw]) if "results" in raw else [raw]

        for target in targets:
            if not isinstance(target, dict):
                continue

            for page in target.get("pages", []):
                if isinstance(page, str): push(page)
                elif isinstance(page, dict): push(url=page.get("url", ""), label=page.get("title", ""), method=page.get("method", "GET"))

            for ep in target.get("endpoints_with_params", []):
                base_url: str = ep.get("url", ep.get("base_url", ""))
                method:   str = ep.get("method", "GET").upper()
                label:    str = ep.get("label", "")
                
                # Handle wpath.json specific 'parameters' array mapping
                if "parameters" in ep and isinstance(ep["parameters"], dict):
                    param_set = {}
                    for k, v in ep["parameters"].items():
                        param_set[k] = v[0] if isinstance(v, list) and v else v
                    param_sets = [param_set]
                else:
                    param_sets = ep.get("params", [{}]) or [{}]

                for param_set in param_sets:
                    if method == "GET" and param_set:
                        if "?" in base_url:
                            full_url = f"{base_url}{urlencode(param_set)}" if base_url.endswith(("?", "&")) else base_url
                        else:
                            full_url = f"{base_url}?{urlencode(param_set)}"
                    else:
                        full_url = base_url
                    push(url=full_url, label=label, method=method, params=param_set)

            for u in target.get("urls", []):
                if isinstance(u, str): push(u)
                elif isinstance(u, dict): push(url=u.get("url", ""), label=u.get("label", ""), method=u.get("method", "GET"))

    if not entries:
        raise ValueError("No valid HTTP/HTTPS URLs found in the input file.")

    log.info("Loaded %d unique endpoint(s) from '%s'.", len(entries), config.input_file)
    return entries

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 ─ HAR Capture  (Phase 1)
# ═══════════════════════════════════════════════════════════════════════════════

async def capture_har(entry: EndpointEntry, browser: Browser, config: PipelineConfig, semaphore: asyncio.Semaphore) -> CaptureResult:
    async with semaphore:
        slug      = _url_to_slug(entry.url)
        har_path  = config.har_output_dir / f"{slug}.har"
        result    = CaptureResult(entry=entry, har_path=har_path)
        t0        = time.perf_counter()

        context: BrowserContext | None = None
        page:    Page | None           = None

        try:
            log.info("[CAPTURE ▶] %-6s  %s", entry.method, entry.url)

            context = await browser.new_context(
                record_har_path    = str(har_path),
                record_har_content = config.har_content,
                ignore_https_errors= True,
                java_script_enabled= True,
                user_agent         = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 HAR-Pipeline/1.0",
            )

            page = await context.new_page()

            async def _navigate() -> None:
                await page.goto(entry.url, wait_until="networkidle", timeout=config.page_timeout_ms)

            await asyncio.wait_for(_navigate(), timeout=config.page_timeout_ms / 1_000 + 5)

            result.success = True
            log.info("[CAPTURE ✓] %s  (%.2fs)", slug, time.perf_counter() - t0)

        except asyncio.TimeoutError:
            result.error = f"asyncio hard-stop after {config.page_timeout_ms / 1_000 + 5:.0f}s"
            log.warning("[CAPTURE ⏱] TIMEOUT (asyncio)  %s — %s", slug, result.error)
        except PlaywrightTimeoutError as exc:
            result.error = f"Navigation timeout after {config.page_timeout_ms / 1_000:.0f}s"
            log.warning("[CAPTURE ⏱] TIMEOUT (playwright)  %s", slug)
        except Exception as exc:
            result.error = repr(exc)
            log.error("[CAPTURE ✗] %s — %s", slug, exc)
        finally:
            for obj in (page, context):
                if obj is not None:
                    try: await obj.close()
                    except Exception: pass

        result.duration_s = time.perf_counter() - t0
        return result

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 ─ HAR Parsing & HTTP Reconstruction  (Phase 2)
# ═══════════════════════════════════════════════════════════════════════════════

def parse_har_file(har_path: Path) -> list[HARRequestEntry]:
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
        req  = raw.get("request",  {})
        resp = raw.get("response", {})
        url_str = req.get("url", "").strip()
        
        if not url_str: continue

        parsed_url   = urlparse(url_str)
        method       = req.get("method", "GET").upper()
        http_version = req.get("httpVersion", "HTTP/1.1")

        path = parsed_url.path or "/"
        if parsed_url.query: path = f"{path}?{parsed_url.query}"
        if parsed_url.fragment: path = f"{path}#{parsed_url.fragment}"

        host = parsed_url.netloc or parsed_url.hostname or ""

        raw_headers: list[dict] = req.get("headers", [])
        headers: dict[str, str] = {h["name"]: h["value"] for h in raw_headers if "name" in h and "value" in h}

        post_data: str | None = None
        if "postData" in req:
            pd_block  = req["postData"]
            post_data = pd_block.get("text") or pd_block.get("mimeType") or None

        results.append(HARRequestEntry(
            method=method, url=url_str, path=path, host=host, 
            http_version=http_version, headers=headers, post_data=post_data, 
            status_code=resp.get("status", 0), response_mime=resp.get("content", {}).get("mimeType", "")
        ))
    return results

def format_http_block(entry: HARRequestEntry, index: int = 1) -> str:
    lines: list[str] = [f"{entry.method} {entry.path} {entry.http_version}", f"Host: {entry.host}"]
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
# SECTION 5 ─ Report Writer
# ═══════════════════════════════════════════════════════════════════════════════

def write_per_url_report(result: CaptureResult, har_entries: list[HARRequestEntry], output_dir: Path) -> Path:
    slug        = _url_to_slug(result.entry.url)
    report_path = output_dir / f"{slug}.txt"
    now_iso     = datetime.now(tz=timezone.utc).isoformat()

    with report_path.open("w", encoding="utf-8") as fh:
        border = "═" * 80
        fh.write(f"{border}\n  HAR REQUEST REPORT\n  Target   : {result.entry.url}\n")
        fh.write(f"  Label    : {result.entry.label or '—'}\n  HAR File : {result.har_path}\n")
        fh.write(f"  Captured : {now_iso}\n  Duration : {result.duration_s:.3f}s\n")
        status_str = "SUCCESS ✓" if result.success else f"FAILED ✗  ({result.error})"
        fh.write(f"  Status   : {status_str}\n{border}\n\n")

        if not result.success or not har_entries:
            fh.write("(No request entries — capture failed or returned no data.)\n")
            return report_path

        for i, har_req in enumerate(har_entries, start=1):
            direction = "↑" if har_req.method in {"POST", "PUT", "PATCH"} else "↓"
            sep = f"─── Request #{i:04d}  [{direction} {har_req.status_code}  {har_req.response_mime}]  {'─' * 40}"
            fh.write(f"{sep}\n{format_http_block(har_req, index=i)}\n\n")

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
        "pipeline_version": "1.0.0", "start_time": datetime.now(tz=timezone.utc).isoformat(),
        "total": len(endpoints), "success": 0, "failed": 0, "skipped": 0, "total_requests": 0, "results": []
    }

    async with async_playwright() as pw:
        launcher = getattr(pw, config.browser_type)
        browser  = await launcher.launch(headless=config.headless, args=["--disable-dev-shm-usage", "--no-sandbox", "--disable-gpu", "--disable-background-networking"])
        log.info("Browser: %s | Workers: %d | Endpoints: %d", config.browser_type, config.max_workers, len(endpoints))

        capture_coros = [capture_har(ep, browser, config, semaphore) for ep in endpoints]
        results: list[CaptureResult] = await asyncio.gather(*capture_coros)
        await browser.close()

    for result in results:
        record: dict[str, Any] = {"url": result.entry.url, "success": result.success, "duration_s": round(result.duration_s, 3), "error": result.error, "har_path": str(result.har_path), "request_count": 0}
        if not result.success:
            write_per_url_report(result, [], config.report_dir)
            summary["failed"] += 1
        elif not result.har_path or not result.har_path.exists():
            summary["skipped"] += 1
        else:
            har_entries = parse_har_file(result.har_path)
            record["report_path"] = str(write_per_url_report(result, har_entries, config.report_dir))
            record["request_count"] = len(har_entries)
            summary["success"] += 1
        summary["results"].append(record)

    summary["end_time"] = datetime.now(tz=timezone.utc).isoformat()
    summary["total_requests"] = sum(r.get("request_count", 0) for r in summary["results"])

    with (config.report_dir / "pipeline_summary.json").open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    bar = "═" * 62
    log.info("\n%s\n  PIPELINE COMPLETE\n  Total endpoints  : %d\n  ✓ Success        : %d\n  ✗ Failed         : %d\n  Total requests   : %d\n%s", bar, summary["total"], summary["success"], summary["failed"], summary.get("total_requests", 0), bar)
    return summary

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 ─ Utilities & CLI
# ═══════════════════════════════════════════════════════════════════════════════

def _url_to_slug(url: str, max_label_len: int = 60) -> str:
    parsed  = urlparse(url)
    raw     = f"{parsed.netloc}{parsed.path}".strip("/")
    label   = raw.replace("/", "__").replace(".", "-")
    safe    = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)
    digest  = hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()[:8]
    return f"{safe[:max_label_len] or 'unknown'}_{digest}"

def main() -> None:
    parser = argparse.ArgumentParser(description="HAR Benchmarking Pipeline")
    parser.add_argument("--input", default="wpath.json", help="Path to the JSON endpoint schema file.")
    parser.add_argument("--har-dir", default="har_output", help="Output directory for generated .har files.")
    parser.add_argument("--report-dir", default="reports", help="Output directory for plain-text HTTP request reports.")
    parser.add_argument("--workers", type=int, default=3, help="Maximum concurrent browser contexts.")
    parser.add_argument("--timeout", type=int, default=30, help="Per-page navigation timeout in seconds.")
    parser.add_argument("--browser", choices=["chromium", "firefox", "webkit"], default="chromium")
    parser.add_argument("--headed", action="store_true", help="Launch browser in headed (visible) mode.")
    parser.add_argument("--har-content", choices=["omit", "embed"], default="omit")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")

    args = parser.parse_args()
    global log
    log = _build_logger(args.log_level)

    config = PipelineConfig(
        input_file=Path(args.input), har_output_dir=Path(args.har_dir), report_dir=Path(args.report_dir),
        max_workers=args.workers, page_timeout_ms=args.timeout * 1_000, browser_type=args.browser,
        headless=not args.headed, log_level=args.log_level, har_content=args.har_content,
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