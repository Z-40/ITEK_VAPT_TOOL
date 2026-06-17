#!/usr/bin/env python3
"""
katana_crawler.py
═══════════════════════════════════════════════════════════════════════════════
Automated web crawler using ProjectDiscovery's katana tool.

  • Reads alive subdomains from a JSON file (handles flat lists, arrays of objects,
    dictionaries where subdomains are keys, or single target objects).
  • Crawls each subdomain with katana, injecting an optional auth cookie.
  • Concurrently verifies the HTTP status of discovered links via HEAD requests,
    automatically scrubbing out 404 dead links and JS engine remnants.
  • Writes a structured JSON report mapping subdomains to confirmed live paths.

Prerequisites
─────────────
  Python  ≥ 3.9
  katana  → go install github.com/projectdiscovery/katana/cmd/katana@latest

Usage Examples
──────────────
  python katana_crawler.py -i alive_subdomains.json -o wpath.json -w 4 -v
═══════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse


# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────

log = logging.getLogger("katana_crawler")


class _ColorFormatter(logging.Formatter):
    _LEVEL_COLORS: dict[str, str] = {
        "DEBUG":    "\033[96m",   # bright cyan
        "INFO":     "\033[92m",   # bright green
        "WARNING":  "\033[93m",   # bright yellow
        "ERROR":    "\033[91m",   # bright red
        "CRITICAL": "\033[95m",   # bright magenta
    }
    _RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self._LEVEL_COLORS.get(record.levelname, self._RESET)
        record.levelname = f"{color}{record.levelname:<8}{self._RESET}"
        return super().format(record)


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    log.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.setFormatter(
        _ColorFormatter(
            fmt="%(asctime)s  %(levelname)s  %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    log.addHandler(handler)


# ──────────────────────────────────────────────────────────────────────────────
# CLI Argument Parsing
# ──────────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="katana_crawler.py",
        description="Automate web crawling across alive subdomains using katana with 404 filtering.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-i", "--input", required=True, metavar="FILE", help="Input JSON file containing alive subdomains.")
    parser.add_argument("-o", "--output", required=True, metavar="FILE", help="Output JSON file for crawled URLs.")
    parser.add_argument("-c", "--cookie", default=None, metavar="STRING", help='Auth cookie string (e.g. "session=abc123").')
    parser.add_argument("-d", "--depth", type=int, default=3, metavar="N", help="Katana crawl depth (default: 3).")
    parser.add_argument("-t", "--timeout", type=int, default=300, metavar="SECS", help="Per-subdomain timeout (default: 300).")
    parser.add_argument("-w", "--workers", type=int, default=1, metavar="N", help="Number of parallel subdomain workers.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable DEBUG-level logging.")
    return parser


# ──────────────────────────────────────────────────────────────────────────────
# Input Loading & Normalization
# ──────────────────────────────────────────────────────────────────────────────

_DICT_KEY_PRIORITY: tuple[str, ...] = ("subdomain", "domain", "host", "url", "target", "address", "fqdn", "name")


def _extract_from_dict(entry: dict) -> str | None:
    for key in _DICT_KEY_PRIORITY:
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for value in entry.values():
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def load_subdomains(input_path: str) -> list[str]:
    path = Path(input_path)
    if not path.is_file():
        log.error("Input file not found: %s", input_path)
        sys.exit(1)

    try:
        raw_text = path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except Exception as exc:
        log.error("Failed to parse JSON in '%s': %s", input_path, exc)
        sys.exit(1)

    if isinstance(data, dict):
        extracted_list = None
        for key in ("subdomains", "domains", "targets", "results", "hosts"):
            if key in data and isinstance(data[key], list):
                extracted_list = data[key]
                break
        if not extracted_list:
            for value in data.values():
                if isinstance(value, list):
                    extracted_list = value
                    break
        if not extracted_list:
            if any("." in str(k) and " " not in str(k) for k in data.keys()):
                extracted_list = list(data.keys())
        if not extracted_list:
            single_candidate = _extract_from_dict(data)
            if single_candidate:
                extracted_list = [single_candidate]

        if extracted_list is not None:
            data = extracted_list
        else:
            log.error("Could not automatically determine target dictionary structure.")
            sys.exit(1)

    if not isinstance(data, list):
        log.error("Expected array or dict-enclosed array, got %s.", type(data).__name__)
        sys.exit(1)

    seen: set[str] = set()
    subdomains: list[str] = []
    for idx, item in enumerate(data):
        candidate = item.strip() if isinstance(item, str) else (_extract_from_dict(item) or "") if isinstance(item, dict) else ""
        if candidate and candidate not in seen:
            seen.add(candidate)
            subdomains.append(candidate)

    log.info("Loaded %d unique subdomain(s) from '%s'.", len(subdomains), input_path)
    return subdomains


# ──────────────────────────────────────────────────────────────────────────────
# URL Utilities & Active Status Prober
# ──────────────────────────────────────────────────────────────────────────────

def _ensure_scheme(target: str) -> str:
    return target if target.startswith(("http://", "https://")) else f"https://{target}"


def _has_query_params(url: str) -> bool:
    return bool(urlparse(url).query)


def _extract_query_params(url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(url).query, keep_blank_values=True)


def _check_url_status(url: str, timeout: int = 4) -> int:
    """Perform a rapid network HEAD request to grab the actual status code."""
    # Instantly discard obvious JS code leftovers grabbed by regex parsing
    if "'+ " in url or "' +" in url or '"+' in url or url.endswith(("+", "'", '"')):
        return 404
    if not url.startswith(("http://", "https://")):
        return 404

    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VAPT-Prober/2.0")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return 0  # Network dropped, bad TLS, or invalid DNS


def _filter_live_urls(raw_urls: list[str], subdomain_ctx: str) -> list[str]:
    """Probes URLs concurrently to purge 404s and broken links."""
    unique_raw = sorted(set(raw_urls))
    if not unique_raw:
        return []

    log.debug("[%s] Verifying stability of %d crawled paths...", subdomain_ctx, len(unique_raw))
    live_urls = []
    
    # Use up to 30 concurrent worker threads per subdomain to prevent pipeline choking
    with ThreadPoolExecutor(max_workers=30) as verification_pool:
        future_to_url = {verification_pool.submit(_check_url_status, url): url for url in unique_raw}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                status_code = future.result()
                # Drop 404s and connection drops (0). Retain everything else.
                if status_code != 404 and status_code != 0:
                    live_urls.append(url)
            except Exception:
                pass

    dropped_count = len(unique_raw) - len(live_urls)
    if dropped_count > 0:
        log.debug("[%s] Scrubbed %d dead links / 404 errors from results.", subdomain_ctx, dropped_count)

    return sorted(live_urls)


# ──────────────────────────────────────────────────────────────────────────────
# Katana Integration Engines
# ──────────────────────────────────────────────────────────────────────────────

def check_katana_binary() -> str:
    binary = shutil.which("katana")
    if not binary:
        log.error("katana binary not found on environment PATH.")
        sys.exit(1)
    return binary


def crawl_subdomain(binary: str, subdomain: str, depth: int, cookie: str | None, timeout: int) -> tuple[str, list[str]]:
    target_url = _ensure_scheme(subdomain)
    cmd = [binary, "-u", target_url, "-d", str(depth), "-jc", "-kf", "all", "-silent", "-nc", "-timeout", "15"]
    if cookie:
        cmd.extend(["-H", f"Cookie: {cookie}"])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        raw_urls = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        
        # Pass the extracted URLs directly into the live verification logic
        verified_urls = _filter_live_urls(raw_urls, subdomain)
        return subdomain, verified_urls
    except subprocess.TimeoutExpired:
        log.warning("[%s] Subprocess timed out after %ds.", subdomain, timeout)
        return subdomain, []
    except Exception as exc:
        log.error("[%s] Unexpected processing runtime exception: %s", subdomain, exc)
        return subdomain, []


def _structure_subdomain_result(subdomain: str, verified_urls: list[str]) -> dict:
    pages: list[str] = []
    endpoints_with_params: list[dict] = []

    for url in verified_urls:
        if _has_query_params(url):
            endpoints_with_params.append({"url": url, "parameters": _extract_query_params(url)})
        else:
            pages.append(url)

    return {
        "subdomain":             subdomain,
        "status":                "ok" if verified_urls else "empty",
        "total_unique_urls":     len(verified_urls),
        "pages":                 pages,
        "endpoints_with_params": endpoints_with_params,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Main Orchestrator Pipeline
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    _setup_logging(verbose=args.verbose)

    katana_bin = check_katana_binary()
    subdomains = load_subdomains(args.input)

    if not subdomains:
        log.error("No valid subdomains discovered to target.")
        sys.exit(1)

    total = len(subdomains)
    log.info("━" * 64)
    log.info("  katana Web Crawler (With Active Status Verification)")
    log.info("  Targets  : %d subdomain(s)", total)
    log.info("  Workers  : %d (%s)", args.workers, "parallel" if args.workers > 1 else "sequential")
    log.info("━" * 64)

    result_map: dict[str, dict] = {}

    if args.workers <= 1:
        for idx, subdomain in enumerate(subdomains, start=1):
            log.info("[%d/%d] Crawling & Verifying: %s", idx, total, subdomain)
            _, verified_urls = crawl_subdomain(katana_bin, subdomain, args.depth, args.cookie, args.timeout)
            structured = _structure_subdomain_result(subdomain, verified_urls)
            result_map[subdomain] = structured
            log.info("  ↳ Live Links: %-4d | Pages: %-4d | Parameterized Endpoints: %d",
                     structured["total_unique_urls"], len(structured["pages"]), len(structured["endpoints_with_params"]))
    else:
        log.info("Spawning %d master subdomain worker thread(s)...", args.workers)
        completed = 0
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            future_to_subdomain = {pool.submit(crawl_subdomain, katana_bin, sd, args.depth, args.cookie, args.timeout): sd for sd in subdomains}
            for future in as_completed(future_to_subdomain):
                completed += 1
                subdomain, verified_urls = future.result()
                structured = _structure_subdomain_result(subdomain, verified_urls)
                result_map[subdomain] = structured
                log.info("[%d/%d] %-45s Live URLs: %d (params: %d)",
                         completed, total, subdomain, structured["total_unique_urls"], len(structured["endpoints_with_params"]))

    ordered_results = [result_map[sd] for sd in subdomains]
    total_urls = sum(r["total_unique_urls"] for r in ordered_results)
    total_with_params = sum(len(r["endpoints_with_params"]) for r in ordered_results)
    subdomains_ok = sum(1 for r in ordered_results if r["status"] == "ok")

    output_payload = {
        "scan_metadata": {
            "timestamp":                   datetime.now(tz=timezone.utc).isoformat(),
            "input_file":                  str(Path(args.input).resolve()),
            "output_file":                 str(Path(args.output).resolve()),
            "total_subdomains_scanned":    total,
            "subdomains_with_results":     subdomains_ok,
            "crawl_depth":                 args.depth,
            "total_verified_live_urls":    total_urls,
            "total_endpoints_with_params": total_with_params,
        },
        "results": ordered_results,
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output_payload, indent=2, ensure_ascii=False), encoding="utf-8")

    log.info("━" * 64)
    log.info("  Verification complete! Clean report saved to: %s", out_path.resolve())
    log.info("  Total Verified Live URLs: %d (Dropped all 404 inaccuracies)", total_urls)
    log.info("━" * 64)


if __name__ == "__main__":
    main()