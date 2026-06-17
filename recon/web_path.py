#!/usr/bin/env python3
"""
katana_crawler.py
═══════════════════════════════════════════════════════════════════════════════
Automated web crawler using ProjectDiscovery's katana tool.

  • Reads alive subdomains from a JSON file (handles flat lists, arrays of objects,
    dictionaries where subdomains are keys, or single target objects).
  • Crawls each subdomain with katana, injecting an optional auth cookie.
  • Writes a structured JSON report that maps every subdomain to its
    discovered pages and parameterized endpoints (those carrying query params).

Prerequisites
─────────────
  Python  ≥ 3.9
  katana  → go install github.com/projectdiscovery/katana/cmd/katana@latest
             OR grab a release: https://github.com/projectdiscovery/katana/releases
  Chrome / Chromium  (only needed when JS crawling via -jc is active)

Usage Examples
──────────────
  # Basic crawl (sequential)
  python katana_crawler.py -i alive_subdomains.json -o results.json

  # Authenticated crawl with a session cookie
  python katana_crawler.py -i alive.json -o results.json \
           -c "session=abc123; role=admin"

  # Deep crawl, verbose output, 4 parallel workers
  python katana_crawler.py -i alive.json -o results.json -d 5 -w 4 -v
═══════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse


# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────

# Module-level logger — configured in main() after CLI args are parsed.
log = logging.getLogger("katana_crawler")


class _ColorFormatter(logging.Formatter):
    """
    Custom log formatter that prepends ANSI colour codes to each log level
    label for improved readability in modern terminals.
    Falls back gracefully when colour codes are not supported.
    """

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
        # Left-pad the level name to 8 chars so columns stay aligned
        record.levelname = f"{color}{record.levelname:<8}{self._RESET}"
        return super().format(record)


def _setup_logging(verbose: bool = False) -> None:
    """Attach a coloured StreamHandler to the module logger."""
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
    """Define all CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="katana_crawler.py",
        description="Automate web crawling across alive subdomains using katana.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python katana_crawler.py -i alive_subdomains.json -o results.json
  python katana_crawler.py -i alive.json -o results.json -c "session=abc123"
  python katana_crawler.py -i alive.json -o results.json -d 5 -w 4 -v
        """,
    )

    parser.add_argument(
        "-i", "--input",
        required=True,
        metavar="FILE",
        help="Input JSON file containing alive subdomains.",
    )
    parser.add_argument(
        "-o", "--output",
        required=True,
        metavar="FILE",
        help="Output JSON file for crawled URLs and parameters.",
    )
    parser.add_argument(
        "-c", "--cookie",
        default=None,
        metavar="STRING",
        help='Authentication cookie string (e.g. "session=abc123; token=xyz").',
    )
    parser.add_argument(
        "-d", "--depth",
        type=int,
        default=3,
        metavar="N",
        help="Katana crawl depth — how many link-levels deep to follow (default: 3).",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=300,
        metavar="SECS",
        help="Per-subdomain subprocess timeout in seconds (default: 300).",
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=1,
        metavar="N",
        help="Number of parallel crawling workers (default: 1 = sequential).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging (shows raw commands, katana stderr, etc.).",
    )

    return parser


# ──────────────────────────────────────────────────────────────────────────────
# Input / Subdomain Loading
# ──────────────────────────────────────────────────────────────────────────────

_DICT_KEY_PRIORITY: tuple[str, ...] = (
    "subdomain", "domain", "host", "url", "target", "address", "fqdn", "name",
)


def _extract_from_dict(entry: dict) -> str | None:
    """
    Attempt to extract a raw subdomain / URL string from a dict entry by
    checking common key names in priority order.
    """
    for key in _DICT_KEY_PRIORITY:
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    for value in entry.values():
        if isinstance(value, str) and value.strip():
            return value.strip()

    return None


def load_subdomains(input_path: str) -> list[str]:
    """
    Load and de-duplicate subdomains from the JSON input file. Supports flat lists,
    arrays of objects, top-level objects enclosing an array, a single target object,
    or dictionaries where subdomains are keys.
    """
    path = Path(input_path)

    if not path.is_file():
        log.error("Input file not found: %s", input_path)
        sys.exit(1)

    try:
        raw_text = path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        log.error("Malformed JSON in '%s': %s", input_path, exc)
        sys.exit(1)
    except OSError as exc:
        log.error("Could not read '%s': %s", input_path, exc)
        sys.exit(1)

    # ── Handle Top-Level Dictionary/Object ───────────────────────────────────
    if isinstance(data, dict):
        log.debug("Top-level JSON is a dictionary. Attempting to extract list...")
        extracted_list = None
        
        # Fallback 1: Look for common nested array keys
        for key in ("subdomains", "domains", "targets", "results", "hosts"):
            if key in data and isinstance(data[key], list):
                extracted_list = data[key]
                break
        
        # Fallback 2: Grab the first nested value that is a list
        if not extracted_list:
            for value in data.values():
                if isinstance(value, list):
                    extracted_list = value
                    break

        # Fallback 3: Check if the dictionary keys themselves are subdomains
        # (e.g., {"sub1.domain.com": {"status": "up"}})
        if not extracted_list:
            if any("." in str(k) and " " not in str(k) for k in data.keys()):
                log.debug("Dictionary keys look like subdomains. Extracting keys.")
                extracted_list = list(data.keys())

        # Fallback 4: Check if it's just a single target object 
        # (e.g., {"subdomain": "infoteksoftware.com", "status": "alive"})
        if not extracted_list:
            single_candidate = _extract_from_dict(data)
            if single_candidate:
                log.debug("Dictionary matches a single target profile. Treating as single-item list.")
                extracted_list = [single_candidate]

        if extracted_list is not None:
            data = extracted_list
        else:
            log.error("Top-level is a dictionary, but could not automatically determine the target structure.")
            log.error("File contents snippet: %s...", raw_text[:200].strip())
            sys.exit(1)

    if not isinstance(data, list):
        log.error(
            "Expected a JSON array or a dict containing an array, got %s instead.",
            type(data).__name__,
        )
        sys.exit(1)

    # ── Normalise & de-duplicate ─────────────────────────────────────────────
    seen: set[str] = set()
    subdomains: list[str] = []

    for idx, item in enumerate(data):
        if isinstance(item, str):
            candidate = item.strip()
        elif isinstance(item, dict):
            candidate = _extract_from_dict(item) or ""
        else:
            log.warning(
                "Row %d: unsupported item type (%s) — skipping.",
                idx, type(item).__name__,
            )
            continue

        if not candidate:
            log.warning("Row %d: empty or unextractable value — skipping.", idx)
            continue

        if candidate not in seen:
            seen.add(candidate)
            subdomains.append(candidate)

    log.info(
        "Loaded %d unique subdomain(s) from '%s'.", len(subdomains), input_path
    )
    return subdomains


# ──────────────────────────────────────────────────────────────────────────────
# URL Utilities
# ──────────────────────────────────────────────────────────────────────────────

def _ensure_scheme(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return f"https://{target}"


def _has_query_params(url: str) -> bool:
    return bool(urlparse(url).query)


def _extract_query_params(url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(url).query, keep_blank_values=True)


# ──────────────────────────────────────────────────────────────────────────────
# Katana Binary Check
# ──────────────────────────────────────────────────────────────────────────────

def check_katana_binary() -> str:
    binary = shutil.which("katana")
    if not binary:
        log.error(
            "katana binary not found on PATH.\n"
            "  Install via Go : go install github.com/projectdiscovery/katana/cmd/katana@latest\n"
            "  Pre-built release: https://github.com/projectdiscovery/katana/releases"
        )
        sys.exit(1)

    log.debug("katana binary resolved to: %s", binary)
    return binary


# ──────────────────────────────────────────────────────────────────────────────
# Katana Command Builder
# ──────────────────────────────────────────────────────────────────────────────

def _build_katana_cmd(
    binary: str,
    target_url: str,
    depth: int,
    cookie: str | None,
) -> list[str]:
    cmd: list[str] = [
        binary,
        "-u", target_url,
        "-d", str(depth),
        "-jc",             # JavaScript endpoint extraction
        "-kf", "all",      # Seed from robots.txt & sitemap.xml
        "-silent",         # URL-only stdout
        "-nc",             # Strip ANSI colours
        "-timeout", "15",  # Per-request HTTP timeout (seconds)
    ]

    if cookie:
        cmd.extend(["-H", f"Cookie: {cookie}"])

    return cmd


# ──────────────────────────────────────────────────────────────────────────────
# Katana Execution
# ──────────────────────────────────────────────────────────────────────────────

def crawl_subdomain(
    binary: str,
    subdomain: str,
    depth: int,
    cookie: str | None,
    timeout: int,
) -> tuple[str, list[str]]:
    target_url = _ensure_scheme(subdomain)
    cmd = _build_katana_cmd(binary, target_url, depth, cookie)
    log.debug("[%s] Running: %s", subdomain, " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.warning(
            "[%s] Subprocess timed out after %ds — partial results discarded.",
            subdomain, timeout,
        )
        return subdomain, []
    except FileNotFoundError:
        log.error("katana binary disappeared during execution. Aborting.")
        sys.exit(1)
    except OSError as exc:
        log.error("[%s] OS error while launching katana: %s", subdomain, exc)
        return subdomain, []

    if proc.returncode != 0 and proc.stderr:
        log.debug(
            "[%s] katana exited %d, stderr: %s",
            subdomain, proc.returncode, proc.stderr.strip(),
        )

    raw_urls = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return subdomain, raw_urls


# ──────────────────────────────────────────────────────────────────────────────
# Result Structuring
# ──────────────────────────────────────────────────────────────────────────────

def _structure_subdomain_result(subdomain: str, raw_urls: list[str]) -> dict:
    unique_urls = sorted(set(raw_urls))

    pages: list[str] = []
    endpoints_with_params: list[dict] = []

    for url in unique_urls:
        if _has_query_params(url):
            endpoints_with_params.append(
                {
                    "url": url,
                    "parameters": _extract_query_params(url),
                }
            )
        else:
            pages.append(url)

    return {
        "subdomain":             subdomain,
        "status":                "ok" if unique_urls else "empty",
        "total_unique_urls":     len(unique_urls),
        "pages":                 pages,
        "endpoints_with_params": endpoints_with_params,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Main Orchestration
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    _setup_logging(verbose=args.verbose)

    katana_bin = check_katana_binary()
    subdomains = load_subdomains(args.input)

    if not subdomains:
        log.error(
            "No valid subdomains were found in '%s'. Nothing to crawl.",
            args.input,
        )
        sys.exit(1)

    total = len(subdomains)

    log.info("━" * 64)
    log.info("  katana Web Crawler")
    log.info("  Targets  : %d subdomain(s)", total)
    log.info("  Depth    : %d", args.depth)
    log.info("  Timeout  : %ds / subdomain", args.timeout)
    log.info("  Workers  : %d (%s)", args.workers,
             "parallel" if args.workers > 1 else "sequential")
    log.info("  Cookie   : %s", "provided" if args.cookie else "none")
    log.info("━" * 64)

    result_map: dict[str, dict] = {}

    if args.workers <= 1:
        for idx, subdomain in enumerate(subdomains, start=1):
            log.info(
                "[%d/%d]  Crawling: %s",
                idx, total, subdomain,
            )

            _, raw_urls = crawl_subdomain(
                binary=katana_bin,
                subdomain=subdomain,
                depth=args.depth,
                cookie=args.cookie,
                timeout=args.timeout,
            )

            structured = _structure_subdomain_result(subdomain, raw_urls)
            result_map[subdomain] = structured

            if structured["status"] == "empty":
                log.warning("  ↳ No URLs discovered — host may be unreachable.")
            else:
                log.info(
                    "  ↳ URLs: %-4d  |  Pages: %-4d  |  Endpoints w/ params: %d",
                    structured["total_unique_urls"],
                    len(structured["pages"]),
                    len(structured["endpoints_with_params"]),
                )

    else:
        log.info("Spawning %d worker thread(s)…", args.workers)
        completed = 0

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            future_to_subdomain = {
                pool.submit(
                    crawl_subdomain,
                    katana_bin,
                    sd,
                    args.depth,
                    args.cookie,
                    args.timeout,
                ): sd
                for sd in subdomains
            }

            for future in as_completed(future_to_subdomain):
                completed += 1
                subdomain, raw_urls = future.result()

                structured = _structure_subdomain_result(subdomain, raw_urls)
                result_map[subdomain] = structured

                log.info(
                    "[%d/%d]  %-45s  URLs: %d  (params: %d)",
                    completed, total, subdomain,
                    structured["total_unique_urls"],
                    len(structured["endpoints_with_params"]),
                )

    ordered_results = [result_map[sd] for sd in subdomains]

    total_urls          = sum(r["total_unique_urls"]           for r in ordered_results)
    total_with_params   = sum(len(r["endpoints_with_params"]) for r in ordered_results)
    subdomains_ok       = sum(1 for r in ordered_results if r["status"] == "ok")
    subdomains_empty    = total - subdomains_ok

    output_payload = {
        "scan_metadata": {
            "timestamp":                   datetime.now(tz=timezone.utc).isoformat(),
            "input_file":                  str(Path(args.input).resolve()),
            "output_file":                 str(Path(args.output).resolve()),
            "total_subdomains_scanned":    total,
            "subdomains_with_results":     subdomains_ok,
            "subdomains_empty":            subdomains_empty,
            "crawl_depth":                 args.depth,
            "cookie_injected":             args.cookie is not None,
            "total_unique_urls":           total_urls,
            "total_endpoints_with_params": total_with_params,
        },
        "results": ordered_results,
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        out_path.write_text(
            json.dumps(output_payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as exc:
        log.error("Failed to write output file '%s': %s", args.output, exc)
        sys.exit(1)

    log.info("━" * 64)
    log.info("  Crawl complete!")
    log.info("  Subdomains scanned      : %d", total)
    log.info("  Subdomains with results : %d", subdomains_ok)
    log.info("  Subdomains empty        : %d", subdomains_empty)
    log.info("  Total unique URLs       : %d", total_urls)
    log.info("  Endpoints w/ params     : %d  ← prioritise for injection tests",
             total_with_params)
    log.info("  Output saved to         : %s", out_path.resolve())
    log.info("━" * 64)


if __name__ == "__main__":
    main()

