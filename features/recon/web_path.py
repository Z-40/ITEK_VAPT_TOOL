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
from typing import Dict, Any, List

# ──────────────────────────────────────────────────────────────────────────────
# Logging Configuration
# ──────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stderr
)
log = logging.getLogger("katana_crawler")

# ──────────────────────────────────────────────────────────────────────────────
# HELPER PARSING & TARGET RESOLUTION
# ──────────────────────────────────────────────────────────────────────────────
def extract_subdomains_from_memory(input_json_data: Dict[str, Any]) -> tuple[str, List[str]]:
    """
    Extracts the root target domain and a flat array of subdomains directly
    from an in-memory dictionary payload.
    """
    target = input_json_data.get("target", "unknown_apex").strip()
    
    # Check if input follows the standard subdomains dictionary map layer
    if "subdomains" in input_json_data:
        subs_node = input_json_data["subdomains"]
        if isinstance(subs_node, dict):
            return target, sorted(list(subs_node.keys()))
        elif isinstance(subs_node, list):
            return target, sorted(list(set(subs_node)))

    # Fallback to scanning just the main target or look for direct listings
    return target, [target] if target != "unknown_apex" else []

# ──────────────────────────────────────────────────────────────────────────────
# LIVE URL VERIFICATION ENGINE
# ──────────────────────────────────────────────────────────────────────────────
def _request_status(url: str, method: str, cookie: str | None, timeout: float) -> int:
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
    if cookie:
        req.add_header("Cookie", cookie)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as exc:
        log.debug(f"[url-check] {method} {url} failed: {exc}")
        return 0

def check_url_status(url: str, cookie: str | None = None, timeout: float = 4.0) -> int:
    """Verifies HTTP status via a lightweight HEAD request, falling back to GET
    for servers that don't implement HEAD properly (405/501) or drop the
    connection on it — otherwise those URLs would be wrongly marked dead."""
    status = _request_status(url, "HEAD", cookie, timeout)
    if status in (0, 405, 501):
        status = _request_status(url, "GET", cookie, timeout)
    return status

def process_discovered_links(links: List[str], max_workers: int, cookie: str | None = None, timeout: float = 4.0) -> List[str]:
    """Validates links concurrently and filters out 404/dead anomalies."""
    if not links:
        return []
    
    verified_urls = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_url = {pool.submit(check_url_status, url, cookie, timeout): url for url in links}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            status = future.result()
            if status in [200, 204, 301, 302, 401, 403]:
                verified_urls.append(url)
    return sorted(verified_urls)

# ──────────────────────────────────────────────────────────────────────────────
# KATANA APPLICATION SUBPROCESS WRAPPER
# ──────────────────────────────────────────────────────────────────────────────
def _run_katana(cmd: List[str], katana_timeout: int) -> tuple[List[str], str]:
    """Runs katana once and returns (raw_links, stderr_text)."""
    proc = subprocess.run(
        cmd, capture_output=True, text=True, check=False, errors="replace",
        timeout=katana_timeout,
    )
    raw_links = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return raw_links, proc.stderr.strip()

def crawl_subdomain(
    subdomain: str,
    katana_bin: str,
    depth: int,
    concurrency: int,
    cookie: str | None = None,
    katana_timeout: int = 120,
    url_timeout: float = 4.0,
) -> Dict[str, Any]:
    """Invokes Katana process engine and collects links in memory."""
    def build_cmd(scheme: str) -> List[str]:
        c = [
            katana_bin,
            "-u", f"{scheme}://{subdomain}",
            "-depth", str(depth),
            "-concurrency", str(concurrency),
            "-silent",
            "-no-color"
        ]
        if cookie:
            c.extend(["-H", f"Cookie: {cookie}"])
        return c

    try:
        raw_links, stderr_text = _run_katana(build_cmd("https"), katana_timeout)
        scheme_used = "https"

        # HTTPS yielded nothing — could be a real TLS/connectivity failure rather than
        # "no content". Retry on plain HTTP before giving up on this subdomain.
        if not raw_links:
            if stderr_text:
                log.warning(f"[*] {subdomain}: https crawl returned 0 links (stderr: {stderr_text}) — retrying on http.")
            else:
                log.warning(f"[*] {subdomain}: https crawl returned 0 links — retrying on http.")
            raw_links, stderr_text_http = _run_katana(build_cmd("http"), katana_timeout)
            scheme_used = "http"
            if not raw_links and stderr_text_http:
                log.warning(f"[*] {subdomain}: http crawl also returned 0 links (stderr: {stderr_text_http}).")

        # Scrub out invalid formats or generic extensions
        filtered_links = []
        for link in raw_links:
            parsed = urlparse(link)
            if not parsed.scheme or not parsed.netloc:
                continue
            if parsed.path.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".ico", ".css", ".woff", ".woff2")):
                continue
            filtered_links.append(link)
            
        filtered_links = list(set(filtered_links))
        
        # Concurrently verify live HTTP states
        log.info(f"[*] Crawled {subdomain} ({scheme_used}) -> found {len(filtered_links)} raw URLs. Verifying...")
        live_urls = process_discovered_links(filtered_links, max_workers=20, cookie=cookie, timeout=url_timeout)
        
        # Pull parameters information
        endpoints_with_params = []
        for url in live_urls:
            parsed = urlparse(url)
            if parsed.query:
                params = list(parse_qs(parsed.query).keys())
                endpoints_with_params.append({
                    "url": url,
                    "parameters": params
                })
                
        return {
            "subdomain": subdomain,
            "status": "ok",
            "scheme_used": scheme_used,
            "total_unique_urls": len(live_urls),
            "live_urls": live_urls,
            "endpoints_with_params": endpoints_with_params
        }

    except subprocess.TimeoutExpired:
        log.warning(f"[-] Crawl of {subdomain} exceeded {katana_timeout}s — killed and skipped.")
        return {
            "subdomain": subdomain,
            "status": "timeout",
            "error_msg": f"katana exceeded {katana_timeout}s timeout",
            "total_unique_urls": 0,
            "live_urls": [],
            "endpoints_with_params": []
        }
    except Exception as exc:
        log.error(f"[-] Failed crawling target {subdomain}: {exc}")
        return {
            "subdomain": subdomain,
            "status": "error",
            "error_msg": str(exc),
            "total_unique_urls": 0,
            "live_urls": [],
            "endpoints_with_params": []
        }

# ─────────────────────────────────────────────────────────────────────────────
# MAIN SYNCHRONOUS IN-MEMORY INTERFACE
# ─────────────────────────────────────────────────────────────────────────────
def _skipped_result(reason: str, depth: int | None = None) -> Dict[str, Any]:
    return {
        "scan_metadata": {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "status": "skipped",
            "reason": reason,
            "total_subdomains_scanned": 0,
            "subdomains_with_results": 0,
            "crawl_depth": depth,
            "total_verified_live_urls": 0,
            "total_endpoints_with_params": 0,
        },
        "results": [],
    }

def web_paths(input_json_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accepts a structured payload dictionary containing web scanning configurations,
    executes concurrent Katana crawler routines and live link verification pipelines,
    and returns the structured webpath telemetry map directly back as a dictionary tree.
    """
    # Preflight Binary Resolution
    katana_invoke = shutil.which("katana")
    if not katana_invoke:
        reason = "Missing required system executable: katana"
        log.error(f"'katana' executable is completely absent from systemic path environment variables.")
        return _skipped_result(reason)

    # Ingest structured memory profile directly from arguments
    target, subdomains = extract_subdomains_from_memory(input_json_data)

    # Pull tuneable orchestration constraints
    depth = int(input_json_data.get("depth", 3))
    workers = int(input_json_data.get("workers", 3))
    concurrency = int(input_json_data.get("concurrency", 10))
    cookie = input_json_data.get("cookie", None)
    katana_timeout = int(input_json_data.get("katana_timeout", 120))
    url_timeout = float(input_json_data.get("url_timeout", 4.0))

    if not subdomains:
        log.warning(f"[*] No subdomains available to crawl for target '{target}'.")
        return _skipped_result("No subdomains or target entries to crawl.", depth=depth)

    log.info(f"[*] Starting Web Path Pipeline for target '{target}' across {len(subdomains)} subdomains.")
    
    result_map = {}
    completed = 0
    total = len(subdomains)

    # Concurrently coordinate subdomain crawl workers
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_sub = {
            pool.submit(crawl_subdomain, sub, katana_invoke, depth, concurrency, cookie, katana_timeout, url_timeout): sub
            for sub in subdomains
        }
        
        for future in as_completed(future_to_sub):
            subdomain = future_to_sub[future]
            structured = future.result()
            result_map[subdomain] = structured
            completed += 1
            log.info(f"[{completed}/{total}] Finished {subdomain} (Live URLs: {structured['total_unique_urls']})")

    # Order results to match initial target subdomain mapping array structure
    ordered_results = [result_map[sd] for sd in subdomains]
    total_urls = sum(r.get("total_unique_urls", 0) for r in ordered_results)
    total_with_params = sum(len(r.get("endpoints_with_params", [])) for r in ordered_results)
    subdomains_ok = sum(1 for r in ordered_results if r.get("status") == "ok")

    # Compile and return final stateless report dictionary payload
    return {
        "scan_metadata": {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "status": "completed",
            "total_subdomains_scanned": total,
            "subdomains_with_results": subdomains_ok,
            "crawl_depth": depth,
            "total_verified_live_urls": total_urls,
            "total_endpoints_with_params": total_with_params,
        },
        "results": ordered_results,
    }