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
def check_url_status(url: str, cookie: str | None = None) -> int:
    """Verifies HTTP status code via a lightweight HEAD request."""
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
    if cookie:
        req.add_header("Cookie", cookie)
    
    try:
        with urllib.request.urlopen(req, timeout=4.0) as response:
            return response.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0

def process_discovered_links(links: List[str], max_workers: int, cookie: str | None = None) -> List[str]:
    """Validates links concurrently and filters out 404/dead anomalies."""
    if not links:
        return []
    
    verified_urls = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_url = {pool.submit(check_url_status, url, cookie): url for url in links}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            status = future.result()
            if status in [200, 204, 301, 302, 401, 403]:
                verified_urls.append(url)
    return sorted(verified_urls)

# ──────────────────────────────────────────────────────────────────────────────
# KATANA APPLICATION SUBPROCESS WRAPPER
# ──────────────────────────────────────────────────────────────────────────────
def crawl_subdomain(
    subdomain: str,
    katana_bin: str,
    depth: int,
    concurrency: int,
    cookie: str | None = None
) -> Dict[str, Any]:
    """Invokes Katana process engine and collects links in memory."""
    target_url = f"https://{subdomain}"
    
    cmd = [
        katana_bin,
        "-target", target_url,
        "-depth", str(depth),
        "-concurrency", str(concurrency),
        "-silent",
        "-no-color"
    ]
    if cookie:
        cmd.extend(["-cookie", cookie])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, errors="replace")
        raw_links = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        
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
        log.info(f"[*] Crawled {subdomain} -> found {len(filtered_links)} raw URLs. Verifying...")
        live_urls = process_discovered_links(filtered_links, max_workers=20, cookie=cookie)
        
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
            "total_unique_urls": len(live_urls),
            "live_urls": live_urls,
            "endpoints_with_params": endpoints_with_params
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
def web_paths(input_json_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accepts a structured payload dictionary containing web scanning configurations,
    executes concurrent Katana crawler routines and live link verification pipelines,
    and returns the structured webpath telemetry map directly back as a dictionary tree.
    """
    # Preflight Binary Resolution
    katana_invoke = shutil.which("katana")
    if not katana_invoke:
        log.error("'katana' executable is completely absent from systemic path environment variables.")
        raise RuntimeError("Missing required system executable: katana")

    # Ingest structured memory profile directly from arguments
    target, subdomains = extract_subdomains_from_memory(input_json_data)
    if not subdomains:
        raise ValueError("Input JSON dataset has no subdomains or target entries to crawl.")

    # Pull tuneable orchestration constraints
    depth = int(input_json_data.get("depth", 3))
    workers = int(input_json_data.get("workers", 3))
    concurrency = int(input_json_data.get("concurrency", 10))
    cookie = input_json_data.get("cookie", None)

    log.info(f"[*] Starting Web Path Pipeline for target '{target}' across {len(subdomains)} subdomains.")
    
    result_map = {}
    completed = 0
    total = len(subdomains)

    # Concurrently coordinate subdomain crawl workers
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_sub = {
            pool.submit(crawl_subdomain, sub, katana_invoke, depth, concurrency, cookie): sub 
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
            "total_subdomains_scanned": total,
            "subdomains_with_results": subdomains_ok,
            "crawl_depth": depth,
            "total_verified_live_urls": total_urls,
            "total_endpoints_with_params": total_with_params,
        },
        "results": ordered_results,
    }