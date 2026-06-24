import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# TUNEABLE CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
HTTPX_PER_HOST:   int = 15    
WAFW00F_TIMEOUT:  int = 30    
MAX_WAF_WORKERS:  int = 10    

IS_WIN: bool = sys.platform.startswith("win")

_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# ─────────────────────────────────────────────────────────────────────────────
# LOGGER LOGIC
# ─────────────────────────────────────────────────────────────────────────────
def log_info(msg: str) -> None:
    print(f"[*] {msg}", flush=True)

def log_error(msg: str) -> None:
    print(f"[-] ERROR: {msg}", file=sys.stderr, flush=True)

def log_section(title: str) -> None:
    print(f"\n{'='*78}\n{title.upper()}\n{'='*78}", flush=True)

# ─────────────────────────────────────────────────────────────────────────────
# SANITIZATION AND HELPER PARSING
# ─────────────────────────────────────────────────────────────────────────────
def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)

def _wafw00f_worker(subdomain: str) -> tuple[str, str]:
    """Programmatic, completely localized wrapper invocation of wafw00f engine."""
    from wafw00f.main import WAFW00F
    
    target_url = f"https://{subdomain}"
    try:
        attacker = WAFW00F(target_url, timeout=WAFW00F_TIMEOUT)
        result = attacker.ident_waf(find_all=False)
        if result:
            return subdomain, str(result[0])
        return subdomain, "None Detected"
    except Exception as exc:
        err_str = str(exc)
        if "timeout" in err_str.lower() or "timed out" in err_str.lower():
            return subdomain, "Timeout"
        return subdomain, f"Unreachable ({type(exc).__name__})"

# ─────────────────────────────────────────────────────────────────────────────
# HTTPX SUBPROCESS WRAPPER
# ─────────────────────────────────────────────────────────────────────────────
def run_httpx(binary_path: str, subdomains: dict[str, str]) -> dict[str, list[dict[str, Any]]]:
    """Runs external httpx process with JSON output redirection."""
    results: dict[str, list[dict[str, Any]]] = {sub: [] for sub in subdomains}
    
    with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".txt") as tf_in:
        for sub in subdomains:
            tf_in.write(f"{sub}\n")
        tf_in_path = tf_in.name

    tf_out_path = tf_in_path + ".out.json"

    cmd = [
        binary_path,
        "-l", tf_in_path,
        "-json",
        "-silent",
        "-timeout", str(HTTPX_PER_HOST),
        "-o", tf_out_path,
        "-title", "-server", "-tech-detect", "-status-code", "-cdn",
        "-follow-redirects"
    ]

    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        
        if os.path.exists(tf_out_path):
            with open(tf_out_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        raw_record = json.loads(line)
                        input_host = raw_record.get("input", "").strip().lower()
                        if not input_host:
                            continue
                            
                        clean_record = {
                            "url": raw_record.get("url"),
                            "status_code": raw_record.get("status_code"),
                            "title": raw_record.get("title"),
                            "server": raw_record.get("server"),
                            "cdn": raw_record.get("cdn"),
                            "tech": raw_record.get("tech", []),
                            "pipeline_timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                        }
                        
                        if input_host in results:
                            results[input_host].append(clean_record)
                        else:
                            for sub in results:
                                if input_host.endswith("." + sub) or sub.endswith("." + input_host):
                                    results[sub].append(clean_record)
                                    break
                    except json.JSONDecodeError:
                        continue
    finally:
        for pth in (tf_in_path, tf_out_path):
            try:
                if os.path.exists(pth):
                    os.remove(pth)
            except Exception:
                pass

    return results

# ─────────────────────────────────────────────────────────────────────────────
# REPORT COMPILATION PIPELINE
# ─────────────────────────────────────────────────────────────────────────────
def assemble_report(
    target: str,
    subdomains: dict[str, str],
    httpx_data: dict[str, list[dict[str, Any]]],
    waf_data: dict[str, str],
    scan_start: float
) -> dict[str, Any]:
    
    hosts_list = []
    for sub, ip in subdomains.items():
        http_endpoints = httpx_data.get(sub, [])
        waf_status = waf_data.get(sub, "None Detected")
        
        hosts_list.append({
            "subdomain": sub,
            "resolved_ip": ip,
            "waf_fingerprint": waf_status,
            "endpoints_count": len(http_endpoints),
            "endpoints": http_endpoints
        })

    duration_secs = round(time.time() - scan_start, 2)
    
    return {
        "target": target,
        "generated": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scan_duration_seconds": duration_secs,
        "total_subdomains_processed": len(subdomains),
        "results": hosts_list
    }

# ─────────────────────────────────────────────────────────────────────────────
# MAIN SYNCHRONOUS IN-MEMORY INTERFACE
# ─────────────────────────────────────────────────────────────────────────────
def finger(input_json_data: dict[str, Any]) -> dict[str, Any]:
    """
    Accepts a structured payload dictionary containing the 'target' and its 'subdomains',
    executes concurrent httpx and programmatic wafw00f sweeps, and returns the 
    resulting telemetry profile directly back as a dictionary.
    """
    scan_start = time.time()

    # Preflight Binary Resolution
    httpx_invoke = shutil.which("httpx")
    if not httpx_invoke:
        log_error("'httpx' executable is completely absent from systemic path environment variables.")
        raise RuntimeError("Missing required system executable: httpx")

    # Ingest structured memory profile directly from arguments
    target = input_json_data.get("target", "").strip()
    subdomains = input_json_data.get("subdomains", {})

    if not target:
        raise ValueError("Input JSON dataset is missing the mandatory 'target' key.")
    if not subdomains:
        raise ValueError("Input 'subdomains' map layer is completely empty or missing.")

    log_section("Executing Pipeline — Concurrent httpx & Programmatic wafw00f")
    httpx_data: dict[str, list[dict[str, Any]]] = {}
    waf_data:   dict[str, str]                  = {}

    # Programmatic Native Threat Isolation Orchestration
    with ThreadPoolExecutor(max_workers=MAX_WAF_WORKERS + 1) as pool:
        httpx_future = pool.submit(run_httpx, httpx_invoke, subdomains)
        waf_futures = {pool.submit(_wafw00f_worker, sub): sub for sub in subdomains}

        for fut in as_completed(waf_futures):
            sub, waf = fut.result()
            waf_data[sub] = waf
            indicator = " WAF! " if waf not in ("None Detected", "Timeout") and not waf.startswith("Unreachable") else "  ·     "
            log_info(f"[wafw00f]  {indicator} {sub:<50} -> {waf}")

        httpx_data = httpx_future.result()

    log_section("Compiling Final In-Memory Payload Report")
    return assemble_report(target, subdomains, httpx_data, waf_data, scan_start)
