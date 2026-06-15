#!/usr/bin/env python3
"""
recon_pipeline.py
~~~~~~~~~~~~~~~~~
Heavy-duty orchestration wrapper for Windows-based web recon analysts.
Concurrently routes every subdomain through httpx and wafw00f.

Fixed: Programmatic native threading for wafw00f, eliminated global 
batch timeout traps, and stabilized host tracking for external redirects.
"""

from __future__ import annotations

import argparse
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
from pathlib import Path
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# TUNEABLE CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

HTTPX_PER_HOST:   int = 15    # seconds — passed to httpx via -timeout flag
WAFW00F_TIMEOUT:  int = 30    # seconds — passed to programmatic wafw00f engine
MAX_WAF_WORKERS:  int = 10    # concurrent native wafw00f threads

IS_WIN: bool = sys.platform.startswith("win")

_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_BAD_FNAME_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


# ─────────────────────────────────────────────────────────────────────────────
# WINDOWS UTF-8 CONSOLE SETUP
# ─────────────────────────────────────────────────────────────────────────────

if IS_WIN:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except AttributeError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")

def log_section(title: str) -> None:
    bar = "=" * 70
    print(f"\n{bar}\n  {title}\n{bar}", file=sys.stderr, flush=True)

def log_info(msg: str)  -> None:
    print(f"[{_ts()}]  INFO   {msg}", file=sys.stderr, flush=True)

def log_ok(msg: str)    -> None:
    print(f"[{_ts()}]  OK     {msg}", file=sys.stderr, flush=True)

def log_warn(msg: str)  -> None:
    print(f"[{_ts()}]  WARN   {msg}", file=sys.stderr, flush=True)

def log_error(msg: str) -> None:
    print(f"[{_ts()}]  ERROR  {msg}", file=sys.stderr, flush=True)


# ─────────────────────────────────────────────────────────────────────────────
# STRENGTHENED DEPENDENCY CHECK
# ─────────────────────────────────────────────────────────────────────────────

def _shell_probe(cmd: str) -> bool:
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode != 0:
            return False
        
        err_msg = (proc.stderr or "").lower()
        if "not recognized" in err_msg or "no module named" in err_msg:
            return False
            
        return True
    except (subprocess.TimeoutExpired, OSError):
        return False


def _which_first(candidates: list[str]) -> str | None:
    for name in candidates:
        if shutil.which(name):
            return name
    return None


def _safe_invoke(binary: str) -> str:
    if " " in binary:
        return binary
    full_path = shutil.which(binary)
    if full_path and " " in full_path:
        return f'"{full_path}"'
    return binary


def check_dependencies() -> tuple[str, bool]:
    log_section("Dependency Pre-flight Check")

    # ── httpx Validation ──────────────────────────────────────────────────
    httpx_bin = _which_first(["httpx", "httpx.exe"])
    if httpx_bin is None or not _shell_probe(f"{_safe_invoke(httpx_bin)} -version" if httpx_bin else "httpx -version"):
        if _shell_probe("httpx -version"):
            httpx_bin = "httpx"
        else:
            log_error(
                "httpx binary not found or non-executable.\n"
                "         Install → go install github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
                "         Or drop 'httpx.exe' directly into this tool directory."
            )
            sys.exit(1)

    httpx_invoke = _safe_invoke(httpx_bin)
    log_ok(f"httpx     found  → {shutil.which(httpx_bin) or httpx_bin}")

    # ── wafw00f Programmatic Library Validation ───────────────────────────
    try:
        from wafw00f.main import WAFW00F
        log_ok("wafw00f   found  → Programmatic Python Import Successful")
        wafw00f_available = True
    except ImportError:
        log_error(
            "wafw00f library is missing from your active environment.\n"
            "         Install package via:  pip install wafw00f\n"
            "         Verify via module:    python -m wafw00f --version"
        )
        sys.exit(1)

    return httpx_invoke, wafw00f_available


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — INGEST & DYNAMIC SCHEMA DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def load_targets(path: str) -> tuple[str, dict[str, dict[str, Any]]]:
    log_section("Step 1  —  Ingest & Target Identification")

    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        log_error(f"Input file not found: {path}")
        sys.exit(1)
    except json.JSONDecodeError as exc:
        log_error(f"JSON parse failure: {exc}")
        sys.exit(1)

    subdomains: dict[str, dict[str, Any]] = {}
    target: str = "unknown_target"

    if "subdomains" in data:
        target = str(data.get("target", "unknown_target")).strip()
        raw_subs = data.get("subdomains", [])
        
        for item in raw_subs:
            if isinstance(item, str):
                sub = item.strip()
                if sub:
                    subdomains[sub] = {
                        "ip": "N/A",
                        "probes": [{"probed_url": f"http://{sub}", "error": None}]
                    }
            elif isinstance(item, dict):
                sub = (item.get("subdomain") or item.get("host") or "").strip()
                if sub:
                    subdomains[sub] = {
                        "ip": (item.get("ip") or "N/A").strip(),
                        "probes": item.get("probes") or [{"probed_url": f"http://{sub}", "error": None}]
                    }

    elif "results" in data and "scan_metadata" in data:
        target = data["scan_metadata"].get("target", "unknown_target").strip()
        for entry in data.get("results", []):
            sub = (entry.get("subdomain") or "").strip()
            if not sub:
                continue
            subdomains[sub] = {
                "ip":     (entry.get("ip") or "N/A").strip(),
                "probes": entry.get("probes") or [],
            }
            
    else:
        log_error(
            f"Unknown JSON Schema. Got top-level keys: {set(data.keys())!r}. "
            "Expected ('subdomains', 'target') or ('results', 'scan_metadata')."
        )
        sys.exit(1)

    log_info(f"Target domain    : {target}")
    log_info(f"Unique subdomains : {len(subdomains)}")
    return target, subdomains


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — HTTPX PROCESSING (FIXED REDIRECT TRACKING)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_httpx_ndjson(stdout: str) -> dict[str, list[dict[str, Any]]]:
    results: dict[str, list[dict[str, Any]]] = {}

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        url: str = obj.get("url", "")
        
        # FIX: Explicitly check 'input' to preserve mapping target across redirects
        raw_input = obj.get("input") or url
        host: str = re.sub(r"^https?://", "", raw_input).split(":")[0].rstrip("/").lstrip("*.")

        status = obj.get("status-code") or obj.get("status_code") or obj.get("statusCode")
        server = obj.get("webserver") or obj.get("web-server") or (obj.get("headers") or {}).get("server")
        title = obj.get("title")
        raw_techs = obj.get("tech") or obj.get("technologies") or []
        techs = [raw_techs] if isinstance(raw_techs, str) else list(raw_techs)

        probe: dict[str, Any] = {
            "probed_url":   url,
            "status_code":  status,
            "server":       server,
            "title":        title,
            "technologies": techs,
            "error":        None,
        }
        results.setdefault(host, []).append(probe)
        log_ok(f"[httpx]  [{str(status or '?'):>3}]  {url:<65}  title={title or '(none)'}")

    return results


def run_httpx(httpx_invoke: str, subdomains: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    log_info(f"[httpx]  Preparing batch run against {len(subdomains)} target(s) …")
    tmp_path: str | None = None

    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            tmp_path = tmp.name
            tmp.write("\n".join(subdomains.keys()) + "\n")

        cmd = f'{httpx_invoke} -l "{tmp_path}" -title -tech-detect -status-code -follow-redirects -timeout {HTTPX_PER_HOST} -json -silent'
        
        # FIX: Removed the hardcoded HTTPX_BATCH_TIMEOUT pool trap to allow native execution lifecycle
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if proc.returncode not in (0, 1) or "not recognized" in proc.stderr:
            log_error(f"[httpx] Execution failure. Stderr: {proc.stderr.strip()}")
            return {}

        return _parse_httpx_ndjson(proc.stdout)

    except Exception as exc:
        log_error(f"[httpx]  Unexpected error: {exc}")
        return {}
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — PROGRAMMATIC NATIVE WAFW00F (FIXED SUBPROCESS BOTTLENECK)
# ─────────────────────────────────────────────────────────────────────────────

def _wafw00f_worker(subdomain: str) -> tuple[str, str]:
    """
    Executes WAFW00F programmatically within native threads, completely 
    bypassing OS subprocess execution overhead and cleaning error codes cleanly.
    """
    try:
        from wafw00f.main import WAFW00F
        import requests
        
        # Initialize native engine instance
        attacker = WAFW00F(target=subdomain, timeout=WAFW00F_TIMEOUT)
        detected, xurl = attacker.identwaf()
        
        if detected:
            return subdomain, str(detected[0])
        return subdomain, "None Detected"

    except requests.exceptions.Timeout:
        return subdomain, "Timeout"
    except requests.exceptions.ConnectionError as exc:
        # Check underlying network failure constraints accurately without CLI logging checks
        err_str = str(exc).lower()
        if "gaierror" in err_str or "not known" in err_str or "dns" in err_str:
            return subdomain, "Unreachable (DNS Error)"
        return subdomain, "Unreachable (Conn Failed)"
    except Exception:
        return subdomain, "Unreachable / Host Down"


# ─────────────────────────────────────────────────────────────────────────────
# REPORT CONSTRUCTOR
# ─────────────────────────────────────────────────────────────────────────────

def assemble_report(
    target: str,
    source_file: str,
    subdomains: dict[str, dict[str, Any]],
    httpx_data: dict[str, list[dict[str, Any]]],
    waf_data: dict[str, str],
    scan_start: float,
) -> dict[str, Any]:
    duration = round(time.time() - scan_start, 2)
    scanned_at = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    all_codes: set[int] = set()
    all_servers: set[str] = set()
    all_techs: set[str] = set()
    all_wafs: set[str] = set()
    total_probes = ok_probes = 0
    results_arr: list[dict[str, Any]] = []

    for sub, info in subdomains.items():
        waf = waf_data.get(sub, "Unknown")
        all_wafs.add(waf)

        enriched_probes: list[dict[str, Any]] = []
        httpx_probes = httpx_data.get(sub, [])

        if httpx_probes:
            for p in httpx_probes:
                code = p.get("status_code")
                server = p.get("server")
                techs = p.get("technologies") or []

                total_probes += 1
                if isinstance(code, int) and 100 <= code < 600:
                    ok_probes += 1

                if code is not None: all_codes.add(code)
                if server:           all_servers.add(server)
                all_techs.update(techs)

                enriched_probes.append({
                    "probed_url":   p.get("probed_url"),
                    "status_code":  code,
                    "server":       server,
                    "title":        p.get("title"),
                    "technologies": techs,
                    "error":        None,
                })
        else:
            for orig in info.get("probes", []):
                total_probes += 1
                enriched_probes.append({
                    "probed_url":   orig.get("probed_url"),
                    "status_code":  None,
                    "server":       None,
                    "title":        None,
                    "technologies": [],
                    "error":        orig.get("error") or "Host Unreachable / DNS Resolution Failure",
                })

        results_arr.append({
            "subdomain":  sub,
            "ip":         info["ip"],
            "waf_vendor": waf,
            "probes":     enriched_probes,
        })

    return {
        "scan_metadata": {
            "target":                target,
            "source_file":           str(Path(source_file).resolve()),
            "scanned_at":            scanned_at,
            "scan_duration_seconds": duration,
        },
        "summary": {
            "total_probes":        total_probes,
            "successful_probes":   ok_probes,
            "unique_status_codes": sorted(all_codes),
            "unique_servers":      sorted(all_servers),
            "unique_technologies": sorted(all_techs),
            "observed_waf_types":  sorted(all_wafs),
        },
        "results": results_arr,
    }


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Orchestrator Wrapper")
    parser.add_argument("--input", "-i", required=True, help="Input JSON file")
    args = parser.parse_args()
    scan_start = time.time()

    log_section("recon_pipeline.py  —  Initialising")
    httpx_invoke, wafw00f_available = check_dependencies()

    target, subdomains = load_targets(args.input)
    if not subdomains:
        log_error("No targets parsed out. Exiting.")
        sys.exit(1)

    log_section("Phase 2+3  —  Concurrent httpx & Programmatic wafw00f")
    httpx_data: dict[str, list[dict[str, Any]]] = {}
    waf_data:   dict[str, str]                  = {}

    # Native programmatic orchestration
    with ThreadPoolExecutor(max_workers=MAX_WAF_WORKERS + 1) as pool:
        httpx_future = pool.submit(run_httpx, httpx_invoke, subdomains)
        waf_futures = {pool.submit(_wafw00f_worker, sub): sub for sub in subdomains}

        for fut in as_completed(waf_futures):
            sub, waf = fut.result()
            waf_data[sub] = waf
            indicator = " WAF! " if waf not in ("None Detected", "Timeout") and not waf.startswith("Unreachable") else "  ·     "
            log_info(f"[wafw00f]  {indicator} {sub:<50} -> {waf}")

        httpx_data = httpx_future.result()

    log_section("Phase 4  —  Assembling Final Report")
    report = assemble_report(target, args.input, subdomains, httpx_data, waf_data, scan_start)

    out_path = Path(f"{_BAD_FNAME_RE.sub('_', target)}_master_recon.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    log_section("Scan Complete")
    log_ok(f"Output saved → {out_path.resolve()}")
    print(str(out_path.resolve()), flush=True)


if __name__ == "__main__":
    main()